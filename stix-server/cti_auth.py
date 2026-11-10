"""Authentication helpers for the generated CTI dashboard.

The generated Flask server (``server.py``, rendered from
``templates/server.py.j2``) is the public face of the evidence catalog. It is
gated by the Supabase ``allowed_users`` + ``ip_list`` tables:

* ``allowed_users`` holds the username, a bcrypt digest and a per-user pepper.
* ``ip_list`` holds one IP address per user and a boolean ``decision``. Only
  ``decision is True`` and a matching address grant access.

This module deliberately has no Flask import. The server, the provisioning CLI
(``manage_users.py``) and the unit tests all use the same primitives, so a
password written by the CLI is verifiably the password the server expects.

Password scheme
---------------
``bcrypt(password + unique_peper)``. The pepper is stored in the ``unique_peper``
column and is *not* secret from the database, so it is not a second factor; it
is a per-row salt modifier that makes a stolen digest useless against another
row. Legacy digests written by the old ``hash_password`` implementation were
produced from a randomly shuffled string and cannot be reproduced - those
passwords must be reset with ``manage_users.py set-password``.

Sessions
--------
Signed cookies (itsdangerous), bound to the client IP that created them. The
signing key comes from ``CTI_SESSION_KEY`` or ``config/.session-key`` (created
on first use). Rotating the key invalidates every session.
"""

from __future__ import annotations

import ipaddress
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any

try:  # bcrypt is a hard dependency of the login path, imported lazily below.
    import bcrypt
except ImportError:  # pragma: no cover - exercised only on broken installs
    bcrypt = None  # type: ignore[assignment]

try:
    from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
except ImportError:  # pragma: no cover - Flask always ships itsdangerous
    BadSignature = SignatureExpired = Exception  # type: ignore[misc,assignment]
    URLSafeTimedSerializer = None  # type: ignore[assignment]


SESSION_COOKIE = "cti_session"
SESSION_SALT = "daorcs.cti.session"
SESSION_KEY_ENV = "CTI_SESSION_KEY"
DEFAULT_SESSION_TTL_HOURS = 12
_BCRYPT_PREFIXES = ("$2a$", "$2b$", "$2y$")


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------

def generate_pepper() -> str:
    """Return a fresh per-user pepper (``#`` + 6 hex characters)."""
    return "#" + secrets.token_hex(3)


def is_bcrypt_hash(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 60
        and value.startswith(_BCRYPT_PREFIXES)
    )


def hash_password(password: str, pepper: str | None = None) -> dict[str, str]:
    """Hash *password* with bcrypt and a per-user pepper.

    Returns ``{"password": <digest>, "unique_peper": <pepper>}`` - the exact
    two columns ``allowed_users`` expects.  Pass *pepper* to keep an existing
    one (password rotation without changing the row's pepper).
    """
    if not isinstance(password, str) or not password:
        raise ValueError("password must be a non-empty string")
    if bcrypt is None:
        raise RuntimeError("bcrypt is not installed; cannot hash passwords")
    pepper = pepper if isinstance(pepper, str) and pepper else generate_pepper()
    digest = bcrypt.hashpw(
        (password + pepper).encode("utf-8"), bcrypt.gensalt()
    ).decode("ascii")
    return {"password": digest, "unique_peper": pepper}


def verify_password(password: object, stored_hash: object, pepper: object) -> bool:
    """Constant-time-ish verification of *password* against a stored digest.

    Returns ``False`` for anything that is not a complete bcrypt digest; the
    legacy shuffled hashes are still valid bcrypt strings, so they simply fail
    verification and the operator must reset them.  Never raises on malformed
    input.
    """
    if bcrypt is None or not isinstance(password, str) or not password:
        return False
    if not is_bcrypt_hash(stored_hash):
        return False
    pepper = pepper if isinstance(pepper, str) else ""
    try:
        return bcrypt.checkpw(
            (password + pepper).encode("utf-8"),
            stored_hash.encode("ascii"),
        )
    except (ValueError, TypeError):
        return False


_DUMMY_DIGEST: str | None = None
_DUMMY_LOCK = threading.Lock()


def burn_password_check(password: object) -> None:
    """Spend the same bcrypt work as a real comparison, for unknown users.

    Without this, a missing username returns before bcrypt and a caller can
    enumerate accounts by response time.  The result is intentionally thrown
    away.
    """
    global _DUMMY_DIGEST
    if bcrypt is None:
        return
    with _DUMMY_LOCK:
        if _DUMMY_DIGEST is None:
            _DUMMY_DIGEST = bcrypt.hashpw(
                b"cti-dummy-password", bcrypt.gensalt()).decode("ascii")
        digest = _DUMMY_DIGEST
    candidate = password if isinstance(password, str) else ""
    try:
        bcrypt.checkpw(candidate.encode("utf-8"), digest.encode("ascii"))
    except (ValueError, TypeError):
        pass


# ---------------------------------------------------------------------------
# Client IP handling
# ---------------------------------------------------------------------------

def normalise_ip(value: object) -> str | None:
    """Return a canonical address string, or None when *value* is not an IP.

    Accepts ``1.2.3.4:5678``, ``[2001:db8::1]:443`` and IPv4-mapped IPv6
    (``::ffff:127.0.0.1``), which is what Windows can report for a loopback
    connection.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if text.startswith("["):
        close = text.find("]")
        if close != -1:
            text = text[1:close]
    elif text.count(":") == 1 and "." in text:
        host, _, port = text.partition(":")
        if port.isdigit():
            text = host
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return str(addr)


def client_ip(
    remote_addr: object,
    forwarded_for: object = None,
    trust_proxy: bool = False,
) -> str | None:
    """Resolve the address to check against ``ip_list``.

    ``X-Forwarded-For`` is only consulted when *trust_proxy* is true, because
    an untrusted header lets any client claim any address.  The left-most
    entry is the original client.
    """
    if trust_proxy and isinstance(forwarded_for, str):
        first = forwarded_for.split(",")[0].strip()
        if first and first.lower() != "unknown":
            resolved = normalise_ip(first)
            if resolved is not None:
                return resolved
    return normalise_ip(remote_addr)


def is_loopback(value: object) -> bool:
    resolved = normalise_ip(value)
    if resolved is None:
        return False
    try:
        return ipaddress.ip_address(resolved).is_loopback
    except ValueError:
        return False


def ip_matches(client: object, stored: object) -> bool:
    """Exact match, or CIDR match when *stored* contains ``/``."""
    resolved = normalise_ip(client)
    if resolved is None or not isinstance(stored, str):
        return False
    raw = stored.strip()
    if not raw:
        return False
    try:
        addr = ipaddress.ip_address(resolved)
    except ValueError:
        return False
    if "/" in raw:
        try:
            return addr in ipaddress.ip_network(raw, strict=False)
        except ValueError:
            return False
    stored_addr = normalise_ip(raw)
    return stored_addr is not None and stored_addr == resolved


def check_access(
    entry: Any,
    address: object,
    allow_loopback: bool = False,
) -> tuple[bool, str]:
    """Decide whether *entry* (an IpListEntry or dict) grants *address* access.

    ``allow_loopback`` bypasses the stored-address comparison for loopback
    clients only.  It never bypasses ``decision``: a blocked account stays
    blocked, which is the point of the boolean.
    """
    if entry is None:
        return False, "No access record exists for this account."
    if isinstance(entry, dict):
        decision = entry.get("decision")
        stored = entry.get("ip_address")
    else:
        decision = getattr(entry, "decision", None)
        stored = getattr(entry, "ip_address", None)
    if decision is not True:
        return False, "This account is not allowed to sign in."
    if not isinstance(stored, str) or not stored.strip():
        return False, "No IP address is provisioned for this account."
    if allow_loopback and is_loopback(address):
        return True, "ok"
    if not ip_matches(address, stored):
        return False, "This IP address is not allowed to access the dashboard."
    return True, "ok"


# ---------------------------------------------------------------------------
# Session cookies
# ---------------------------------------------------------------------------

class SessionSigner:
    """Issue and read signed session payloads bound to a client IP."""

    def __init__(self, secret: str, max_age_seconds: int = DEFAULT_SESSION_TTL_HOURS * 3600):
        if not isinstance(secret, str) or not secret:
            raise ValueError("session secret must be a non-empty string")
        if URLSafeTimedSerializer is None:  # pragma: no cover
            raise RuntimeError("itsdangerous is required for sessions")
        self.max_age_seconds = max(1, int(max_age_seconds))
        self._serializer = URLSafeTimedSerializer(secret, salt=SESSION_SALT)

    def issue(self, user_id: int, username: str, address: object) -> str:
        resolved = normalise_ip(address)
        if resolved is None:
            raise ValueError("a valid client IP is required to issue a session")
        return self._serializer.dumps({
            "uid": int(user_id),
            "username": str(username),
            "ip": resolved,
            "issued": int(time.time()),
        })

    def read_with_reason(
        self,
        token: object,
        address: object,
    ) -> tuple[dict[str, Any] | None, str]:
        """Read a session cookie and explain the outcome.

        ``read()`` is deliberately silent: a rejected cookie and a missing one
        look the same to the gate. When auth debugging is on, the server calls
        this variant instead so the log can distinguish "never signed in" from
        "expired", "bad signature" and "cookie was issued to another IP".
        The reason string is safe to log - it never contains the token.
        """
        if not isinstance(token, str) or not token:
            return None, "no session cookie"
        resolved = normalise_ip(address)
        if resolved is None:
            return None, "request address is not a valid IP"
        try:
            data = self._serializer.loads(token, max_age=self.max_age_seconds)
        except SignatureExpired:
            return None, "session expired"
        except BadSignature:
            return None, "bad signature"
        except Exception:  # malformed payloads must never 500 the gate
            return None, "malformed session payload"
        if not isinstance(data, dict):
            return None, "session payload is not an object"
        bound = normalise_ip(data.get("ip"))
        if bound != resolved:
            return None, (
                f"session is bound to {bound or data.get('ip')!r}, "
                f"request came from {resolved!r}"
            )
        if not isinstance(data.get("uid"), int) or not isinstance(data.get("username"), str):
            return None, "session payload is missing uid or username"
        return data, "ok"

    def read(self, token: object, address: object) -> dict[str, Any] | None:
        return self.read_with_reason(token, address)[0]


def load_session_key(
    path: str | os.PathLike[str] | None = None,
    env_var: str = SESSION_KEY_ENV,
) -> str:
    """Return the session signing key, creating ``config/.session-key`` once.

    ``CTI_SESSION_KEY`` wins over the file so a deployment can supply the key
    out of band.  A file that cannot be written is not fatal: the process keeps
    its in-memory key and sessions simply do not survive a restart.
    """
    from_env = os.environ.get(env_var)
    if from_env:
        return from_env

    key_path = Path(path) if path is not None else (
        Path(__file__).resolve().parent / "config" / ".session-key")
    try:
        existing = key_path.read_text(encoding="utf-8-sig").strip()
    except (FileNotFoundError, OSError, UnicodeError):
        existing = ""
    if existing:
        return existing

    generated = secrets.token_urlsafe(48)
    try:
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_text(generated + "\n", encoding="utf-8")
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
    except OSError:
        pass
    return generated


def safe_next_path(value: object, default: str = "/") -> str:
    """Only allow same-origin absolute paths as a post-login destination."""
    if not isinstance(value, str):
        return default
    candidate = value.strip()
    if (
        not candidate.startswith("/")
        or candidate.startswith("//")
        or "\\" in candidate
        or "\r" in candidate
        or "\n" in candidate
    ):
        return default
    return candidate


# ---------------------------------------------------------------------------
# Login throttling
# ---------------------------------------------------------------------------

class FailureTracker:
    """In-memory failed-login counter keyed by arbitrary strings.

    Per-process only; that is enough to blunt a password-spray against one
    server instance without adding a shared store to a dashboard that can run
    on a single host.
    """

    def __init__(self, max_attempts: int = 5, window_seconds: int = 300):
        self.max_attempts = max(1, int(max_attempts))
        self.window_seconds = max(1, int(window_seconds))
        self._lock = threading.Lock()
        self._hits: dict[str, list[float]] = {}

    def _prune(self, key: str, now: float) -> list[float]:
        hits = [t for t in self._hits.get(key, ()) if now - t < self.window_seconds]
        if hits:
            self._hits[key] = hits
        else:
            self._hits.pop(key, None)
        return hits

    def blocked(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            return len(self._prune(key, now)) >= self.max_attempts

    def retry_after(self, key: str) -> int:
        """Seconds until the oldest counted failure leaves the window."""
        now = time.monotonic()
        with self._lock:
            hits = self._prune(key, now)
            if len(hits) < self.max_attempts:
                return 0
            oldest = hits[len(hits) - self.max_attempts]
            return max(1, int(self.window_seconds - (now - oldest)) + 1)

    def record_failure(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            hits = self._prune(key, now)
            hits.append(now)
            self._hits[key] = hits

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._hits.clear()
