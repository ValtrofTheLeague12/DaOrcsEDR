"""Shared-secret auth for the panel.

The panel is loopback-bound and, with no token configured, open - the same
posture ml/serve.py takes. That is deliberate: an operator console on this
box should not have to log in to read a status page.

Set ADMIN_PANEL_TOKEN in .env and every /api route requires it, INCLUDING from
loopback. There is no loopback exemption here, and the difference from
ml/serve.py is deliberate: ml/serve.py is a dependency the C++ analyzer dials
programmatically with no header, so it must trust loopback to work at all. The
panel is only ever driven by a human browser. A loopback bypass would mean
setting the token changed nothing locally - the login page would never appear
and the token would look like it worked while gating nothing. Either it gates or
it does not exist.

What the token does and does not buy:

  * It gates the panel's own API. It does NOT add auth to anything the panel
    calls - the analyzer on 60025 and MalAPI on 60000 have none of their own.
    If the panel becomes reachable, so does whatever it fronts, unless those are
    separately locked down.

The token comparison is constant-time so it cannot be recovered by timing, and
a session cookie is issued after login so the token itself is not re-sent on
every poll.

The cookie is HMAC-signed with an expiry. That is the weakest thing here: a
signed cookie is a bearer token and says nothing about *who* the user is. It is
adequate for a single-operator console and is not a substitute for real
identity. If this console ever gets a second operator, replace this with real
identity rather than extending it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import os
import secrets
import time

from . import config

COOKIE_NAME = "admin_panel_session"
SESSION_TTL = 8 * 60 * 60  # 8 hours; long enough for a work session, short
                            # enough that a forgotten browser expires.

# Guards the signing key file so it is not world-readable.
_KEY_FILE_NAME = ".session-key"


def _secret() -> bytes:
    """Per-install signing key, generated once.

    Generated rather than derived from the login token so that ROTATING the
    login token does not also invalidate every live session, and so that the
    token can be changed without the panel having a new "previous key" to keep.
    """
    override = os.environ.get("ADMIN_PANEL_SESSION_KEY")
    if override:
        return override.encode("utf-8")

    path = config.REPO / "python" / "panel" / _KEY_FILE_NAME
    try:
        return path.read_bytes().strip()
    except OSError:
        pass

    key = secrets.token_urlsafe(32).encode("ascii")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # 0600 from the start - no window where it is readable by everyone.
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key)
    except OSError:
        # Unwritable panel directory: fall back to a process-lifetime key.
        # Sessions then die with the process, which is annoying but not unsafe.
        return key
    return key


def token() -> str:
    """The login token, or "" when the panel is open."""
    return config.setting("ADMIN_PANEL_TOKEN", "")


def required() -> bool:
    return bool(token())


def is_loopback(addr: str | None) -> bool:
    if not addr:
        return False
    try:
        return ipaddress.ip_address(addr.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def issue_cookie() -> str:
    """A signed, expiring session value."""
    expires = int(time.time()) + SESSION_TTL
    payload = f"{expires}.{secrets.token_urlsafe(24)}"
    sig = hmac.new(_secret(), payload.encode("utf-8"), hashlib.sha256).digest()
    return f"{payload}.{_b64e(sig)}"


def check_cookie(value: str | None) -> bool:
    if not value:
        return False
    parts = value.split(".")
    if len(parts) != 3:
        return False
    expires_s, nonce, sig_s = parts
    payload = f"{expires_s}.{nonce}"
    try:
        expected = hmac.new(_secret(), payload.encode("utf-8"), hashlib.sha256).digest()
        provided = _b64d(sig_s)
    except Exception:  # noqa: BLE001 - malformed cookie is just invalid
        return False
    if not hmac.compare_digest(expected, provided):
        return False
    try:
        return int(expires_s) > time.time()
    except ValueError:
        return False


def check_token(candidate: str | None) -> bool:
    """Constant-time comparison against the configured token."""
    expected = token()
    if not expected:
        return True
    if not candidate:
        return False
    return hmac.compare_digest(candidate, expected)


def authorised(cookie_value: str | None, bearer: str | None,
               remote_addr: str | None) -> bool:
    if not required():
        return True
    if check_cookie(cookie_value):
        return True
    return check_token(bearer)