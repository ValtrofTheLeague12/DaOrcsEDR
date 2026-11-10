"""Passwords for the evidence-bundle zip.

The panel's Analysis Configuration page owns the zip password: it either takes
one the operator typed or generates one and shows it exactly once. This module
is the generated half - the value never comes from ``random`` (not a CSPRNG)
and is never written to a repo config; the caller stores it in the operator
password file outside the checkout (see ``mega/protect.py``).

Two modes, because they fail differently if a human has to retype one:

  random  - every character drawn from ``secrets`` over the full printable
            charset. The strongest option, and the default.
  stale   - words joined by ``_`` with a random tag, in the shape an operator
            can read over a phone without mis-hearing an ambiguous glyph.

Both produce exactly the requested number of characters. Length is clamped to
12..128, the same bounds the panel and ``mega/protect.py`` enforce, because a
password shorter than 12 bytes is not protection for evidence that leaves the
host.

Run directly for a quick one-off:

    python -m panel.utils.password_generator --length 24 --mode random
"""

from __future__ import annotations

import argparse
import secrets
import string
from enum import StrEnum

# The same floor/ceiling as mega/protect.py. Kept here as well so a caller that
# constructs the class directly cannot produce something the panel would refuse
# to store after all the work of generating it.
MIN_PASSWORD = 12
MAX_PASSWORD = 128
DEFAULT_PASSWORD_LENGTH = 24


class PasswordModes(StrEnum):
    RANDOM_MODE = "random"
    STALE_MODE = "stale"


def _coerce_mode(mode: "PasswordModes | str | None") -> PasswordModes:
    """Accept the enum, its value, or None (which means random)."""
    if mode in (None, ""):
        return PasswordModes.RANDOM_MODE
    if isinstance(mode, PasswordModes):
        return mode
    try:
        return PasswordModes(str(mode).strip().lower())
    except ValueError:
        raise ValueError(
            "unknown password mode {!r}; expected one of: {}".format(
                mode, ", ".join(m.value for m in PasswordModes))
        ) from None


class PasswordGenerator:
    """Generate one password of a fixed length in the requested mode."""

    def __init__(self, password_length: int | None = DEFAULT_PASSWORD_LENGTH,
                 password_gen_mode: "PasswordModes | str | None" = None):
        self.password_mode = _coerce_mode(password_gen_mode)
        try:
            request = int(password_length) if password_length else MIN_PASSWORD
        except (TypeError, ValueError):
            raise ValueError("password_length must be an integer") from None
        # Clamp rather than randomise an out-of-range request: the value the
        # caller asked for is the value it should get back, and the panel
        # validates the range before calling anyway.
        self.password_length = max(MIN_PASSWORD, min(MAX_PASSWORD, request))

    def generate(self) -> str:
        if self.password_mode is PasswordModes.STALE_MODE:
            return self._stale()
        return self._random()

    # The name the generator was originally written with; kept so callers that
    # already use it do not have to change in the same commit.
    GeneratePassword = generate

    def _random(self) -> str:
        charset = (string.ascii_lowercase + string.ascii_uppercase
                   + string.digits + string.punctuation)
        return "".join(secrets.choice(charset)
                       for _ in range(self.password_length))

    def _stale(self) -> str:
        """Words plus a random tag, padded/trimmed to exactly the length.

        The tag is what keeps two word-only passwords from colliding, and its
        fixed 9 characters ('#' + 8 hex) is reserved before the words are laid
        out so the result is never shortened afterwards.
        """
        try:
            from faker import Faker
        except ImportError:  # pragma: no cover - depends on the deployment
            raise RuntimeError(
                "the stale password mode needs faker - install it, or use "
                "the random mode") from None

        tag = "#" + secrets.token_hex(4)
        body_length = max(1, self.password_length - len(tag))
        faker = Faker()
        words: list[str] = []
        while True:
            word = "".join(ch for ch in faker.word() if ch.isascii() and ch.isalnum())
            if not word:
                continue
            candidate = "_".join(words + [word])
            if len(candidate) > body_length:
                break
            words.append(word)
            if len(candidate) >= body_length - 2:
                break

        body = "_".join(words)[:body_length]
        # Short bodies happen at the floor (12 - 9 = 3 chars): pad with the
        # same printable alphabet so the value is never shorter than asked.
        if len(body) < body_length:
            body += self._random_alnum(body_length - len(body))
        return body + tag

    @staticmethod
    def _random_alnum(length: int) -> str:
        charset = string.ascii_lowercase + string.digits
        return "".join(secrets.choice(charset) for _ in range(length))


def generate_password(length: int = DEFAULT_PASSWORD_LENGTH,
                      mode: "PasswordModes | str | None" = None) -> str:
    """Convenience wrapper: one call, one password, no object to hold."""
    return PasswordGenerator(length, mode).generate()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="generate a bundle password")
    parser.add_argument("--length", type=int, default=DEFAULT_PASSWORD_LENGTH,
                        help=f"characters, {MIN_PASSWORD}-{MAX_PASSWORD} "
                             f"(default {DEFAULT_PASSWORD_LENGTH})")
    parser.add_argument("--mode", choices=[m.value for m in PasswordModes],
                        default=PasswordModes.RANDOM_MODE.value)
    args = parser.parse_args(argv)
    print(generate_password(args.length, args.mode))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
