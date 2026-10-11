#!/usr/bin/env python3
"""Shared logging for the ml/ scripts.

Each run appends to a timestamped file under logs/ at the repo root
($ML_LOG_DIR overrides it when ml/ is copied onto a training VM):

    logs/ml_<script>_<UTC yyyymmdd-HHMMSS>.log

Console behaviour is deliberately unchanged: INFO lines keep their exact
`[*]` / `[+]` / `[!]` text on stdout, warnings and errors go to stderr, so
piping and eyeballing still work the way they did with plain prints. The file
additionally captures DEBUG detail and full tracebacks via log.exception().
predict.py --json turns the console handlers off so stdout stays
machine-readable; the run is still written to the file.

    import mllog
    log = mllog.setup("train")
    log.info("[+] trained in %.1fs", elapsed)
"""

from __future__ import annotations

import logging
import os
import sys
import time
from pathlib import Path

_CONSOLE_FMT = "%(message)s"
_FILE_FMT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"
_FILE_DATE = "%Y-%m-%d %H:%M:%S"


def log_dir() -> Path:
    """Destination for log files: $ML_LOG_DIR, else <repo>/logs."""
    override = os.environ.get("ML_LOG_DIR")
    if override:
        return Path(override)
    # ml/mllog.py -> repo root is parents[1].
    return Path(__file__).resolve().parents[1] / "logs"


class _LevelRange(logging.Filter):
    """Accept records with lo <= level < hi (stdout/stderr split)."""

    def __init__(self, lo: int, hi: int) -> None:
        super().__init__()
        self._lo = lo
        self._hi = hi

    def filter(self, record: logging.LogRecord) -> bool:
        return self._lo <= record.levelno < self._hi


def _console_handler(stream, lo: int, hi: int) -> logging.Handler:
    handler = logging.StreamHandler(stream)
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter(_CONSOLE_FMT))
    handler.addFilter(_LevelRange(lo, hi))
    handler._ml_console = True  # type: ignore[attr-defined]
    return handler


def _file_handler(script: str) -> logging.Handler | None:
    dest = log_dir()
    try:
        dest.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
        path = dest / f"ml_{script}_{stamp}.log"
        handler = logging.FileHandler(path, encoding="utf-8", delay=True)
    except OSError as exc:
        # A read-only or missing logs/ must never kill a training run.
        print(f"[!] mllog: cannot open {dest} ({exc}); file logging off",
              file=sys.stderr)
        return None
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter(_FILE_FMT, datefmt=_FILE_DATE))
    return handler


def setup(script: str, console: bool = True, stdout: bool = True) -> logging.Logger:
    """Configure and return the `ml.<script>` logger. Idempotent.

    console=False  -> file logging only (no console handlers at all).
    stdout=False   -> keep the stderr console handler but drop stdout; used by
                      predict.py --json so stdout stays pure JSON while
                      warnings and errors remain visible.
    """
    logger = logging.getLogger(f"ml.{script}")
    if logger.handlers:
        if not console:
            for handler in [h for h in logger.handlers
                            if getattr(h, "_ml_console", False)]:
                logger.removeHandler(handler)
        elif not stdout:
            for handler in [h for h in logger.handlers
                            if getattr(h, "_ml_console", False)
                            and getattr(h, "_ml_stdout", False)]:
                logger.removeHandler(handler)
        return logger
    logger.setLevel(logging.DEBUG)
    logger.propagate = False  # no duplicate output through the root logger

    file_handler = _file_handler(script)
    if file_handler is not None:
        logger.addHandler(file_handler)

    if console:
        # stdout: INFO..WARNING-class messages (the [!] prints used stderr,
        # so warnings keep going there); stderr: WARNING and above.
        if stdout:
            out = _console_handler(sys.stdout, logging.INFO, logging.WARNING)
            out._ml_stdout = True  # type: ignore[attr-defined]
            logger.addHandler(out)
        logger.addHandler(_console_handler(sys.stderr, logging.WARNING,
                                          logging.CRITICAL + 1))
    return logger
