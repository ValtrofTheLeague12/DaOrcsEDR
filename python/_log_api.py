# _log_api.py

from __future__ import annotations

import sys
from pathlib import Path

from loguru import logger

# The API server's log goes under the AppData root with the analyzer's, so the
# panel can tail both from one place and a run leaves nothing behind in whatever
# directory the server happened to be started from.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from panel.core.config import logs_dir  # noqa: E402

LOG_DIR     = logs_dir()
LOG_FILE    = LOG_DIR / "logs.jsonl"
ROTATION    = "200 MB"
RETENTION   = 10
COMPRESSION = "gz"
ENQUEUE     = True
BACKTRACE   = True
DIAGNOSE    = False


def setup_logging(
    log_dir: Path = LOG_DIR,
    log_file: Path | None = None,
    *,
    level: str = "DEBUG",
    rotation: str = ROTATION,
    retention: int | str = RETENTION,
    compression: str | None = COMPRESSION,
    also_stderr: bool = True,
    stderr_level: str = "INFO",
) -> Path:
    log_dir.mkdir(parents=True, exist_ok=True)
    target = log_file if log_file is not None else log_dir / "logs.jsonl"
    target.parent.mkdir(parents=True, exist_ok=True)

    logger.remove()

    logger.add(
        target,
        level=level,
        serialize=True,
        rotation=rotation,
        retention=retention,
        compression=compression,
        enqueue=ENQUEUE,
        backtrace=BACKTRACE,
        diagnose=DIAGNOSE,
        encoding="utf-8",
    )

    if also_stderr:
        logger.add(
            sys.stderr,
            level=stderr_level,
            format=(
                "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
                "<level>{level: <8}</level> | "
                "<level>{message}</level>"
            ),
            colorize=True,
            backtrace=BACKTRACE,
            diagnose=DIAGNOSE,
        )

    logger.info("logging initialised — file={} rotation={} retention={} compression={}",
                str(target), rotation, retention, compression)
    return target