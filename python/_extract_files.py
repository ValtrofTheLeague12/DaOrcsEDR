# scrape.py

from __future__ import annotations

import errno
import hashlib
import shutil
import socket
import subprocess
import sys
import traceback
import zipfile
from pathlib import Path

from colorama import Fore, Style, init
from loguru import logger

# Generated state goes under the AppData root, not the working directory. The
# analyzer spawns this script from python/, so a relative "logs" and "cache" put
# a log tree and a cache tree inside the source repo.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from panel.core.config import cache_dir as appdata_cache, logs_dir as appdata_logs  # noqa: E402

init(autoreset=True)

URL_FILE   = Path("url")
CACHE_DIR  = appdata_cache()
MALAPI_DIR = Path("malapi")
LOTS_DIR   = Path("lots")
LOG_DIR    = appdata_logs()
LOG_FILE   = LOG_DIR / "logs.jsonl"
WSL_DISTRO = None
DEPTH      = 3
SOCKETS    = 4

NET_PROBE_HOST    = "1.1.1.1"
NET_PROBE_PORT    = 53
NET_PROBE_TIMEOUT = 3.0

MIN_HTML_FILES = 1

WSA_NAMES = {
    10050: "WSAENETDOWN",
    10051: "WSAENETUNREACH",
    10052: "WSAENETRESET",
    10053: "WSAECONNABORTED",
    10054: "WSAECONNRESET",
    10060: "WSAETIMEDOUT",
    10061: "WSAECONNREFUSED",
    10064: "WSAEHOSTDOWN",
    10065: "WSAEHOSTUNREACH",
}

CACHE_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def _console_format(record) -> str:
    ts = record["time"].strftime("%Y-%m-%d %H:%M:%S")
    level = record["level"].name
    message = record["message"]
    tb = record["extra"].get("traceback", "") or ""

    if level in ("ERROR", "CRITICAL"):
        return Fore.RED + f"{ts} | {level:<8} | {message}" + Style.RESET_ALL + "\n" + tb
    if level == "WARNING":
        return Fore.YELLOW + f"{ts} | {level:<8} | {message}" + Style.RESET_ALL + "\n"
    if level == "SUCCESS":
        return Fore.GREEN + f"{ts} | {level:<8} | {message}" + Style.RESET_ALL + "\n"
    return Fore.CYAN + f"{ts} | {level:<8} | {message}" + Style.RESET_ALL + "\n"


logger.remove()
logger.add(sys.stderr, level="DEBUG", format=_console_format, colorize=False)
logger.add(
    LOG_FILE,
    level="DEBUG",
    serialize=True,
    rotation="200 MB",
    retention=10,
    compression="gz",
    enqueue=True,
    encoding="utf-8",
)


def _log_exception(context: str, exc: Exception) -> None:
    tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    logger.bind(traceback=tb).error("[-] {}: {}", context, exc)


def _errno_name(rc: int) -> str:
    if rc in WSA_NAMES:
        return WSA_NAMES[rc]
    return errno.errorcode.get(rc, f"errno={rc}")


# ---------------------------------------------------------------------------
# HTML globbing — one function per directory
# ---------------------------------------------------------------------------

def list_malapi_html() -> list[Path]:
    return _list_html_under(MALAPI_DIR, "malapi")


def list_lots_html() -> list[Path]:
    return _list_html_under(LOTS_DIR, "lots")


def _list_html_under(root: Path, label: str) -> list[Path]:
    try:
        if not root.exists() or not root.is_dir():
            logger.debug("[!] {} ({}) is not a directory — no HTML to list", label, root)
            return []
    except OSError as exc:
        _log_exception(f"stat {label} ({root})", exc)
        return []

    try:
        files = sorted(
            (p for p in root.rglob("*.html") if p.is_file()),
            key=lambda p: str(p).lower(),
        )
    except OSError as exc:
        _log_exception(f"globbing {label} ({root})", exc)
        return []
    except Exception as exc:
        _log_exception(f"unexpected error globbing {label} ({root})", exc)
        return []

    logger.info("[+] {}: {} HTML file(s) under {}", label, len(files), root)
    return files


def _print_html_under(root: Path, label: str) -> None:
    files = _list_html_under(root, label)
    if not files:
        logger.warning("[!] no HTML files under {} ({})", label, root)
        return

    try:
        root_resolved = root.resolve()
    except OSError:
        root_resolved = root

    print("")
    print(f"=== {label.upper()} HTML ({len(files)} file(s)) under {root} ===")
    for path in files:
        try:
            rel = path.relative_to(root_resolved)
        except ValueError:
            rel = path
        try:
            size_kb = path.stat().st_size / 1024.0
            print(f"  {rel}  ({size_kb:.1f} KiB)")
        except OSError as exc:
            print(f"  {rel}  (stat failed: {exc})")
            logger.warning("[!] stat failed for {}: {}", path, exc)
    print(f"=== end {label.upper()} ({len(files)} file(s)) ===\n")


def print_malapi_html() -> None:
    _print_html_under(MALAPI_DIR, "malapi")


def print_lots_html() -> None:
    _print_html_under(LOTS_DIR, "lots")


def print_all_html() -> None:
    print_malapi_html()
    print_lots_html()


# ---------------------------------------------------------------------------
# Network check
# ---------------------------------------------------------------------------

def is_online() -> bool:
    logger.debug("[*] probing network via connect_ex {}:{}",
                 NET_PROBE_HOST, NET_PROBE_PORT)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(NET_PROBE_TIMEOUT)
    try:
        rc = sock.connect_ex((NET_PROBE_HOST, NET_PROBE_PORT))
        if rc == 0:
            logger.debug("[+] network reachable (connect_ex rc=0)")
            return True
        logger.debug("[!] connect_ex rc={} ({})", rc, _errno_name(rc))
        return False
    except OSError as exc:
        logger.debug("[!] connect_ex raised: {}", exc)
        return False
    except Exception as exc:
        _log_exception("connect_ex network probe", exc)
        return False
    finally:
        try:
            sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Local directory check
# ---------------------------------------------------------------------------

def _dir_has_html(dest: Path, min_files: int = MIN_HTML_FILES) -> bool:
    try:
        if not dest.exists() or not dest.is_dir():
            return False
        if not dest.iterdir():
            return False
    except OSError as exc:
        logger.debug("[!] cannot inspect {}: {}", dest, exc)
        return False

    try:
        for candidate in (
            dest / "index.html",
            *dest.glob("*/index.html"),
            *dest.glob("*/*/index.html"),
        ):
            if candidate.is_file():
                return True
    except OSError as exc:
        logger.debug("[!] fast-path glob failed under {}: {}", dest, exc)

    count = 0
    try:
        for _ in dest.rglob("*.html"):
            count += 1
            if count >= min_files:
                return True
    except OSError as exc:
        logger.debug("[!] rglob failed under {}: {}", dest, exc)
        return False
    return False


def _local_hit(dest: Path) -> bool:
    if not _dir_has_html(dest):
        return False
    logger.success("[+] local hit: {} already populated", dest)
    return True


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

def _cache_key(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]


def _cache_zip(url: str) -> Path:
    return CACHE_DIR / f"{_cache_key(url)}.zip"


def _cache_hit(url: str, dest: Path) -> bool:
    archive = _cache_zip(url)
    if not archive.exists():
        logger.debug("[*] no cache entry for {} ({})", url, archive.name)
        return False

    try:
        if not zipfile.is_zipfile(archive):
            logger.warning("[!] corrupt cache archive, discarding: {}", archive)
            archive.unlink(missing_ok=True)
            return False
    except OSError as exc:
        _log_exception(f"validating cache archive {archive}", exc)
        return False

    try:
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        dest.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        _log_exception(f"preparing {dest} for cache extract", exc)
        return False

    try:
        with zipfile.ZipFile(archive, "r") as zf:
            zf.extractall(dest)
        logger.success("[+] cache hit: {} → {} ({})", url, dest, archive.name)
        return True
    except Exception as exc:
        _log_exception(f"extracting cache for {url}", exc)
        shutil.rmtree(dest, ignore_errors=True)
        archive.unlink(missing_ok=True)
        return False


def _cache_store(url: str, dest: Path) -> None:
    archive = _cache_zip(url)
    tmp = archive.with_suffix(".zip.tmp")
    logger.debug("[*] storing cache for {} → {}", url, archive.name)
    try:
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
            for path in dest.rglob("*"):
                if path.is_file():
                    zf.write(path, path.relative_to(dest.parent))
        tmp.replace(archive)
        size_mb = archive.stat().st_size / (1024 * 1024)
        logger.info("[+] cached {} → {} ({:.2f} MB)", url, archive.name, size_mb)
    except Exception as exc:
        _log_exception(f"storing cache for {url}", exc)
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Offline extraction
# ---------------------------------------------------------------------------

def extract_from_cache(url: str, dest: Path) -> bool:
    archive = _cache_zip(url)
    if not archive.exists():
        logger.warning("[-] no cache entry for {} ({})", url, archive.name)
        return False

    try:
        if not zipfile.is_zipfile(archive):
            logger.error("[-] cache archive is corrupt: {}", archive)
            return False
    except OSError as exc:
        _log_exception(f"validating {archive}", exc)
        return False

    try:
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        dest.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        _log_exception(f"preparing {dest} for offline extract", exc)
        return False

    try:
        with zipfile.ZipFile(archive, "r") as zf:
            zf.extractall(dest)
        logger.success("[+] extracted (offline) {} → {}", archive.name, dest)
        return True
    except Exception as exc:
        _log_exception(f"offline extract for {url}", exc)
        shutil.rmtree(dest, ignore_errors=True)
        return False


def extract_all_offline(urls: list[str]) -> tuple[int, int, int, int]:
    malapi_ok = 0
    lots_ok = 0
    missing = 0
    already = 0

    for url in urls:
        try:
            dest = classify(url)
            if dest is None:
                logger.debug("[*] offline: skipping unrecognised URL {}", url)
                continue

            if _local_hit(dest):
                already += 1
                continue

            if extract_from_cache(url, dest):
                if dest == MALAPI_DIR:
                    malapi_ok += 1
                else:
                    lots_ok += 1
            else:
                missing += 1
        except Exception as exc:
            _log_exception(f"offline handling of {url}", exc)
            missing += 1

    return malapi_ok, lots_ok, missing, already


# ---------------------------------------------------------------------------
# WSL / HTTrack plumbing
# ---------------------------------------------------------------------------

def _wsl_available() -> bool:
    if shutil.which("wsl") is None:
        logger.debug("[!] wsl not found on PATH")
        return False
    try:
        r = subprocess.run(["wsl", "--status"], capture_output=True, timeout=5)
        if r.returncode == 0:
            logger.debug("[+] WSL is available")
            return True
        logger.debug("[!] wsl --status exit={}", r.returncode)
        return False
    except subprocess.TimeoutExpired:
        logger.error("[-] wsl --status timed out")
        return False
    except Exception as exc:
        _log_exception("checking WSL availability", exc)
        return False


def _to_wsl_path(win_path: Path) -> str:
    p = win_path.resolve()
    drive = p.drive.rstrip(":").lower()
    rest = str(p)[len(p.drive):].replace("\\", "/").lstrip("/")
    return f"/mnt/{drive}/{rest}"


def _wsl_prefix() -> list[str]:
    base = ["wsl"]
    if WSL_DISTRO:
        base += ["-d", WSL_DISTRO]
    return base


def _ensure_httrack_in_wsl() -> bool:
    cmd = _wsl_prefix() + ["which", "httrack"]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=10)
        if r.returncode == 0:
            logger.debug("[+] httrack found inside WSL")
            return True
    except subprocess.TimeoutExpired:
        logger.error("[-] probing httrack timed out")
        return False
    except Exception as exc:
        _log_exception("probing httrack inside WSL", exc)
        return False

    logger.warning("[!] httrack not found in WSL — attempting install")
    install = _wsl_prefix() + [
        "bash", "-lc",
        "sudo apt-get update -qq && sudo apt-get install -y -qq httrack",
    ]
    try:
        r = subprocess.run(install, capture_output=True, timeout=300)
        if r.returncode != 0:
            logger.error("[-] apt install failed: {}",
                         r.stderr.decode(errors="replace")[:400])
            return False
        logger.success("[+] httrack installed inside WSL")
        return True
    except subprocess.TimeoutExpired:
        logger.error("[-] apt install timed out")
        return False
    except Exception as exc:
        _log_exception("installing httrack in WSL", exc)
        return False


def mirror(url: str, dest: Path) -> str:
    try:
        if _local_hit(dest):
            return "local"

        if _cache_hit(url, dest):
            return "cache"

        try:
            dest.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            _log_exception(f"creating {dest}", exc)
            return "fail"

        wsl_dest = _to_wsl_path(dest)
        logger.info("[+] mirroring {} → {} (wsl: {})", url, dest, wsl_dest)

        cmd = _wsl_prefix() + [
            "httrack", url,
            "-O", wsl_dest,
            f"-r{DEPTH}",
            f"--sockets={SOCKETS}",
            "--robots=0",
            "-%v",
        ]

        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        except subprocess.TimeoutExpired:
            logger.error("[-] httrack timed out after 30 min for {}", url)
            return "fail"
        except Exception as exc:
            _log_exception(f"running httrack for {url}", exc)
            return "fail"

        if r.returncode != 0:
            logger.error("[-] httrack exit={} for {}", r.returncode, url)
            if r.stderr:
                logger.error("[-] stderr: {}", r.stderr.strip()[:400])
            return "fail"

        if r.stdout:
            logger.debug("[*] httrack stdout tail: {}", r.stdout.strip()[-400:])

        logger.success("[+] mirrored {}", url)
        _cache_store(url, dest)
        return "download"

    except Exception as exc:
        _log_exception(f"mirror({url})", exc)
        return "fail"


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def load_urls(path: Path) -> list[str]:
    try:
        if not path.exists():
            logger.error("[-] file not found: {}", path)
            return []
        if path.stat().st_size == 0:
            logger.error("[-] file is empty: {}", path)
            return []

        urls = [
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        if not urls:
            logger.error("[-] no URLs found in {}", path)
            return []

        logger.info("[+] loaded {} URL(s) from {}", len(urls), path)
        return urls
    except Exception as exc:
        _log_exception(f"loading URLs from {path}", exc)
        return []


def classify(url: str) -> Path | None:
    try:
        lowered = url.lower()
        if "malapi.io" in lowered:
            return MALAPI_DIR
        if "lots-project.com" in lowered:
            return LOTS_DIR
        return None
    except Exception as exc:
        _log_exception(f"classifying {url}", exc)
        return None


def _log_counts(counts: dict[str, int]) -> None:
    logger.info(
        "[+] done — download={} cache={} local={} fail={} skipped={}",
        counts["download"], counts["cache"], counts["local"],
        counts["fail"], counts["skipped"],
    )


def main() -> int:
    try:
        logger.info("[*] scrape start")
        urls = load_urls(URL_FILE)
        if not urls:
            logger.error("[-] aborting: no URLs to process")
            return 1

        counts = {"download": 0, "cache": 0, "local": 0, "skipped": 0, "fail": 0}
        pending: list[tuple[str, Path]] = []

        for url in urls:
            dest = classify(url)
            if dest is None:
                logger.warning("[-] skipping unrecognised URL: {}", url)
                counts["skipped"] += 1
                continue
            if _local_hit(dest):
                counts["local"] += 1
                continue
            pending.append((url, dest))

        if not pending:
            logger.success("[+] all destinations already populated — nothing to do")
            _log_counts(counts)

            print_malapi_html()
            print_lots_html()

            logger.info("[*] scrape end (no work)")
            return 0

        online = is_online()

        if not online:
            logger.warning("[!] network unreachable — running in offline mode")
            malapi_ok, lots_ok, missing, already = extract_all_offline(urls)
            logger.info(
                "[+] offline done — malapi={} lots={} missing={} already_present={}",
                malapi_ok, lots_ok, missing, already,
            )

            print_malapi_html()
            print_lots_html()

            logger.info("[*] scrape end (offline)")
            return 0 if (malapi_ok or lots_ok or already) else 1

        logger.info("[+] network reachable — running in online mode")

        if not _wsl_available():
            logger.error("[-] WSL is not available or not responding")
            return 1

        if not _ensure_httrack_in_wsl():
            logger.error("[-] httrack is not available inside WSL")
            return 1

        for url, dest in pending:
            try:
                logger.debug("[*] pending: {} → {}", url, dest)
                outcome = mirror(url, dest)
                counts[outcome if outcome in counts else "fail"] += 1
            except Exception as exc:
                _log_exception(f"handling {url}", exc)
                counts["fail"] += 1

        _log_counts(counts)

        print_malapi_html()
        print_lots_html()

        logger.info("[*] scrape end (online)")
        return 0 if counts["fail"] == 0 else 1

    except KeyboardInterrupt:
        logger.warning("[!] interrupted by user")
        return 130
    except Exception as exc:
        _log_exception("main()", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())