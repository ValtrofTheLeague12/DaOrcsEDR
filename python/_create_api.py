# _generate_api.py

from __future__ import annotations

import platform
import re
import socket
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import yaml
from jinja2 import Environment, FileSystemLoader
from loguru import logger

from _log_api import setup_logging

setup_logging(level="DEBUG", stderr_level="DEBUG", also_stderr=True)

YAML_MALAPI  = Path("yaml/malapi")
YAML_LOTS    = Path("yaml/lots")
TEMPLATE_DIR = Path("templates")
TEMPLATE     = "abuse.py.j2"

OUTPUT_DIR      = Path("api")
OUTPUT_PY       = OUTPUT_DIR / "server.py"
OUTPUT_REQ      = OUTPUT_DIR / "requirements.txt"
OUTPUT_README   = OUTPUT_DIR / "README.md"
OUTPUT_MANIFEST = OUTPUT_DIR / "manifest.yaml"

MAX_WORKERS = 8


def _log_exception(context: str, exc: Exception) -> None:
    tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    logger.bind(traceback=tb).error("[-] {}: {}", context, exc)


def _safe_ident(name: str) -> str:
    s = re.sub(r"[^0-9a-zA-Z_]", "_", name)
    s = re.sub(r"_+", "_", s).strip("_")
    if not s:
        s = "entry"
    if s[0].isdigit():
        s = "_" + s
    return s.lower()


def _hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"


def _platform() -> str:
    try:
        return f"{platform.system()} {platform.release()} ({platform.machine()})"
    except Exception:
        return "unknown"


def _py_version() -> str:
    try:
        return platform.python_version()
    except Exception:
        return "unknown"

def _load_yaml_file(path: Path) -> dict | None:
    try:
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            logger.warning("[!] {} does not parse to a mapping, skipping", path.name)
            return None
        return {"path": path, "data": data}
    except Exception as exc:
        _log_exception(f"loading {path}", exc)
        return None


def _load_yaml_dir(root: Path) -> list[dict]:
    if not root.is_dir():
        logger.error("[-] YAML directory not found: {}", root)
        return []

    files = sorted(root.glob("*.yaml"))
    total = len(files)
    logger.info("[*] {}: {} YAML file(s) to load", root, total)

    if total == 0:
        return []

    out: list[dict] = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(_load_yaml_file, p): p for p in files}
        for i, fut in enumerate(as_completed(futures), start=1):
            path = futures[fut]
            try:
                item = fut.result()
            except Exception as exc:
                _log_exception(f"worker for {path.name}", exc)
                continue
            if item is not None:
                out.append(item)
            if i % 50 == 0 or i == total:
                logger.info("[*] {}: {}/{} loaded", root.name, i, total)

    logger.info("[+] loaded {} YAML file(s) from {}", len(out), root)
    return out


def collect_apis() -> list[dict]:
    items = _load_yaml_dir(YAML_MALAPI)
    apis: list[dict] = []

    for item in items:
        path = item["path"]
        data = item["data"]
        api_name = data.get("name") or path.stem
        apis.append({
            "APIName":      api_name,
            "functionName": _safe_ident(api_name),
            "yaml_path":    path.as_posix(),
            "dll":          data.get("dll", ""),
            "description":  data.get("description", ""),
            "attacks":      data.get("attacks", []) or [],
        })

    logger.info("[+] collected {} API entries", len(apis))
    return apis


def collect_domains() -> list[dict]:
    items = _load_yaml_dir(YAML_LOTS)
    domains: list[dict] = []

    for item in items:
        path = item["path"]
        data = item["data"]
        host = data.get("host") or path.stem

        url_safe = (
            host.replace("*", "wildcard_")
                .replace("/", "_")
                .replace(":", "_")
        )

        domains.append({
            "domain":       host,
            "functionName": _safe_ident(host),
            "url_safe":     url_safe,
            "yaml_path":    path.as_posix(),
            "provider":     data.get("provider", ""),
            "tags":         data.get("tags", []) or [],
        })

    logger.info("[+] collected {} domain entries", len(domains))
    return domains


def _render_template(template_name: str, context: dict) -> str:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    return env.get_template(template_name).render(**context)


def render_server(apis: list[dict], domains: list[dict], meta: dict) -> str:
    return _render_template(TEMPLATE, {
        "yaml_files": apis,
        "domains":    domains,
        "meta":       meta,
    })


def render_readme(apis: list[dict], domains: list[dict], meta: dict) -> str:
    return _render_template("README.md.j2", {
        "yaml_files": apis,
        "domains":    domains,
        "meta":       meta,
    })



def _write(path: Path, content: str) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        logger.info("[+] wrote {} ({} bytes)", path, len(content))
        return True
    except Exception as exc:
        _log_exception(f"writing {path}", exc)
        return False


REQUIREMENTS = """\
Flask>=3.0
PyYAML>=6.0
colorama>=0.4.6
"""


def main() -> int:
    try:
        logger.info("[*] generate start")

        apis    = collect_apis()
        domains = collect_domains()

        if not apis and not domains:
            logger.error("[-] nothing to generate — both YAML directories are empty")
            return 1

        now = datetime.now(timezone.utc).astimezone()
        meta = {
            "generated_at":   now.isoformat(timespec="seconds"),
            "generated_at_h": now.strftime("%Y-%m-%d %H:%M:%S %Z"),
            "generated_by":   _hostname(),
            "generator_host": _hostname(),
            "platform":       _platform(),
            "python":         _py_version(),
            "api_count":      len(apis),
            "domain_count":   len(domains),
            "total_routes":   len(apis) + len(domains),
            "source_malapi":  YAML_MALAPI.as_posix(),
            "source_lots":    YAML_LOTS.as_posix(),
        }

        logger.info(
            "[*] generating api/ — apis={} domains={} at {} by {}",
            meta["api_count"], meta["domain_count"],
            meta["generated_at_h"], meta["generated_by"],
        )

        server_src = render_server(apis, domains, meta)
        readme_src = render_readme(apis, domains, meta)

        files = [
            (OUTPUT_PY,       server_src),
            (OUTPUT_REQ,      REQUIREMENTS),
            (OUTPUT_README,   readme_src),
            (OUTPUT_MANIFEST, yaml.safe_dump(meta, sort_keys=False, allow_unicode=True)),
        ]

        results: list[bool] = [False] * len(files)
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures = {
                pool.submit(_write, path, content): idx
                for idx, (path, content) in enumerate(files)
            }
            for fut in as_completed(futures):
                idx = futures[fut]
                try:
                    results[idx] = fut.result()
                except Exception as exc:
                    _log_exception(f"writer {files[idx][0]}", exc)
                    results[idx] = False

        if not all(results):
            logger.error("[-] one or more files failed to write")
            return 1

        logger.info("[+] generate done — output in {}", OUTPUT_DIR)
        return 0

    except KeyboardInterrupt:
        logger.warning("[!] interrupted by user")
        return 130
    except Exception as exc:
        _log_exception("main()", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())