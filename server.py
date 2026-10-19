#!/usr/bin/env python3
r"""Flask REST API around the static analyzer.

Runs the analyzer as a service: clients upload a sample, pick a pipeline and
get back a task they can poll (or block on).

    python\.venv\Scripts\python.exe server.py
    python\.venv\Scripts\python.exe server.py --port 7000 --rate-limit 20

The bind address is resolved process environment first, then the repository
`.env` (SA_API_HOST, SA_API_PORT), then 127.0.0.1:60020 - in that order, so an
explicit export always wins and the default only applies when neither says
anything. On this checkout `.env` sets 60025, which is what it binds.

Endpoints (JSON in, JSON out):

    GET    /                                service index
    GET    /health                          liveness + queue stats
    GET    /phases                          analyzer --list-phases --json
    GET    /pipelines                       named pipeline configs
    POST   /analyze?pipeline=<spec>         upload a sample -> 202 + task id
             &filename=<name>               (or multipart/form-data with a file)
             &wait=true                     block until finished -> 200/502
    GET    /tasks                           list tasks
    GET    /tasks/<id>                      task detail (+ manifest when done)
    GET    /tasks/<id>/log                  analyzer stdout/stderr tail
    GET    /tasks/<id>/artifacts            artifact files of the run
    GET    /tasks/<id>/artifacts/<path>     download one artifact
    DELETE /tasks/<id>                      cancel (if running) and purge

Protection:
  * uploads are capped at 10 MB (413), checked from Content-Length and again
    after reading;
  * POST /analyze is token-bucket rate limited per client IP (429 +
    Retry-After); every endpoint has a generous flood cap;
  * SIGINT/SIGTERM keep the listener up, refuse new work with 503, wait for
    running analyses up to --shutdown-timeout, then kill what is left.

Concurrency: Flask runs threaded (werkzeug), analyses run on a
ThreadPoolExecutor (--max-workers), so a task that spawns other work (the
analyzer's own services, capa, radare2, ...) never serialises the API.

Examples:

    curl localhost:60020/health
    curl -X POST "localhost:60020/analyze?pipeline=extract_eat&wait=true" \
         -H "X-Filename: a.exe" --data-binary @a.exe
    curl -F "file=@a.exe" "localhost:60020/analyze?pipeline=quick"
    curl localhost:60020/tasks/<id>/artifacts
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

try:
    from flask import Flask, Response, jsonify, request, send_file
    from werkzeug.exceptions import HTTPException, RequestEntityTooLarge
    from werkzeug.serving import make_server
except ImportError:  # pragma: no cover - friendly bootstrap
    sys.exit("Flask is required. Run me with the repo venv:\n"
             "    python\\.venv\\Scripts\\python.exe server.py\n"
             "or: pip install flask")

REPO = Path(__file__).resolve().parent
MAX_UPLOAD = 10 * 1024 * 1024  # 10 MB, per spec
UCRT64_BIN = r"C:\msys64\ucrt64\bin"

log = logging.getLogger("analyzer.api")


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Rate limiting - token bucket, one per client IP
# ---------------------------------------------------------------------------
class RateLimiter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._buckets: dict[str, tuple[float, float]] = {}  # ip -> (tokens, ts)

    def allow(self, key: str, limit: int, window: float) -> tuple[bool, int]:
        """Consume one token. Returns (allowed, retry_after_seconds)."""
        if limit <= 0:
            return True, 0
        now = time.monotonic()
        rate = limit / window
        with self._lock:
            if len(self._buckets) > 512:  # long-lived servers must not leak
                cutoff = now - window * 4
                self._buckets = {
                    ip: b for ip, b in self._buckets.items() if b[1] > cutoff
                }
            tokens, ts = self._buckets.get(key, (float(limit), now))
            tokens = min(float(limit), tokens + (now - ts) * rate)
            if tokens < 1.0:
                self._buckets[key] = (tokens, now)
                return False, max(1, int((1.0 - tokens) / rate) + 1)
            self._buckets[key] = (tokens - 1.0, now)
            return True, 0


# ---------------------------------------------------------------------------
# Task model
# ---------------------------------------------------------------------------
QUEUED, RUNNING, DONE, FAILED, CANCELLED, ERROR = (
    "queued", "running", "done", "failed", "cancelled", "error"
)
TERMINAL = {DONE, FAILED, CANCELLED, ERROR}


class Task:
    def __init__(self, task_id: str, pipeline: str, filename: str, stored: str) -> None:
        self.id = task_id
        self.pipeline = pipeline
        self.filename = filename          # original name as uploaded
        self.stored = stored              # on-disk name (task-id prefixed, unique)
        self.state = QUEUED
        self.error: Optional[str] = None
        self.exit_code: Optional[int] = None
        self.submitted = utcnow()
        self.started: Optional[str] = None
        self.finished: Optional[str] = None
        self.proc: Optional[subprocess.Popen] = None
        self.cancel_requested = False
        self.manifest: Optional[dict] = None
        self.log_path: Optional[Path] = None

    @property
    def stem(self) -> str:
        return os.path.splitext(self.stored)[0]

    @property
    def export_dir(self) -> Path:
        return REPO / "exports" / f"{self.stem}_analysis"

    @property
    def dir(self) -> Path:
        return REPO / "tasks" / self.id

    def view(self, full: bool = True) -> dict:
        out: dict[str, Any] = {
            "id": self.id,
            "state": self.state,
            "pipeline": self.pipeline,
            "filename": self.filename,
            "submitted": self.submitted,
            "started": self.started,
            "finished": self.finished,
            "exit_code": self.exit_code,
            "error": self.error,
            "links": {
                "self": f"/tasks/{self.id}",
                "log": f"/tasks/{self.id}/log",
                "artifacts": f"/tasks/{self.id}/artifacts",
            },
        }
        if full and self.state in TERMINAL:
            out["manifest"] = self.manifest
        return out


class TaskRegistry:
    """All shared mutable state, behind one lock (tasks are few, holds are short)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._tasks: dict[str, Task] = {}

    def add(self, task: Task) -> None:
        with self._lock:
            self._tasks[task.id] = task

    def get(self, task_id: str) -> Optional[Task]:
        with self._lock:
            return self._tasks.get(task_id)

    def remove(self, task_id: str) -> Optional[Task]:
        with self._lock:
            return self._tasks.pop(task_id, None)

    def list(self) -> list[Task]:
        with self._lock:
            return sorted(self._tasks.values(), key=lambda t: t.submitted, reverse=True)

    def counts(self) -> dict[str, int]:
        with self._lock:
            c = {QUEUED: 0, RUNNING: 0}
            for t in self._tasks.values():
                if t.state in (QUEUED, RUNNING):
                    c[t.state] = c.get(t.state, 0) + 1
            return c

    def running(self) -> list[Task]:
        with self._lock:
            return [t for t in self._tasks.values() if t.state == RUNNING]


# ---------------------------------------------------------------------------
# Server core
# ---------------------------------------------------------------------------
class Api:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.analyzer = Path(args.analyzer).resolve()
        self.registry = TaskRegistry()
        self.limiter = RateLimiter()
        self.pool = ThreadPoolExecutor(
            max_workers=args.max_workers, thread_name_prefix="analyze"
        )
        self.shutdown_event = threading.Event()
        self.phases: Optional[list] = None  # cached at startup
        self.pipelines: list[dict] = []
        self.started_at = time.time()
        self._retention_stop = threading.Event()

    # -- helpers ------------------------------------------------------------
    def child_env(self) -> dict:
        env = os.environ.copy()
        # ucrt64 must be FIRST: a DLL later in PATH can shadow one of the
        # analyzer's and the exe then dies with 0xC0000135 before printing.
        if Path(UCRT64_BIN).is_dir() and not env.get("PATH", "").startswith(UCRT64_BIN):
            env["PATH"] = UCRT64_BIN + os.pathsep + env["PATH"]
        env["STATIC_ANALYZER_CURSES"] = "0"
        return env

    def run_analyzer(self, flags: list[str], timeout: float = 60) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(self.analyzer), *flags],
            cwd=str(REPO), env=self.child_env(), text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout,
            **spawn_kwargs(),
        )

    def warm_caches(self) -> None:
        try:
            proc = self.run_analyzer(["--list-phases", "--json"])
            text = proc.stdout or ""
            payload = text[text.index("\n[\n") + 1:] if "\n[\n" in text else text
            self.phases = json.loads(payload)
        except Exception as exc:  # noqa: BLE001 - warm-up must not kill startup
            log.warning("could not cache phase catalog: %s", exc)
        self.pipelines = scan_pipelines(self.analyzer)

    # -- analysis -----------------------------------------------------------
    def submit(self, data: bytes, filename: str, pipeline: str,
               wait: bool) -> tuple[int, dict]:
        """Persist the upload and schedule it. Returns (http_code, body)."""
        counts = self.registry.counts()
        if counts[QUEUED] + counts[RUNNING] >= self.args.max_queued + self.args.max_workers:
            return 503, {"error": "task queue is full, retry later"}

        task_id = uuid.uuid4().hex[:12]
        safe = sanitize_filename(filename)
        # Task-id prefix keeps the analyzer stem unique, so concurrent uploads
        # of the same file never share exports/<stem>_analysis/.
        stored = f"{task_id}_{safe}"
        task = Task(task_id, pipeline, filename, stored)
        task.dir.mkdir(parents=True, exist_ok=True)
        (task.dir / stored).write_bytes(data)
        self.registry.add(task)

        self.pool.submit(self._run, task)
        if not wait:
            return 202, {"status": "queued", "task": task.view(),
                         "poll": f"/tasks/{task.id}"}

        deadline = time.monotonic() + self.args.wait_timeout
        while task.state not in TERMINAL and time.monotonic() < deadline:
            time.sleep(0.2)
        if task.state not in TERMINAL:
            return 504, {"error": "analysis timed out", "task": task.view()}
        body = task.view()
        body["log_tail"] = read_tail(task.log_path)
        if task.state == DONE:
            return 200, body
        if task.state == FAILED:
            return 502, body
        return 409, body  # cancelled / error

    def _run(self, task: Task) -> None:
        with self.registry._lock:  # noqa: SLF001 - registry owns the transition
            if task.cancel_requested:
                task.state = CANCELLED
                task.finished = utcnow()
                return
            task.state = RUNNING
            task.started = utcnow()

        # file on disk is the sanitized, task-id-prefixed name
        args = [str(self.analyzer), "--pipeline", task.pipeline, str(task.dir / task.stored)]
        task.log_path = task.dir / "analyzer.log"
        try:
            with open(task.log_path, "wb") as logf:
                proc = subprocess.Popen(
                    args, cwd=str(REPO), env=self.child_env(),
                    stdout=logf, stderr=subprocess.STDOUT,
                    **spawn_kwargs(),
                )
                task.proc = proc
                try:
                    rc = proc.wait(timeout=self.args.timeout)
                except subprocess.TimeoutExpired:
                    kill_tree(proc)
                    task.state = ERROR
                    task.error = f"analysis exceeded {self.args.timeout}s and was killed"
                else:
                    task.exit_code = rc
                    task.manifest = load_manifest(task)
                    if task.cancel_requested:
                        task.state = CANCELLED
                    elif rc == 0:
                        task.state = DONE
                    else:
                        task.state = FAILED
                        task.error = failure_reason(task)
        except OSError as exc:
            task.state = ERROR
            task.error = f"could not start the analyzer: {exc}"
        finally:
            task.proc = None
            task.finished = utcnow()

    def cancel(self, task: Task) -> bool:
        with self.registry._lock:  # noqa: SLF001
            task.cancel_requested = True
            state = task.state
            proc = task.proc
        if state in TERMINAL:
            return False
        if state == RUNNING and proc is not None:
            kill_tree(proc)
        return True

    # -- housekeeping -------------------------------------------------------
    def retention_loop(self) -> None:
        while not self._retention_stop.wait(60):
            if self.args.retention <= 0:
                continue
            cutoff = time.time() - self.args.retention
            for task in self.registry.list():
                if task.state not in TERMINAL or task.finished is None:
                    continue
                finished = datetime.fromisoformat(task.finished).timestamp()
                if finished < cutoff:
                    purge_task(task)
                    self.registry.remove(task.id)
                    log.info("retention: removed task %s", task.id)

    def drain(self, grace: float) -> None:
        """Wait for queued/running analyses, then kill whatever is left."""
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            counts = self.registry.counts()
            if counts[QUEUED] + counts[RUNNING] == 0:
                break
            time.sleep(0.5)
        for task in self.registry.running():
            if task.proc is not None:
                kill_tree(task.proc)

    def stop(self, grace: float) -> None:
        """Stop accepting, let running analyses finish, kill the stragglers."""
        self._retention_stop.set()
        self.drain(grace)
        self.pool.shutdown(wait=False, cancel_futures=True)


# ---------------------------------------------------------------------------
# Flask application
# ---------------------------------------------------------------------------
def create_app(api: Api) -> Flask:
    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD + 64 * 1024  # multipart overhead

    def client_ip() -> str:
        return request.remote_addr or "?"

    def rate(key: str, limit: int, window: float) -> Optional[Response]:
        allowed, retry = api.limiter.allow(key, limit, window)
        if allowed:
            return None
        resp = jsonify(error="rate limit exceeded", limit_per_min=limit)
        resp.status_code = 429
        resp.headers["Retry-After"] = str(retry)
        resp.headers["X-RateLimit-Limit"] = str(limit)
        return resp

    @app.before_request
    def gate() -> Optional[Response]:
        if api.shutdown_event.is_set():
            return jsonify(error="server is shutting down"), 503
        return rate("flood:" + client_ip(), api.args.read_limit, 60.0)

    # -- errors as JSON -----------------------------------------------------
    @app.errorhandler(RequestEntityTooLarge)
    def _too_large(_exc: RequestEntityTooLarge) -> tuple[dict, int]:
        return jsonify(error="sample too large", max_bytes=MAX_UPLOAD), 413

    @app.errorhandler(HTTPException)
    def _http_error(exc: HTTPException) -> tuple[dict, int]:
        if exc.code == 404:
            return jsonify(error="not found", path=request.path), 404
        if exc.code == 405:
            return jsonify(error="method not allowed"), 405
        return jsonify(error=exc.description or "error"), exc.code or 500

    @app.errorhandler(Exception)
    def _boom(exc: Exception) -> tuple[dict, int]:
        log.exception("unhandled error on %s %s", request.method, request.path)
        return jsonify(error="internal error", detail=str(exc)), 500

    # -- GET ---------------------------------------------------------------
    @app.get("/")
    def index():
        return jsonify(
            service="static-analyzer-api",
            version="0.2.0",
            endpoints=["/health", "/phases", "/pipelines", "/analyze", "/tasks"],
            max_upload_bytes=MAX_UPLOAD,
            pipelines=[p["name"] for p in api.pipelines],
        )

    @app.get("/health")
    def health():
        counts = api.registry.counts()
        return jsonify(
            status="shutting_down" if api.shutdown_event.is_set() else "ok",
            analyzer=str(api.analyzer),
            analyzer_present=api.analyzer.is_file(),
            queued=counts[QUEUED],
            running=counts[RUNNING],
            uptime_s=round(time.time() - api.started_at, 1),
            rate_limit_per_min=api.args.rate_limit,
            max_upload_bytes=MAX_UPLOAD,
        )

    @app.get("/phases")
    def phases():
        if api.phases is None:
            return jsonify(error="phase catalog unavailable"), 503
        return jsonify(api.phases)

    @app.get("/pipelines")
    def pipelines():
        return jsonify(api.pipelines)

    @app.get("/tasks")
    def task_list():
        limit = request.args.get("limit", 100, type=int)
        return jsonify([t.view(full=False) for t in api.registry.list()[:limit]])

    @app.get("/tasks/<task_id>")
    def task_detail(task_id: str):
        task = api.registry.get(task_id)
        if task is None:
            return jsonify(error="unknown task", id=task_id), 404
        return jsonify(task.view())

    @app.get("/tasks/<task_id>/log")
    def task_log(task_id: str):
        task = api.registry.get(task_id)
        if task is None:
            return jsonify(error="unknown task", id=task_id), 404
        return Response(read_tail(task.log_path, 65536),
                        mimetype="text/plain; charset=utf-8")

    @app.get("/tasks/<task_id>/artifacts")
    def task_artifacts(task_id: str):
        task = api.registry.get(task_id)
        if task is None:
            return jsonify(error="unknown task", id=task_id), 404
        return jsonify(list_artifacts(task))

    @app.get("/tasks/<task_id>/artifacts/<path:rel>")
    def task_artifact(task_id: str, rel: str):
        task = api.registry.get(task_id)
        if task is None:
            return jsonify(error="unknown task", id=task_id), 404
        base = task.export_dir.resolve()
        target = (base / rel).resolve()
        if not target.is_relative_to(base) or not target.is_file():
            return jsonify(error="artifact not found"), 404
        ctype = {
            ".json": "application/json",
            ".html": "text/html; charset=utf-8",
            ".htm": "text/html; charset=utf-8",
            ".txt": "text/plain; charset=utf-8",
            ".log": "text/plain; charset=utf-8",
            ".csv": "text/plain; charset=utf-8",
        }.get(target.suffix.lower(), "application/octet-stream")
        return send_file(target, mimetype=ctype, as_attachment=True,
                         download_name=target.name)

    # -- POST /analyze ------------------------------------------------------
    @app.post("/analyze")
    def analyze():
        blocked = rate("analyze:" + client_ip(), api.args.rate_limit,
                       api.args.rate_window)
        if blocked is not None:
            return blocked

        pipeline = request.args.get("pipeline", "default")
        wait = request.args.get("wait", "false").lower() in ("1", "true", "yes")
        filename = request.args.get("filename")

        if request.content_length is None and not request.headers.get("Transfer-Encoding"):
            return jsonify(error="Content-Length required"), 411
        if (request.content_length or 0) > MAX_UPLOAD + 64 * 1024:
            return jsonify(error="sample too large", max_bytes=MAX_UPLOAD,
                           received_bytes=request.content_length), 413

        # Order matters: get_data() drains the input stream, so calling it first
        # leaves request.files empty and every multipart upload 400s with "no
        # file part in multipart body". Parse the form first; only fall back to
        # the raw body when this is not a multipart request.
        multipart = "multipart/form-data" in (request.content_type or "")
        if multipart:
            part = request.files.get("file")
            if part is None and request.files:
                part = next(iter(request.files.values()))
            if part is None:
                return jsonify(error="no file part in multipart body"), 400
            data = part.read()
            filename = filename or part.filename
            if "wait" not in request.args and request.form.get("wait"):
                wait = request.form["wait"].lower() in ("1", "true", "yes")
            if "pipeline" not in request.args and request.form.get("pipeline"):
                pipeline = request.form["pipeline"]
        else:
            data = request.get_data(cache=False)  # 413 via MAX_CONTENT_LENGTH
        filename = filename or request.headers.get("X-Filename") or "sample.bin"

        if not data:
            return jsonify(error="empty body"), 400
        if len(data) > MAX_UPLOAD:  # belt and braces (raw bodies)
            return jsonify(error="sample too large", max_bytes=MAX_UPLOAD), 413

        code, payload = api.submit(data, filename, pipeline, wait)
        resp = jsonify(payload)
        resp.status_code = code
        if code == 202:
            resp.headers["Location"] = f"/tasks/{payload['task']['id']}"
        return resp

    # -- DELETE -------------------------------------------------------------
    @app.delete("/tasks/<task_id>")
    def task_delete(task_id: str):
        task = api.registry.get(task_id)
        if task is None:
            return jsonify(error="unknown task", id=task_id), 404
        was_running = api.cancel(task)
        purge_task(task)
        api.registry.remove(task.id)
        return jsonify(removed=True, cancelled=was_running)

    return app


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
def scan_pipelines(analyzer: Path) -> list[dict]:
    out = [{"name": "default",
            "description": "Complete static analysis (classic 26-phase order)",
            "source": "builtin"}]
    seen = {"default"}
    roots = [REPO / "pipelines", analyzer.parent / "pipelines"]
    for root in roots:
        if not root.is_dir():
            continue
        for file in sorted(root.iterdir()):
            if file.suffix.lower() not in (".yaml", ".yml", ".json"):
                continue
            name = file.stem
            description = "(no description)"
            try:
                if file.suffix.lower() == ".json":
                    doc = json.loads(file.read_text(encoding="utf-8"))
                    name = str(doc.get("name", name))
                    description = str(doc.get("description") or description)
                else:
                    text = file.read_text(encoding="utf-8")
                    m = re.search(r"^name:\s*(.+)$", text, re.M)
                    if m:
                        name = m.group(1).strip().strip("\"'")
                    m = re.search(r"^description:\s*(.+)$", text, re.M)
                    if m:
                        description = m.group(1).strip().strip("\"'")
            except Exception as exc:  # noqa: BLE001 - list it, mark it broken
                description = f"unreadable: {exc}"
            if name in seen:
                continue
            seen.add(name)
            out.append({"name": name, "description": description,
                        "source": str(file)})
    return out


def sanitize_filename(name: str) -> str:
    base = os.path.basename(name.replace("\\", "/")).strip()
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base).lstrip(".")
    if not base or base in (".", ".."):
        base = "sample.bin"
    return base[:120]


def spawn_kwargs() -> dict:
    """On Windows give the analyzer its own process group so a Ctrl+C aimed at
    this console does not reach it: the drain phase must decide when it dies
    (kill_tree uses taskkill, which ignores process groups)."""
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {}


def kill_tree(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10,
            )
        else:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
    except Exception:  # noqa: BLE001 - best effort
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass


def load_manifest(task: Task) -> Optional[dict]:
    path = task.export_dir / "run_summary.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 - absent on config errors
        return None


def failure_reason(task: Task) -> str:
    tail = read_tail(task.log_path) or ""
    for line in reversed(tail.splitlines()):
        line = line.strip()
        if not line or line.startswith("[trace]"):
            continue
        if "pipeline error" in line:
            return line
        if "Result:" in line:
            return "analysis failed (see log)"
    return "analysis failed (see log)"


def read_tail(path: Optional[Path], limit: int = 8192) -> str:
    if path is None or not path.is_file():
        return ""
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        fh.seek(max(0, size - limit))
        return fh.read().decode("utf-8", errors="replace")


def purge_task(task: Task) -> None:
    shutil.rmtree(task.dir, ignore_errors=True)
    shutil.rmtree(task.export_dir, ignore_errors=True)


def list_artifacts(task: Task) -> list[dict]:
    base = task.export_dir
    if not base.is_dir():
        return []
    out = []
    for path in sorted(base.rglob("*")):
        if path.is_file():
            stat = path.stat()
            out.append({
                "path": path.relative_to(base).as_posix(),
                "bytes": stat.st_size,
                "download": f"/tasks/{task.id}/artifacts/"
                            + path.relative_to(base).as_posix(),
            })
    return out


def _env(name: str, default: str = "") -> str:
    """Process env, then the repository `.env`, then the default.

    The panel already resolves settings this way (see panel/config.setting),
    and this function is the other half of that contract - the panel's own
    docstring says "same precedence as server.py", which was aspirational until
    now.

    It mattered: the repository `.env` sets SA_API_PORT=60025, so the panel
    dialled 60025 while this server bound its own hardcoded default of 60020.
    Every phase-catalog read came back WinError 10061 and the Analysis
    Configuration page reported "analyzer offline" against a server that was
    running perfectly well three lines above it in the same terminal. Two
    numbers that disagree look exactly like a dead service.

    Only fills in a name that is not already in the environment, so an explicit
    export still wins and nothing here can override the operator's shell.
    """
    if name in os.environ:
        return os.environ[name]
    try:
        raw = (REPO / ".env").read_text(encoding="utf-8-sig")
    except OSError:
        return default
    prefix = name + "="
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith(prefix):
            return stripped[len(prefix):].strip().strip("\"'")
    return default


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Flask REST API around the static analyzer")
    p.add_argument("--host", default=_env("SA_API_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(_env("SA_API_PORT", "60020")))
    p.add_argument("--analyzer",
                   default=_env("SA_ANALYZER") or str(
                       REPO / "build-ucrt" / "static_analyzer.exe"))
    p.add_argument("--max-workers", type=int,
                   default=int(_env("SA_MAX_WORKERS", "2")),
                   help="concurrent analyses (default 2)")
    p.add_argument("--max-queued", type=int, default=8,
                   help="queued tasks accepted beyond the workers before 503")
    p.add_argument("--rate-limit", type=int, default=10,
                   help="POST /analyze per client per minute (0 disables)")
    p.add_argument("--rate-window", type=float, default=60.0)
    p.add_argument("--read-limit", type=int, default=300,
                   help="requests of any other kind per client per minute")
    p.add_argument("--timeout", type=float, default=900.0,
                   help="seconds a single analysis may run")
    p.add_argument("--wait-timeout", type=float, default=600.0,
                   help="seconds a ?wait=true request may block")
    p.add_argument("--shutdown-timeout", type=float, default=30.0,
                   help="seconds to let running analyses finish on SIGINT/SIGTERM")
    p.add_argument("--retention", type=int, default=86400,
                   help="seconds to keep finished tasks (0 = forever)")
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logging.getLogger("werkzeug").setLevel(
        logging.DEBUG if args.verbose else logging.WARNING)

    api = Api(args)
    if not api.analyzer.is_file():
        alt = shutil.which("static_analyzer")
        if alt:
            api.analyzer = Path(alt)
        else:
            log.error("analyzer not found: %s (build it or pass --analyzer)",
                      args.analyzer)
            return 1
    api.warm_caches()

    try:
        server = make_server(args.host, args.port, create_app(api), threaded=True)
    except OSError as exc:
        log.error("could not bind %s:%d: %s", args.host, args.port, exc)
        return 1

    # Signal handling: flip the flag first so in-flight/new requests get 503,
    # keep the listener alive while running analyses drain, and only stop
    # serve_forever() once the drain deadline passed. Cleanup stays on the
    # main thread after the loop returns.
    def on_signal(signum: int, _frame: Any) -> None:
        if api.shutdown_event.is_set():
            return
        log.info("signal %d: draining (max %.0fs), refusing new work...",
                 signum, args.shutdown_timeout)
        api.shutdown_event.set()

        def drain_then_stop() -> None:
            api.drain(args.shutdown_timeout)
            server.shutdown()

        threading.Thread(target=drain_then_stop, daemon=True).start()

    for sig in (signal.SIGINT, signal.SIGTERM, getattr(signal, "SIGBREAK", None)):
        if sig is not None:
            try:
                signal.signal(sig, on_signal)
            except (ValueError, OSError):  # non-main thread / unsupported
                pass

    threading.Thread(target=api.retention_loop, daemon=True).start()
    log.info("listening on http://%s:%d (analyzer=%s, workers=%d, rate=%d/min, "
             "max upload=%d MB)",
             args.host, args.port, api.analyzer, args.max_workers,
             args.rate_limit, MAX_UPLOAD // (1024 * 1024))
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:  # handler replaced; safety net only
            api.shutdown_event.set()

    log.info("shutting down...")
    api.stop(args.shutdown_timeout)
    server.server_close()
    log.info("bye")
    return 0


if __name__ == "__main__":
    sys.exit(main())
