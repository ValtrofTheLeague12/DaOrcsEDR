#!/usr/bin/env python3
"""Flask REST API around the static analyzer.

Runs the analyzer as a service: clients upload a sample, pick a pipeline and
get back a task they can poll (or block on).

    python\\.venv\\Scripts\\python.exe server.py                 # 127.0.0.1:60020
    python\\.venv\\Scripts\\python.exe server.py --port 7000 --rate-limit 20

Endpoints (JSON in, JSON out):

    GET    /                                service index
    GET    /health                          liveness + queue stats
    GET    /phases                          analyzer --list-phases --json
    GET    /pipelines                       named pipeline configs
    GET    /capabilities                    granular capability endpoints
    POST   /capabilities/<name>             run ONE capability, JSON inline
             (aliases: /hashes /strings /ioc /iat /malapi /sections /got
              /capa /disasm /graphs /extraction /model /cti)
    POST   /analyze?pipeline=<spec>         full pipeline -> 202 + task id
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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from queue import PriorityQueue, Empty

try:
    from flask import Flask, Response, jsonify, request, send_file
    from werkzeug.exceptions import HTTPException, RequestEntityTooLarge
    from werkzeug.serving import make_server
except ImportError:  # pragma: no cover - friendly bootstrap
    sys.exit("Flask is required. Run me with the repo venv:\n"
             "    python\\.venv\\Scripts\\python.exe server.py\n"
             "or: pip install flask")

try:
    from loguru import logger
except ImportError:
    logger = None

REPO = Path(__file__).resolve().parent
MAX_UPLOAD = 10 * 1024 * 1024  # 10 MB, per spec
MAX_INLINE = 5 * 1024 * 1024   # max bytes of artifact JSON returned inline
UCRT64_BIN = r"C:\msys64\ucrt64\bin"

# Granular capabilities: endpoint -> (phases to run, artifact path filter).
# Each runs ONLY its own phase(s) (export/summary are auto-inserted by the
# planner) and returns the produced artifact JSON inline - no task queue.
CAPABILITIES: dict[str, tuple[list[str], tuple[str, ...]]] = {
    "hashes":    (["export"], ("hash/", "fileinfo/")),
    "strings":   (["strings"], ("strings/",)),
    "ioc":       (["strings"], ("ioc/",)),
    "iat":       (["iat"], ("iat/",)),
    "malapi":    (["iat"], ("malapi/",)),
    "sections":  (["sections"], ("eat/",)),
    "got":       (["got"], ("got/",)),
    "capa":      (["capa"], ("capa/",)),
    "disasm":    (["radare2"], ("radare2/",)),
    "graphs":    (["graphs"], ("graphs.json",)),
    "extraction": (["extraction"], ("extraction/",)),
    "model":     (["model"], ("ml/",)),
    "cti":       (["cti"], ("cti/",)),
}

CAPABILITY_DOCS = {
    "hashes": "SHA-256/MD5/SHA1 + file info",
    "strings": "extracted strings + CyberChef decode pass",
    "ioc": "IOC mining: IPs, domains, URLs",
    "iat": "PE import address table",
    "malapi": "MalAPI classification of imported functions",
    "sections": "PE section table + export address table",
    "got": "ELF/Mach-O GOT/PLT entries",
    "capa": "capa capability detection (network, persistence, anti-analysis)",
    "disasm": "radare2 disassembly and function analysis",
    "graphs": "Graphviz call graphs from radare2",
    "extraction": "full LIEF extraction: sections, exports, imports, YARA",
    "model": "EMBER2024 LightGBM score (needs ML service on :60010)",
    "cti": "CTI enrichment of IOCs (needs network)",
}

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

# Priority levels for the queue (lower = higher priority)
PRIORITY_HIGH = 0
PRIORITY_NORMAL = 1
PRIORITY_LOW = 2


class Task:
    def __init__(
        self,
        task_id: str,
        pipeline: str,
        filename: str,
        stored: str,
        priority: int = PRIORITY_NORMAL,
    ) -> None:
        self.id = task_id
        self.pipeline = pipeline
        self.filename = filename          # original name as uploaded
        self.stored = stored              # on-disk name (task-id prefixed, unique)
        self.state = QUEUED
        self.priority = priority
        self.queue_position: int = 0      # position in queue (1-based)
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
            "priority": self.priority,
            "queue_position": self.queue_position if self.state == QUEUED else None,
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

    def __lt__(self, other: "Task") -> bool:
        # For PriorityQueue: lower priority value = higher priority
        if self.priority != other.priority:
            return self.priority < other.priority
        return self.submitted < other.submitted


class TaskQueue:
    """Thread-safe priority queue for tasks with position tracking."""

    def __init__(self, max_queued: int, max_workers: int) -> None:
        self._lock = threading.Lock()
        self._queue: PriorityQueue = PriorityQueue()
        self._tasks: dict[str, Task] = {}  # All tasks by ID
        self._max_queued = max_queued
        self._max_workers = max_workers
        self._running_count = 0

    def can_accept(self) -> bool:
        with self._lock:
            queued = self._queue.qsize()
            return (queued + self._running_count) < (self._max_queued + self._max_workers)

    def enqueue(self, task: Task) -> int:
        """Add task to queue, return queue position (1-based)."""
        with self._lock:
            self._tasks[task.id] = task
            self._queue.put(task)
            self._update_positions()
            return task.queue_position

    def dequeue(self) -> Optional[Task]:
        """Get next task from queue."""
        with self._lock:
            try:
                task = self._queue.get_nowait()
                self._running_count += 1
                task.state = RUNNING
                task.started = utcnow()
                task.queue_position = 0
                self._update_positions()
                return task
            except Empty:
                return None

    def mark_done(self, task_id: str) -> None:
        """Mark task as done (called when task finishes)."""
        with self._lock:
            self._running_count = max(0, self._running_count - 1)
            if task_id in self._tasks:
                task = self._tasks[task_id]
                task.queue_position = 0

    def get_task(self, task_id: str) -> Optional[Task]:
        with self._lock:
            return self._tasks.get(task_id)

    def get(self, task_id: str) -> Optional[Task]:
        return self.get_task(task_id)

    def remove_task(self, task_id: str) -> Optional[Task]:
        with self._lock:
            task = self._tasks.pop(task_id, None)
            if task and task.state == QUEUED:
                # Rebuild queue without this task
                self._rebuild_queue()
            return task

    def remove(self, task_id: str) -> Optional[Task]:
        return self.remove_task(task_id)

    def _rebuild_queue(self) -> None:
        """Rebuild priority queue from remaining queued tasks."""
        queued_tasks = [t for t in self._tasks.values() if t.state == QUEUED]
        self._queue = PriorityQueue()
        for t in sorted(queued_tasks):
            self._queue.put(t)
        self._update_positions()

    def _update_positions(self) -> None:
        """Update queue positions for all queued tasks."""
        # Get all queued tasks sorted by priority and submission time
        queued = sorted([t for t in self._tasks.values() if t.state == QUEUED])
        for pos, task in enumerate(queued, 1):
            task.queue_position = pos

    def list_tasks(self, reverse: bool = True) -> list[Task]:
        with self._lock:
            tasks = list(self._tasks.values())
            tasks.sort(key=lambda t: t.submitted, reverse=reverse)
            return tasks

    def list(self, reverse: bool = True) -> list[Task]:
        """Alias for list_tasks for backward compatibility."""
        return self.list_tasks(reverse)

    def counts(self) -> dict[str, int]:
        with self._lock:
            c = {QUEUED: 0, RUNNING: 0}
            for t in self._tasks.values():
                if t.state in (QUEUED, RUNNING):
                    c[t.state] = c.get(t.state, 0) + 1
            return c

    def running_tasks(self) -> list[Task]:
        with self._lock:
            return [t for t in self._tasks.values() if t.state == RUNNING]

    def queued_tasks(self) -> list[Task]:
        with self._lock:
            return sorted([t for t in self._tasks.values() if t.state == QUEUED])

    def cancel_queued(self) -> None:
        with self._lock:
            for task in self._tasks.values():
                if task.state == QUEUED:
                    task.state = CANCELLED
                    task.finished = utcnow()
                    task.queue_position = 0
            self._queue = PriorityQueue()

    def queue_status(self) -> dict:
        """Get detailed queue status."""
        with self._lock:
            queued = [t for t in self._tasks.values() if t.state == QUEUED]
            running = [t for t in self._tasks.values() if t.state == RUNNING]
            return {
                "queued": len(queued),
                "running": len(running),
                "max_queued": self._max_queued,
                "max_workers": self._max_workers,
                "can_accept": (len(queued) + len(running)) < (self._max_queued + self._max_workers),
                "queue": [
                    {
                        "id": t.id,
                        "filename": t.filename,
                        "pipeline": t.pipeline,
                        "priority": t.priority,
                        "position": t.queue_position,
                        "submitted": t.submitted,
                    }
                    for t in sorted(queued)
                ],
                "running_tasks": [
                    {
                        "id": t.id,
                        "filename": t.filename,
                        "pipeline": t.pipeline,
                        "started": t.started,
                    }
                    for t in running
                ],
            }


# ---------------------------------------------------------------------------
# Server core
# ---------------------------------------------------------------------------
class Api:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.analyzer = Path(args.analyzer).resolve()
        self.registry = TaskQueue(args.max_queued, args.max_workers)
        self.limiter = RateLimiter()
        self.shutdown_event = threading.Event()
        self._workers_stop = threading.Event()
        self._workers = [
            threading.Thread(
                target=self._worker_loop,
                name=f"analyze-{index + 1}",
                daemon=True,
            )
            for index in range(args.max_workers)
        ]
        for worker in self._workers:
            worker.start()
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
               wait: bool, priority: int = PRIORITY_NORMAL) -> tuple[int, dict]:
        """Persist the upload and schedule it. Returns (http_code, body)."""
        if not self.registry.can_accept():
            return 503, {"error": "task queue is full, retry later"}

        task_id = uuid.uuid4().hex[:12]
        safe = sanitize_filename(filename)
        # Task-id prefix keeps the analyzer stem unique, so concurrent uploads
        # of the same file never share exports/<stem>_analysis/.
        stored = f"{task_id}_{safe}"
        task = Task(task_id, pipeline, filename, stored, priority=priority)
        task.dir.mkdir(parents=True, exist_ok=True)
        (task.dir / stored).write_bytes(data)
        
        position = self.registry.enqueue(task)
        
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

    def _worker_loop(self) -> None:
        while not self._workers_stop.is_set():
            task = self.registry.dequeue()
            if task is None:
                self._workers_stop.wait(0.1)
                continue
            self._run(task)

    def _run(self, task: Task) -> None:
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
                with self.registry._lock:  # noqa: SLF001
                    task.proc = proc
                    cancel_requested = task.cancel_requested
                if cancel_requested:
                    kill_tree(proc)
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
            with self.registry._lock:  # noqa: SLF001
                task.proc = None
            task.finished = utcnow()
            self.registry.mark_done(task.id)

    def run_capability(self, name: str, data: bytes, filename: str,
                       timeout: Optional[float] = None) -> tuple[int, dict]:
        """Run a single capability inline (no task queue) and return its
        artifact JSON directly."""
        phases, keep = CAPABILITIES[name]
        task_id = uuid.uuid4().hex[:12]
        safe = sanitize_filename(filename)
        stored = f"{task_id}_{safe}"
        task = Task(task_id, name, filename, stored)
        task.dir.mkdir(parents=True, exist_ok=True)
        (task.dir / stored).write_bytes(data)
        task.log_path = task.dir / "analyzer.log"

        spec = json.dumps(phases)  # planner: inline JSON phase list
        args = [str(self.analyzer), "--pipeline", spec, str(task.dir / stored)]
        started = time.monotonic()
        try:
            with open(task.log_path, "wb") as logf:
                proc = subprocess.Popen(
                    args, cwd=str(REPO), env=self.child_env(),
                    stdout=logf, stderr=subprocess.STDOUT,
                    **spawn_kwargs(),
                )
                task.proc = proc
                try:
                    rc = proc.wait(timeout=timeout or self.args.timeout)
                except subprocess.TimeoutExpired:
                    kill_tree(proc)
                    task.state = ERROR
                    task.error = f"analysis exceeded {timeout or self.args.timeout}s"
                else:
                    task.exit_code = rc
                    task.state = DONE if rc == 0 else FAILED
                    if rc != 0:
                        task.error = failure_reason(task)
        except OSError as exc:
            task.state = ERROR
            task.error = f"could not start the analyzer: {exc}"
        finally:
            task.proc = None
            task.finished = utcnow()

        body: dict[str, Any] = {
            "capability": name,
            "phases": phases,
            "state": task.state,
            "exit_code": task.exit_code,
            "error": task.error,
            "filename": filename,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "artifacts": inline_artifacts(task, keep),
        }
        code = 200 if task.state == DONE else (
            504 if task.state == ERROR and task.error and "exceeded" in task.error
            else 502)
        purge_task(task)
        return code, body

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
        for task in self.registry.running_tasks():
            self.cancel(task)

    def stop_workers(self) -> None:
        self._workers_stop.set()
        self.registry.cancel_queued()
        for worker in self._workers:
            worker.join(timeout=5)

    def stop(self, grace: float) -> None:
        """Stop accepting, let running analyses finish, kill the stragglers."""
        self._retention_stop.set()
        self.drain(grace)
        self.stop_workers()


# ---------------------------------------------------------------------------
# Flask application
# ---------------------------------------------------------------------------
def create_app(api: Api) -> Flask:
    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD + 64 * 1024  # multipart overhead

    # OpenAPI for the analyzer, so the admin panel documents this service from
    # the live app rather than by parsing this file. Assets come from flasgger's
    # own static directory, not a CDN, so it works on an isolated network.
    #
    # `headers` must be an empty list - flasgger iterates it in an
    # after_request hook on every response, and a missing key 500s every route.
    # The spec and UI are exempt from the rate limiter below: they start no
    # analysis, upload nothing, and a throttled spec is just a broken page.
    try:
        from flasgger import Swagger

        Swagger(app, config={
            "title": "Static analyzer API",
            "version": "1.0",
            "description": (
                "REST wrapper around the static analyzer. Upload a sample, "
                "pick a pipeline, poll the task, download the artifacts."
            ),
            "headers": [],
            "specs": [{
                "endpoint": "apispec_1",
                "route": "/apispec_1.json",
                "rule_filter": lambda rule: True,
                "model_filter": lambda tag: True,
            }],
            "swagger_ui": True,
            "specs_route": "/apidocs/",
            "static_url_path": "/flasgger_static",
        })
    except ImportError:  # pragma: no cover - optional dependency
        pass

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
        if api.shutdown_event.is_set() and request.method == "POST":
            return jsonify(error="server is shutting down"), 503
        # Documentation is free to read: it starts no analysis, uploads nothing
        # and exposes no sample data. Throttling it would only make the panel's
        # documentation page fail under the same load that caused the throttle.
        if request.path in ("/apidocs/", "/apispec_1.json") or \
                request.path.startswith("/flasgger_static/"):
            return None
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
    @app.get("/api")
    def index():
        """Service index: version, endpoints, pipelines and capabilities
        ---
        tags: [meta]
        responses:
          200:
            description: What this service offers
        """
        return jsonify(
            service="static-analyzer-api",
            version="0.2.0",
            endpoints=["/health", "/phases", "/pipelines", "/capabilities",
                       "/analyze", "/tasks"],
            max_upload_bytes=MAX_UPLOAD,
            pipelines=[p["name"] for p in api.pipelines],
            capabilities=sorted(CAPABILITIES),
        )

    @app.get("/health")
    def health():
        """Liveness plus queue depth and rate-limit state
        ---
        tags: [meta]
        responses:
          200:
            description: Status, analyzer path, queued and running counts
        """
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
        """Analyzer phase catalog as JSON
        ---
        tags: [meta]
        responses:
          200:
            description: Every phase the analyzer knows about
          503:
            description: Catalog was not available at startup
        """
        if api.phases is None:
            return jsonify(error="phase catalog unavailable"), 503
        return jsonify(api.phases)

    @app.get("/pipelines")
    def pipelines():
        """Named pipeline configs discovered on disk
        ---
        tags: [meta]
        responses:
          200:
            description: Pipeline name, description and source path
        """
        return jsonify(api.pipelines)

    @app.get("/tasks")
    def task_list():
        """List analysis tasks, newest first
        ---
        tags: [tasks]
        parameters:
          - name: limit
            in: query
            required: false
            type: integer
            description: Maximum number of tasks to return
        responses:
          200:
            description: Task summaries without manifests
        """
        limit = request.args.get("limit", 100, type=int)
        return jsonify([t.view(full=False) for t in api.registry.list_tasks()[:limit]])

    @app.get("/queue")
    def queue_status():
        """Queue depth, positions and running tasks
        ---
        tags: [tasks]
        responses:
          200:
            description: Queue state, including whether it can accept work
        """
        return jsonify(api.registry.queue_status())

    @app.get("/tasks/<task_id>")
    def task_detail(task_id: str):
        """Task detail, with the manifest once it has finished
        ---
        tags: [tasks]
        parameters:
          - name: task_id
            in: path
            required: true
            type: string
            description: Task handle from POST /analyze
        responses:
          200:
            description: Task state and, when terminal, its manifest
          404:
            description: Unknown task id
        """
        task = api.registry.get(task_id)
        if task is None:
            return jsonify(error="unknown task", id=task_id), 404
        return jsonify(task.view())

    @app.get("/tasks/<task_id>/log")
    def task_log(task_id: str):
        """Tail of the analyzer's stdout and stderr for a task
        ---
        tags: [tasks]
        parameters:
          - name: task_id
            in: path
            required: true
            type: string
            description: Task handle from POST /analyze
        responses:
          200:
            description: Last 64 KB of the run log, as plain text
          404:
            description: Unknown task id
        """
        task = api.registry.get(task_id)
        if task is None:
            return jsonify(error="unknown task", id=task_id), 404
        return Response(read_tail(task.log_path, 65536),
                        mimetype="text/plain; charset=utf-8")

    @app.get("/tasks/<task_id>/artifacts")
    def task_artifacts(task_id: str):
        """List the artifact files a run produced
        ---
        tags: [tasks]
        parameters:
          - name: task_id
            in: path
            required: true
            type: string
            description: Task handle from POST /analyze
        responses:
          200:
            description: File list with sizes and download links
          404:
            description: Unknown task id
        """
        task = api.registry.get(task_id)
        if task is None:
            return jsonify(error="unknown task", id=task_id), 404
        return jsonify(list_artifacts(task))

    @app.get("/tasks/<task_id>/artifacts/<path:rel>")
    def task_artifact(task_id: str, rel: str):
        """Download one artifact from a run
        ---
        tags: [tasks]
        parameters:
          - name: task_id
            in: path
            required: true
            type: string
            description: Task handle from POST /analyze
          - name: rel
            in: path
            required: true
            type: string
            description: Artifact path, relative to the run root
        responses:
          200:
            description: The file, as an attachment
          404:
            description: Unknown task, or the path escapes the run directory
        """
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

    # -- upload parsing (shared by /analyze and capability endpoints) ------
    def read_upload() -> tuple[Optional[tuple[bytes, str, dict]], Optional[tuple[dict, int]]]:
        """Returns ((data, filename, form_fields), None) or (None, (error, code)).

        Multipart must go through request.files FIRST - get_data() would
        consume the stream before werkzeug can parse the parts."""
        if request.content_length is None and not request.headers.get("Transfer-Encoding"):
            return None, ({"error": "Content-Length required"}, 411)
        if (request.content_length or 0) > MAX_UPLOAD + 64 * 1024:
            return None, ({"error": "sample too large", "max_bytes": MAX_UPLOAD,
                           "received_bytes": request.content_length}, 413)

        multipart = "multipart/form-data" in (request.content_type or "")
        filename = request.args.get("filename")
        form: dict[str, str] = {}
        if multipart:
            part = request.files.get("file")
            if part is None and request.files:
                part = next(iter(request.files.values()))
            if part is None:
                return None, ({"error": "no file part in multipart body"}, 400)
            data = part.read()
            filename = filename or part.filename
            form = request.form.to_dict()
        else:
            # raw body: fields arrive as query params (reading request.form
            # here would try to parse the binary stream)
            data = request.get_data(cache=False)  # 413 via MAX_CONTENT_LENGTH

        filename = filename or request.headers.get("X-Filename") or "sample.bin"
        if not data:
            return None, ({"error": "empty body"}, 400)
        if len(data) > MAX_UPLOAD:  # belt and braces (raw bodies)
            return None, ({"error": "sample too large", "max_bytes": MAX_UPLOAD}, 413)
        return (data, filename, form), None

    # -- granular capabilities ---------------------------------------------
    @app.get("/capabilities")
    def capability_index():
        """Index of granular capability endpoints
        ---
        tags: [capabilities]
        responses:
          200:
            description: One entry per capability, with its phases and aliases
        description: >
          Each capability runs a single phase and returns its artifact JSON
          inline, without going through the task queue. Useful when you want one
          specific artifact and do not want to run a whole pipeline.
        """
        return jsonify([
            {"name": name, "description": CAPABILITY_DOCS.get(name, ""),
             "phases": phases, "endpoint": f"/capabilities/{name}",
             "alias": f"/{name}"}
            for name, (phases, _) in sorted(CAPABILITIES.items())
        ])

    def run_capability_route(name: str):
        if name not in CAPABILITIES:
            return jsonify(error="unknown capability", capability=name,
                           available=sorted(CAPABILITIES)), 404
        blocked = rate("analyze:" + client_ip(), api.args.rate_limit,
                       api.args.rate_window)
        if blocked is not None:
            return blocked
        upload, err = read_upload()
        if err is not None:
            return jsonify(err[0]), err[1]
        data, filename, _form = upload
        try:
            timeout = request.args.get("timeout", type=float)
        except (TypeError, ValueError):
            timeout = None
        code, body = api.run_capability(name, data, filename, timeout)
        return jsonify(body), code

    @app.post("/capabilities/<name>")
    def capability_post(name: str):
        """Run one capability and return its artifact JSON inline
        ---
        tags: [capabilities]
        parameters:
          - name: name
            in: path
            required: true
            type: string
            description: Capability name, e.g. hashes, capa, disasm
          - name: body
            in: body
            required: true
            description: Raw sample bytes, or a multipart form with a file part
          - name: timeout
            in: query
            required: false
            type: number
            description: Seconds to allow before the run is killed
        responses:
          200:
            description: Artifact JSON produced by the capability
          400:
            description: Empty body, or no file part in a multipart request
          413:
            description: Sample exceeds the 10 MB limit
          502:
            description: The analyzer failed or timed out
        description: >
          Aliases exist for every capability - POST /strings is the same as
          POST /capabilities/strings. No task queue is involved: the run is
          synchronous and the artifact comes back in the response body.
        """
        return run_capability_route(name)

    # short aliases: POST /strings, POST /hashes, ...
    for _cap in CAPABILITIES:
        app.add_url_rule(f"/{_cap}", f"cap_{_cap}",
                         (lambda c: lambda: run_capability_route(c))(_cap),
                         methods=["POST"])

    # -- POST /analyze ------------------------------------------------------
    @app.post("/analyze")
    def analyze():
        """Run a full pipeline over an uploaded sample
        ---
        tags: [analysis]
        parameters:
          - name: body
            in: body
            required: true
            description: Raw sample bytes, or a multipart form with a file part
          - name: pipeline
            in: query
            required: false
            type: string
            description: Pipeline name, or an inline JSON list of phase tags
          - name: wait
            in: query
            required: false
            type: boolean
            description: Block until the run finishes instead of returning 202
          - name: priority
            in: query
            required: false
            type: integer
            description: 0 high, 1 normal, 2 low
          - name: filename
            in: query
            required: false
            type: string
            description: Override the stored filename
        responses:
          200:
            description: Finished, when wait=true
          202:
            description: Queued; poll the task at the Location header
          400:
            description: Empty body
          409:
            description: Cancelled while wait=true
          413:
            description: Sample exceeds the 10 MB limit
          429:
            description: Rate limited
          502:
            description: The analyzer failed
          504:
            description: Timed out
        """
        blocked = rate("analyze:" + client_ip(), api.args.rate_limit,
                       api.args.rate_window)
        if blocked is not None:
            return blocked

        pipeline = request.args.get("pipeline", "default")
        wait = request.args.get("wait", "false").lower() in ("1", "true", "yes")
        priority = request.args.get("priority", type=int, default=PRIORITY_NORMAL)

        upload, err = read_upload()
        if err is not None:
            return jsonify(err[0]), err[1]
        data, filename, form = upload
        if "wait" not in request.args and form.get("wait"):
            wait = form["wait"].lower() in ("1", "true", "yes")
        if "pipeline" not in request.args and form.get("pipeline"):
            pipeline = form["pipeline"]
        if "priority" not in request.args and form.get("priority"):
            try:
                priority = int(form["priority"])
            except (TypeError, ValueError):
                pass

        code, payload = api.submit(data, filename, pipeline, wait, priority)
        resp = jsonify(payload)
        resp.status_code = code
        if code == 202:
            resp.headers["Location"] = f"/tasks/{payload['task']['id']}"
        return resp

    # -- DELETE -------------------------------------------------------------
    @app.delete("/tasks/<task_id>")
    def task_delete(task_id: str):
        """Cancel a running task, then purge it
        ---
        tags: [tasks]
        parameters:
          - name: task_id
            in: path
            required: true
            type: string
            description: Task handle from POST /analyze
        responses:
          200:
            description: removed, plus whether it was cancelled
          404:
            description: Unknown task id
        """
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


def inline_artifacts(task: Task, keep: tuple[str, ...]) -> dict[str, Any]:
    """Read the run's produced JSON files whose path matches `keep` and return
    {relpath: parsed-json} (raw text when not valid JSON)."""
    out: dict[str, Any] = {}
    base = task.export_dir
    if not base.is_dir():
        return out
    budget = MAX_INLINE
    for path in sorted(base.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(base).as_posix()
        if keep and not any(f in rel for f in keep):
            continue
        size = path.stat().st_size
        if size > budget:
            out[rel] = {"truncated": True, "bytes": size}
            continue
        budget -= size
        text = path.read_text(encoding="utf-8", errors="replace")
        try:
            out[rel] = json.loads(text)
        except ValueError:
            out[rel] = text
    return out


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


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    def server_setting(name: str, default: str) -> str:
        if name in os.environ:
            return os.environ[name]
        env_file = REPO / ".env"
        if env_file.is_file():
            for line in env_file.read_text(encoding="utf-8-sig").splitlines():
                entry = line.strip()
                if entry and not entry.startswith("#") and "=" in entry:
                    key, value = entry.split("=", 1)
                    if key.strip() == name:
                        return value.strip().strip("\"'")
        return default

    p = argparse.ArgumentParser(description="Flask REST API around the static analyzer")
    p.add_argument("--host", default=server_setting("SA_API_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(server_setting("SA_API_PORT", "60020")))
    p.add_argument("--analyzer",
                   default=os.environ.get("SA_ANALYZER") or str(
                       REPO / "build-ucrt" / "static_analyzer.exe"))
    p.add_argument("--max-workers", type=int,
                   default=int(os.environ.get("SA_MAX_WORKERS", "2")),
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


def setup_logging(verbose: bool) -> None:
    """Configure loguru for structured logging."""
    if logger is None:
        # Fallback to stdlib logging if loguru not available
        logging.basicConfig(
            level=logging.DEBUG if verbose else logging.INFO,
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        )
        logging.getLogger("werkzeug").setLevel(
            logging.DEBUG if verbose else logging.WARNING)
        return

    logger.remove()  # Remove default handler
    log_level = "DEBUG" if verbose else "INFO"
    
    # Console output with colors
    logger.add(
        sys.stderr,
        level=log_level,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
               "<level>{level: <8}</level> | "
               "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
               "<level>{message}</level>",
        colorize=True,
    )
    
    # File logging with rotation
    log_dir = REPO / "logs"
    log_dir.mkdir(exist_ok=True)
    logger.add(
        log_dir / "server_{time:YYYY-MM-DD}.log",
        level=log_level,
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
        rotation="1 day",
        retention="7 days",
        compression="zip",
    )
    
    # Reduce werkzeug noise
    logging.getLogger("werkzeug").setLevel(
        logging.DEBUG if verbose else logging.WARNING)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    setup_logging(args.verbose)
    
    if logger:
        log = logger.bind(name="analyzer.api")
    else:
        log = logging.getLogger("analyzer.api")

    api = Api(args)
    if not api.analyzer.is_file():
        alt = shutil.which("static_analyzer")
        if alt:
            api.analyzer = Path(alt)
        else:
            log.error("analyzer not found: %s (build it or pass --analyzer)", args.analyzer)
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
        log.info("signal %d: draining (max %.0fs), refusing new work...", signum, args.shutdown_timeout)
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
    print(f"Starting server on {args.host}:{args.port}", flush=True)
    log.info("listening on http://{}:{} (analyzer={}, workers={}, rate={}/min, max upload={} MB)",
             args.host, args.port, api.analyzer, args.max_workers, args.rate_limit, MAX_UPLOAD // (1024 * 1024))
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
    raise SystemExit(main())
