import io
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server


class CompletedProcess:
    def wait(self, timeout=None):
        return 0

    def poll(self):
        return 0


class ServerQueueTests(unittest.TestCase):
    def setUp(self):
        args = server.parse_args([
            "--analyzer", "queue-test-analyzer.exe",
            "--max-workers", "1",
            "--retention", "0",
        ])
        self.api = server.Api(args)
        self.client = server.create_app(self.api).test_client()

    def tearDown(self):
        self.api.stop(1)

    def test_uploaded_executable_runs_as_queued_task(self):
        fixture = Path(__file__).parent / "fixtures" / "suspicious_sample.exe"
        sample = fixture.read_bytes()
        launched = []

        def launch(args, **_kwargs):
            launched.append(args)
            return CompletedProcess()

        with patch.object(server.subprocess, "Popen", side_effect=launch):
            response = self.client.post(
                "/analyze?pipeline=queue-smoke",
                data={"file": (io.BytesIO(sample), fixture.name)},
                content_type="multipart/form-data",
            )
            self.assertEqual(response.status_code, 202, response.get_json())
            task_id = response.get_json()["task"]["id"]

            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                task = self.client.get(f"/tasks/{task_id}").get_json()
                if task["state"] in server.TERMINAL:
                    break
                time.sleep(0.02)

        self.assertEqual(task["state"], server.DONE, task)
        self.assertEqual(len(launched), 1)
        self.assertEqual(launched[0][2], "queue-smoke")
        self.assertEqual(Path(launched[0][-1]).read_bytes(), sample)

        deleted = self.client.delete(f"/tasks/{task_id}")
        self.assertEqual(deleted.status_code, 200, deleted.get_json())

    def test_drain_kills_running_processes(self):
        """drain() kills what is still running, and only that.

        Rewritten against the current registry: enqueue/dequeue/mark_done are
        gone, tasks are added with add() and looked up with running(). drain()
        also does not set cancel_requested - that belongs to cancel() - so the
        contract worth pinning is which tasks get killed.
        """
        # Real Popen-shaped stubs, not bare objects: tearDown calls api.stop(), which
        # drains again with the *unpatched* kill_tree, and that calls poll().
        killed = CompletedProcess()
        not_started = CompletedProcess()

        running_with_proc = server.Task("d1", "quick", "a.exe", "d1_a.exe")
        running_with_proc.state = server.RUNNING
        running_with_proc.proc = killed

        # Still RUNNING but between spawn and handle capture: drain must
        # tolerate this rather than calling kill_tree(None).
        running_without_proc = server.Task("d2", "quick", "b.exe", "d2_b.exe")
        running_without_proc.state = server.RUNNING
        running_without_proc.proc = None

        still_queued = server.Task("d3", "quick", "c.exe", "d3_c.exe")
        still_queued.state = server.QUEUED
        still_queued.proc = not_started

        for task in (running_with_proc, running_without_proc, still_queued):
            self.api.registry.add(task)

        with patch.object(server, "kill_tree") as kill:
            self.api.drain(0)   # grace 0: skip the wait, go straight to killing

        # Exactly the running task that actually holds a process: not the one
        # with no proc yet, and not the queued one that has not spawned.
        kill.assert_called_once_with(killed)

    def test_shutdown_rejects_every_route(self):
        """Once shutdown is signalled the gate answers 503 before any route runs.

        The old test expected /health to stay readable at 200 with a
        "shutting_down" status. The gate is now a blanket before_request, so
        health checks get a 503 too - which is what a load balancer wants. This
        asserts the behaviour that shipped rather than the one that was planned.
        """
        self.api.shutdown_event.set()

        for method, path, kwargs in (
            ("get", "/health", {}),
            ("post", "/analyze", {"data": b"test binary",
                                  "content_type": "application/octet-stream",
                                  "headers": {"X-Filename": "sample.exe"}}),
            ("get", "/tasks", {}),
        ):
            with self.subTest(path=path):
                response = getattr(self.client, method)(path, **kwargs)
                self.assertEqual(response.status_code, 503, response.get_json())
                self.assertEqual(response.get_json()["error"], "server is shutting down")

        # ...and critically, no work was accepted on the way past.
        self.assertEqual(self.api.registry.counts()[server.QUEUED], 0)
        self.assertEqual(self.api.registry.counts()[server.RUNNING], 0)
        self.assertEqual(self.api.registry.list(), [])

    def test_server_address_defaults_load_from_dotenv(self):
        with tempfile.TemporaryDirectory() as temp:
            Path(temp, ".env").write_text(
                "SA_API_HOST=0.0.0.0\nSA_API_PORT=61234\n", encoding="utf-8"
            )
            with patch.object(server, "REPO", Path(temp)), patch.dict(os.environ, {}, clear=True):
                args = server.parse_args([])

        self.assertEqual(args.host, "0.0.0.0")
        self.assertEqual(args.port, 61234)


if __name__ == "__main__":
    unittest.main()
