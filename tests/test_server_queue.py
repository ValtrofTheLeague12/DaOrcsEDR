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
        task = server.Task("drain-test", "quick", "sample.exe", "drain-test_sample.exe")
        self.api.registry.enqueue(task)
        self.assertIs(self.api.registry.dequeue(), task)
        process = object()
        task.proc = process

        with patch.object(server, "kill_tree") as kill:
            self.api.drain(0)

        self.assertTrue(task.cancel_requested)
        kill.assert_called_once_with(process)
        task.proc = None
        task.state = server.CANCELLED
        task.finished = server.utcnow()
        self.api.registry.mark_done(task.id)

    def test_shutdown_keeps_status_readable_but_rejects_new_work(self):
        self.api.shutdown_event.set()

        health = self.client.get("/health")
        self.assertEqual(health.status_code, 200, health.get_json())
        self.assertEqual(health.get_json()["status"], "shutting_down")

        response = self.client.post(
            "/analyze",
            data=b"test binary",
            content_type="application/octet-stream",
            headers={"X-Filename": "sample.exe"},
        )
        self.assertEqual(response.status_code, 503, response.get_json())
        self.assertEqual(self.api.registry.counts()[server.QUEUED], 0)

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
