"""clamd.py submission - the ClamAV panel's one action with side effects.

Three things are pinned here, because all three are places a panel like this
usually lies:

  * the transport a form offers is the transport that can actually run (a
    missing script or Python module is a refusal, not a button that fails after
    the upload);
  * a TCP scan really speaks clamd's INSTREAM framing and writes a result
    document the Results tab can read - proved against a fake clamd on
    localhost, not against the live VM;
  * the guard against two concurrent scans is check-and-set inside one lock,
    so two submissions cannot both win.

The SFTP path is not exercised end to end: it spawns SSH into a VM, and a test
that needs one is not a unit test. Its argv/result-collection contract is the
script's own, and the fake-clamd test covers the other half.
"""

from __future__ import annotations

import io
import json
import re
import socket
import struct
import sys
import threading
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))

from panel.clamd import clamd  # noqa: E402


# ---------------------------------------------------------------------------
# A fake clamd: accept one connection, read INSTREAM frames, answer.
# ---------------------------------------------------------------------------

def _fake_clamd(reply: bytes = b"stream: Eicar-Test-Signature FOUND\0"):
    """Start a one-shot clamd on an ephemeral port; return (port, holder)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    holder: dict = {"payload": b"", "error": None}

    def serve():
        try:
            conn, _ = srv.accept()
            conn.settimeout(5)
            with conn:
                # The command word, then [len][chunk]... [0].
                cmd = b""
                while not cmd.endswith(b"\0"):
                    part = conn.recv(1)
                    if not part:
                        return
                    cmd += part
                holder["command"] = cmd
                body = b""
                while True:
                    raw = conn.recv(4)
                    if len(raw) < 4:
                        return
                    size = struct.unpack(">I", raw)[0]
                    if size == 0:
                        break
                    chunk = b""
                    while len(chunk) < size:
                        part = conn.recv(size - len(chunk))
                        if not part:
                            return
                        chunk += part
                    body += chunk
                holder["payload"] = body
                conn.sendall(reply)
        except Exception as exc:  # noqa: BLE001 - surfaced in the assertion
            holder["error"] = exc
        finally:
            srv.close()

    threading.Thread(target=serve, daemon=True, name="fake-clamd").start()
    return port, holder


def _fake_pingd(version: bytes = b"ClamAV 1.4.3/27400/Tue Oct 27 06:00:00 2026"):
    """Start a one-shot clamd that answers PING and VERSION; return (port, holder)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    holder: dict = {"commands": [], "error": None}

    def serve():
        try:
            conn, _ = srv.accept()
            conn.settimeout(5)
            with conn:
                buf = b""
                while len(holder["commands"]) < 2:
                    part = conn.recv(1)
                    if not part:
                        return
                    buf += part
                    if not buf.endswith(b"\0"):
                        continue
                    command = buf[:-1].decode("utf-8", "replace")
                    buf = b""
                    holder["commands"].append(command)
                    if command == "zPING":
                        conn.sendall(b"PONG\0")
                    elif command == "zVERSION":
                        conn.sendall(version + b"\0")
                    else:
                        conn.sendall(b"UNKNOWN COMMAND\0")
        except Exception as exc:  # noqa: BLE001 - surfaced in the assertion
            holder["error"] = exc
        finally:
            srv.close()

    threading.Thread(target=serve, daemon=True, name="fake-pingd").start()
    return port, holder


def _wait(job_id: str, seconds: float = 10.0) -> dict:
    deadline = time.time() + seconds
    while time.time() < deadline:
        with clamd._jobs_lock:
            job = clamd._jobs.get(job_id)
        if job and job["state"] != "running":
            return job
        time.sleep(0.02)
    raise AssertionError(f"job {job_id} did not finish")


@pytest.fixture()
def results_dir(tmp_path, monkeypatch):
    """Keep result documents out of the repo's python/clamd/results/."""
    path = tmp_path / "results"
    monkeypatch.setattr(clamd, "RESULTS_DIR", path)
    return path


# The operator's socket_validator.py is untracked code that lives in the working
# tree and is theirs to change - and at the time of writing it was 0 bytes. The
# panel's tests must not depend on the state of that file, so they run against a
# stand-in with the same three calls and the same shape of narration. What is
# under test is the panel's half of the contract, not the client's implementation.
CLIENT_STUB = '''\
"""Stand-in for panel/utils/socket_validator.py - see the test module."""

import socket


class SocketValidator:
    def __init__(self, ip: str):
        print("Checking if the ip is valid")
        print("IPs of network adapter: 127.0.0.1")
        print("IPs of network adapter: 10.0.0.4")
        self.ip = ip

    def establish_tcp_connection(self, port: int):
        sock = socket.create_connection((self.ip, port), timeout=3)
        print("\\x1b[32mConnection to TCP Server has been established\\x1b[0m")
        return sock

    def closeConnection(self, sock) -> None:
        sock.close()
        print("Connection closed")
'''


@pytest.fixture(autouse=True)
def client_stub(tmp_path, monkeypatch):
    """A deterministic socket client for every test that touches TCP."""
    path = tmp_path / "socket_validator.py"
    path.write_text(CLIENT_STUB, encoding="utf-8")
    monkeypatch.setattr(clamd, "SOCKET_VALIDATOR", path)
    return path


@pytest.fixture(autouse=True)
def select(monkeypatch):
    """Pin the transport that config/dynamic_analysis.json would report.

    The real file is part of the working tree, so a test must not depend on the
    value it happens to hold today: every test states the selection it is
    exercising, and `select("tcp")` moves the same fixture.
    """
    def _select(mode: str) -> None:
        monkeypatch.setattr(clamd.dynamic_analysis, "load",
                            lambda repo: {"communication": mode})
    _select("sftp")
    return _select


@pytest.fixture(autouse=True)
def no_stray_guard():
    """No test may inherit a running-scan guard from another."""
    clamd._submit_running = None
    yield
    clamd._submit_running = None


class TestTransports:
    def test_both_transports_are_described(self):
        ways = clamd.transports()
        assert set(ways) == {"sftp", "tcp"}
        for way in ways.values():
            assert set(way) >= {"id", "available", "reason", "detail", "files"}
            assert isinstance(way["available"], bool)
            if not way["available"]:
                assert way["reason"]

    def test_status_carries_the_selected_transport_and_its_source(self):
        got = clamd.status()
        assert set(got["transports"]) == {"sftp", "tcp"}
        assert got["communication"]["mode"] == "sftp"
        assert got["communication"]["path"] == "config/dynamic_analysis.json"
        assert got["communication"]["error"] is None
        assert got["default_transport"] == "sftp"

    def test_sftp_names_every_driver_file_it_needs(self):
        sftp = clamd.transports()["sftp"]
        names = [Path(p).name for p in sftp["files"]]
        assert names == ["scan_remote.py", "clamd-python.py", "vm_info.json"]
        assert sftp["path"].endswith("scan_remote.py")

    def test_tcp_names_the_operator_socket_client(self):
        tcp = clamd.transports()["tcp"]
        assert Path(tcp["path"]).name == "socket_validator.py"


class TestStatusByTransport:
    """One selected transport, one set of checks - never a blended list."""

    def test_sftp_checks_the_clamd_scripts(self):
        got = clamd.status()
        names = [c["name"] for c in got["checks"]]
        assert names == ["scan_remote.py", "clamd-python.py", "vm_info.json",
                         "paramiko installed", "VM target"]
        assert all(c["ok"] for c in got["checks"]
                   if c["name"] != "VM target" and not c["advisory"])
        assert got["endpoint"].startswith("ssh://")

    def test_sftp_reports_a_missing_script_by_name(self, monkeypatch, tmp_path):
        monkeypatch.setattr(clamd, "SCAN_REMOTE", tmp_path / "scan_remote.py")
        got = clamd.status()
        row = next(c for c in got["checks"] if c["name"] == "scan_remote.py")
        assert row["ok"] is False
        assert "scan_remote.py" in row["detail"]
        assert got["ready"] is False
        assert got["ok"] is False

    def test_the_status_carries_a_connection_test_output(self):
        got = clamd.status()
        output = got["output"]
        assert output[0].startswith("$ clamd connection test - sftp")
        assert any(line.startswith("[ok  ] scan_remote.py") for line in output)
        assert output[-1] == "--- ready"
        assert got["checked_at"] > 0

    def test_a_failed_check_marks_the_output_not_ready(self, monkeypatch, tmp_path):
        monkeypatch.setattr(clamd, "SCAN_REMOTE", tmp_path / "scan_remote.py")
        output = clamd.status()["output"]
        assert any(line.startswith("[FAIL] scan_remote.py") for line in output)
        assert output[-1] == "--- not ready"

    def test_tcp_uses_the_socket_validator_and_asks_clamd(self, select, monkeypatch):
        select("tcp")
        port, holder = _fake_pingd()
        monkeypatch.setattr(clamd, "_tcp_target", lambda: ("127.0.0.1", port))

        got = clamd.status()
        names = [c["name"] for c in got["checks"]]
        assert names == ["socket_validator.py", "ifaddr installed",
                         "colorama installed", "clamd target",
                         "socket client loads", "connect", "PING -> PONG"]
        assert got["ready"] is True
        assert got["reachable"] is True
        assert got["version"].startswith("ClamAV")
        assert holder["commands"] == ["zPING", "zVERSION"]
        assert got["endpoint"] == f"tcp://127.0.0.1:{port}"

        # The connection test's output keeps the client's own narration, so the
        # page can show what the operator's script actually did.
        output = got["output"]
        assert any("Checking if the ip is valid" in ln for ln in output)
        assert any("Connection to TCP Server has been established" in ln
                   for ln in output)
        assert any(ln.startswith("[ok  ] PING -> PONG") for ln in output)
        assert output[-1] == "--- ready"
        assert not any("\x1b[" in ln for ln in output)
        # The client enumerates every adapter to prove the IP is local; that is
        # folded into one line so the connect result is not buried.
        assert not any("IPs of network adapter" in ln for ln in output)
        assert any("interface lines omitted" in ln for ln in output)

    def test_tcp_with_nothing_listening_is_not_ready(self, select, monkeypatch):
        select("tcp")
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        monkeypatch.setattr(clamd, "_tcp_target", lambda: ("127.0.0.1", port))

        got = clamd.status()
        assert got["ready"] is False
        assert got["reachable"] is False
        connect = next(c for c in got["checks"] if c["name"] == "connect")
        assert connect["ok"] is False

    def test_a_malformed_config_is_an_error_not_a_guess(self, monkeypatch):
        def boom(repo):
            raise ValueError("'communication' must be one of: tcp, sftp")
        monkeypatch.setattr(clamd.dynamic_analysis, "load", boom)

        comm = clamd._communication()
        assert comm["error"] and "communication" in comm["error"]
        refused = clamd.start_submit("x.exe", io.BytesIO(b"MZ"), None)
        assert refused["ok"] is False
        assert refused["code"] == "config-error"


class TestStatusTranscript:
    """The connection test narrates itself, one announced step at a time.

    A flat list of outcomes cannot say which line belongs to which check, and
    the page shows this text as the evidence. Every step therefore prints its
    intent (`[n/total] ...`) immediately before its own result row, and the
    count in the header is the number of steps actually run.
    """

    STEP = re.compile(r"^\[(\d+)/(\d+)\] (.+)$")
    RESULT = re.compile(r"^\[(ok  |info|FAIL)\] (.+?): (.*)$")

    @classmethod
    def _steps(cls, output):
        """[(echo, result)] for each announced step, in order."""
        pairs = []
        for i, line in enumerate(output):
            if cls.STEP.match(line):
                pairs.append((line, output[i + 1]))
        return pairs

    def test_every_step_is_announced_before_its_result(self):
        got = clamd.status()
        pairs = self._steps(got["output"])
        assert len(pairs) == len(got["checks"])
        for (echo, result), check in zip(pairs, got["checks"]):
            assert self.RESULT.match(result), result
            assert check["name"] in result
            assert check["echo"] in echo

    def test_the_steps_are_numbered_one_to_total(self):
        output = clamd.status()["output"]
        numbers = [int(m.group(1)) for m in map(self.STEP.match, output) if m]
        totals = {int(m.group(2)) for m in map(self.STEP.match, output) if m}
        assert numbers == list(range(1, len(numbers) + 1))
        assert totals == {len(numbers)}

    def test_the_header_counts_the_steps(self):
        output = clamd.status()["output"]
        assert any(re.match(r"^  \d+ steps - ", ln) for ln in output)

    def test_a_failed_step_still_announces_itself(self, monkeypatch, tmp_path):
        monkeypatch.setattr(clamd, "SCAN_REMOTE", tmp_path / "scan_remote.py")
        output = clamd.status()["output"]
        pairs = self._steps(output)
        echo, result = pairs[0]
        assert "locating the host-side" in echo
        assert result.startswith("[FAIL] scan_remote.py")
        assert output[-1] == "--- not ready"

    def test_tcp_announces_each_step_then_prints_the_client_trace(self, select,
                                                                 monkeypatch):
        select("tcp")
        port, _ = _fake_pingd()
        monkeypatch.setattr(clamd, "_tcp_target", lambda: ("127.0.0.1", port))
        got = clamd.status()
        output = got["output"]

        pairs = self._steps(output)
        assert len(pairs) == len(got["checks"])
        assert "asking clamd for PING and VERSION" in pairs[-1][0]
        assert pairs[-1][1].startswith("[ok  ] PING -> PONG")

        # The client's own narration belongs after the steps it belongs to,
        # never between an announcement and its result.
        trace_at = output.index("  socket_validator.py said:")
        last_result = max(output.index(result) for _, result in pairs)
        assert trace_at > last_result

    def test_each_transport_has_an_intent_for_every_check(self, select, monkeypatch):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        closed = probe.getsockname()[1]
        probe.close()
        monkeypatch.setattr(clamd, "_tcp_target", lambda: ("127.0.0.1", closed))

        select("sftp")
        sftp = clamd.status()["checks"]
        select("tcp")
        tcp = clamd.status()["checks"]
        for check in sftp + tcp:
            assert check["echo"].strip()
            # The echo is a sentence about the step, not the label repeated.
            assert check["echo"] != check["name"]


class TestSocketClientContract:
    """A client file that imports but defines nothing is unavailable, not a 500.

    This is not hypothetical: the operator's socket_validator.py was truncated
    to zero bytes, and an empty module imports cleanly and then has no
    SocketValidator. The status page has to say so.
    """

    def test_an_empty_client_file_is_reported_as_empty(self, select, tmp_path,
                                                       monkeypatch):
        select("tcp")
        empty = tmp_path / "socket_validator.py"
        empty.write_text("", encoding="utf-8")
        monkeypatch.setattr(clamd, "SOCKET_VALIDATOR", empty)

        got = clamd.status()
        assert got["ready"] is False
        # It must not be advertised as a working transport either.
        assert got["transports"]["tcp"]["available"] is False
        assert "empty" in got["transports"]["tcp"]["reason"]
        row = next(c for c in got["checks"] if c["name"] == "socket_validator.py")
        assert row["ok"] is False
        assert "empty" in row["detail"]

    def test_a_client_without_the_class_is_a_transport_refusal(self, tmp_path,
                                                               monkeypatch):
        wrong = tmp_path / "socket_validator.py"
        wrong.write_text("class SomethingElse:\n    pass\n", encoding="utf-8")
        monkeypatch.setattr(clamd, "SOCKET_VALIDATOR", wrong)

        with pytest.raises(clamd.SubmitError) as info:
            clamd._socket_validator()
        assert info.value.code == "transport-unavailable"
        assert "SocketValidator" in str(info.value)

    def test_status_reports_a_wrong_client_as_not_ready(self, select, tmp_path,
                                                        monkeypatch):
        select("tcp")
        wrong = tmp_path / "socket_validator.py"
        wrong.write_text("class SomethingElse:\n    pass\n", encoding="utf-8")
        monkeypatch.setattr(clamd, "SOCKET_VALIDATOR", wrong)

        got = clamd.status()
        assert got["ready"] is False
        row = next(c for c in got["checks"] if c["name"] == "socket client loads")
        assert row["ok"] is False
        assert "SocketValidator" in row["detail"]

    def test_the_adapter_enumeration_folds_into_one_line(self):
        trace = [
            "Checking if the ip is valid",
            "IPs of network adapter: Wi-Fi",
            "Given IP Adrress is found within host only network: Wi-Fi",
            "IPs of network adapter: Ethernet",
            "Given IP Adrress is found within host only network: Ethernet",
            "Connection to TCP Server has been established",
        ]
        folded = clamd._condense_trace(trace)
        assert folded == [
            "Checking if the ip is valid",
            "… 4 interface lines omitted (the client checks every adapter)",
            "Connection to TCP Server has been established",
        ]


class TestInstreamReply:
    @pytest.mark.parametrize("reply,status,signature", [
        (b"stream: Win.Test.EICAR_HDB-1 FOUND\0", "FOUND", "Win.Test.EICAR_HDB-1"),
        (b"stream: OK\0", "OK", ""),
        (b"stream: OK\n", "OK", ""),
    ])
    def test_parses_a_verdict(self, reply, status, signature):
        got_status, got_signature, _ = clamd._parse_instream(reply)
        assert (got_status, got_signature) == (status, signature)

    def test_size_limit_is_an_error_with_the_sentence_kept(self):
        status, _, detail = clamd._parse_instream(
            b"INSTREAM size limit exceeded. ERROR\0")
        assert status == "ERROR"
        assert "size limit exceeded" in detail

    def test_an_empty_reply_is_an_error_not_a_clean_scan(self):
        status, _, detail = clamd._parse_instream(b"")
        assert status == "ERROR"
        assert "without a reply" in detail

    def test_an_unknown_reply_never_reads_as_clean(self):
        status, _, detail = clamd._parse_instream(b"banana\0")
        assert status == "ERROR"
        assert detail == "banana"


class TestStaging:
    def _file(self, name="sample.exe", body=b"MZ" + b"\0" * 100):
        class _Upload(io.BytesIO):
            filename = name
        return _Upload(body)

    def test_name_is_reduced_to_a_basename(self, tmp_path):
        staged = clamd._stage_upload("..\\..\\evil.exe", self._file())
        try:
            assert staged["name"] == "evil.exe"
            assert staged["path"].parent != tmp_path
            assert staged["path"].name == "evil.exe"
        finally:
            clamd.shutil.rmtree(staged["folder"], ignore_errors=True)

    def test_it_hashes_what_it_wrote(self):
        import hashlib
        body = b"MZ" + b"\1" * 64
        staged = clamd._stage_upload("x.exe", self._file(body=body))
        try:
            assert staged["sha256"] == hashlib.sha256(body).hexdigest()
            assert staged["bytes"] == len(body)
        finally:
            clamd.shutil.rmtree(staged["folder"], ignore_errors=True)

    def test_an_empty_upload_is_refused(self):
        with pytest.raises(clamd.SubmitError) as exc:
            clamd._stage_upload("x.exe", self._file(body=b""))
        assert exc.value.code == "empty"

    def test_the_cap_is_enforced_while_writing(self, monkeypatch):
        monkeypatch.setattr(clamd, "SUBMIT_MAX_BYTES", 32)
        with pytest.raises(clamd.SubmitError) as exc:
            clamd._stage_upload("big.exe", self._file(body=b"M" * 64))
        assert exc.value.code == "too-large"

    def test_no_usable_name_is_refused(self):
        with pytest.raises(clamd.SubmitError) as exc:
            clamd._stage_upload("..", self._file())
        assert exc.value.code == "bad-name"


class TestStartSubmitRefusals:
    def _file(self, body=b"MZ"):
        class _Upload(io.BytesIO):
            filename = "x.exe"
        return _Upload(body)

    def test_a_mode_that_disagrees_with_the_config_is_refused(self):
        got = clamd.start_submit("x.exe", self._file(), "carrier-pigeon")
        assert got["ok"] is False
        assert got["code"] == "mode-locked"
        assert "dynamic_analysis.json" in got["error"]

    def test_an_unavailable_transport_is_refused_with_its_reason(self, monkeypatch):
        monkeypatch.setattr(clamd, "SCAN_REMOTE", Path("no-such-scan_remote.py"))
        got = clamd.start_submit("x.exe", self._file(), "sftp")
        assert got["ok"] is False
        assert got["code"] == "transport-unavailable"
        assert "scan_remote.py" in got["error"]


class TestTcpScan:
    def test_instream_roundtrip_writes_a_result_document(self, results_dir, select,
                                                        monkeypatch):
        select("tcp")
        port, holder = _fake_clamd()
        monkeypatch.setattr(clamd, "_tcp_target", lambda: ("127.0.0.1", port))

        body = b"MZ" + b"\2" * 128
        # No mode argument: the transport comes from the config, which the
        # fixture pinned to tcp above.
        got = clamd.start_submit("eicar.exe", io.BytesIO(body))
        assert got["ok"] is True, got
        assert got["mode"] == "tcp"

        job = _wait(got["job_id"])
        assert holder["error"] is None
        assert holder["command"] == b"zINSTREAM\0"
        assert holder["payload"] == body, "INSTREAM framing lost the sample"

        assert job["state"] == "passed"
        row = job["results"][0]
        assert row["verdict"] == "infected"
        assert row["signature"] == "Eicar-Test-Signature"

        saved = json.loads(Path(row["result_file"]).read_text(encoding="utf-8"))
        assert saved["verdict"] == "infected"
        assert saved["status"] == "FOUND"
        assert saved["endpoint"] == f"tcp:127.0.0.1:{port}"
        assert len(saved["sha256"]) == 64

        # The same document the Results tab reads must recognise it.
        entry = clamd._result_entry(Path(row["result_file"]))
        assert entry["verdict"] == "infected"
        assert entry["signature"] == "Eicar-Test-Signature"

        # The socket client's own narration is in the log, ANSI stripped.
        assert any("SocketValidator" in ln or "socket" in ln for ln in job["log"])
        assert not any("\x1b[" in ln for ln in job["log"])

    def test_a_clean_reply_is_clean(self, results_dir, select, monkeypatch):
        select("tcp")
        port, _ = _fake_clamd(reply=b"stream: OK\0")
        monkeypatch.setattr(clamd, "_tcp_target", lambda: ("127.0.0.1", port))
        got = clamd.start_submit("clean.exe", io.BytesIO(b"MZclean"), "tcp")
        job = _wait(got["job_id"])
        assert job["state"] == "passed"
        assert job["results"][0]["verdict"] == "clean"

    def test_a_refused_connection_fails_without_a_result_file(self, results_dir,
                                                             select, monkeypatch):
        select("tcp")
        # A port nothing is listening on: reserve one, then close it.
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        monkeypatch.setattr(clamd, "_tcp_target", lambda: ("127.0.0.1", port))
        got = clamd.start_submit("x.exe", io.BytesIO(b"MZ"))
        job = _wait(got["job_id"])
        assert job["state"] == "failed"
        assert job["results"][0]["state"] == "failed"
        assert not results_dir.exists() or not list(results_dir.glob("*.json"))


class TestCurrentAndGuard:
    def test_current_submit_returns_the_last_clamd_job(self, results_dir, select,
                                                       monkeypatch):
        select("tcp")
        port, _ = _fake_clamd(reply=b"stream: OK\0")
        monkeypatch.setattr(clamd, "_tcp_target", lambda: ("127.0.0.1", port))
        got = clamd.start_submit("x.exe", io.BytesIO(b"MZ"))
        _wait(got["job_id"])
        current = clamd.current_submit()
        assert current is not None
        assert current["id"] == got["job_id"]
        assert current["kind"] == "clamd"

    def test_a_second_scan_is_refused_while_one_holds_the_guard(self, select):
        select("tcp")
        clamd._submit_running = "c-held"
        got = clamd.start_submit("x.exe", io.BytesIO(b"MZ"))
        assert got["ok"] is False
        assert got["job_id"] == "c-held"
        assert "already" in got["error"]


class TestResultDocument:
    """The document behind a verdict: returned verbatim, names strictly bare."""

    @pytest.fixture()
    def client(self, tmp_path, monkeypatch):
        monkeypatch.setattr(clamd, "RESULTS_DIR", tmp_path / "results")
        from panel.app import create_app
        return create_app().test_client()

    @pytest.fixture(autouse=True)
    def seeded(self, results_dir):
        results_dir.mkdir(parents=True, exist_ok=True)
        (results_dir / "sample_20260101_000000_aaaaaa.json").write_text(
            '{"verdict": "infected", "signature": "Eicar-Test-Signature"}',
            encoding="utf-8")
        return results_dir

    def test_reads_the_document_verbatim(self):
        got = clamd.result_document("sample_20260101_000000_aaaaaa.json")
        assert got["name"] == "sample_20260101_000000_aaaaaa.json"
        assert got["bytes"] == len(got["raw"])
        assert json.loads(got["raw"])["verdict"] == "infected"

    @pytest.mark.parametrize("name", [
        "../secret.json", "sub/other.json", "..", "", "notes.txt",
        "sample.json.bak", "C:\\temp\\x.json",
    ])
    def test_refuses_anything_that_is_not_a_bare_json_name(self, name):
        with pytest.raises(clamd.SubmitError) as info:
            clamd.result_document(name)
        assert info.value.code == "bad-name"

    def test_a_name_it_cannot_find_is_not_found(self):
        with pytest.raises(clamd.SubmitError) as info:
            clamd.result_document("absent.json")
        assert info.value.code == "not-found"

    def test_a_zero_byte_document_is_returned_not_hidden(self, results_dir):
        (results_dir / "interrupted.json").write_text("", encoding="utf-8")
        got = clamd.result_document("interrupted.json")
        assert got["raw"] == ""
        assert got["bytes"] == 0

    def test_the_route_returns_the_bytes(self, client):
        res = client.get("/api/clamd/results/sample_20260101_000000_aaaaaa.json")
        assert res.status_code == 200
        body = res.get_json()
        assert body["name"] == "sample_20260101_000000_aaaaaa.json"
        assert json.loads(body["raw"])["signature"] == "Eicar-Test-Signature"

    def test_the_route_maps_refusals_to_400_and_404(self, client):
        bad = client.get("/api/clamd/results/notes.txt")
        assert bad.status_code == 400
        assert bad.get_json()["code"] == "bad-name"
        missing = client.get("/api/clamd/results/absent.json")
        assert missing.status_code == 404
        assert missing.get_json()["code"] == "not-found"


class TestSubmitEndpoint:
    """The route is the unit: it owns the multipart form and the status codes."""

    @pytest.fixture()
    def client(self, tmp_path, monkeypatch):
        monkeypatch.setattr(clamd, "RESULTS_DIR", tmp_path / "results")
        from panel.app import create_app
        return create_app().test_client()

    def test_an_upload_starts_a_job_the_build_endpoint_can_follow(self, client,
                                                                 select, monkeypatch):
        select("tcp")
        port, holder = _fake_clamd(reply=b"stream: OK\0")
        monkeypatch.setattr(clamd, "_tcp_target", lambda: ("127.0.0.1", port))
        # No `mode` field: the route reads the transport from the config.
        res = client.post(
            "/api/clamd/submit",
            data={"file": (io.BytesIO(b"MZ from flask"), "route.exe")},
            content_type="multipart/form-data")
        assert res.status_code == 202, res.get_data(as_text=True)
        body = res.get_json()
        assert body["ok"] is True
        assert body["mode"] == "tcp"

        job = _wait(body["job_id"])
        assert job["state"] == "passed"
        assert holder["payload"] == b"MZ from flask"

        followed = client.get(f"/api/build/{body['job_id']}").get_json()
        assert followed["kind"] == "clamd"
        assert followed["results"][0]["verdict"] == "clean"

        current = client.get("/api/clamd/submit").get_json()
        assert current["id"] == body["job_id"]

    def test_a_mode_that_disagrees_with_the_config_is_a_400(self, client):
        res = client.post(
            "/api/clamd/submit",
            data={"mode": "carrier-pigeon",
                  "file": (io.BytesIO(b"MZ"), "x.exe")},
            content_type="multipart/form-data")
        assert res.status_code == 400
        assert res.get_json()["code"] == "mode-locked"

    def test_an_unreadable_config_is_a_400_not_a_scan(self, client, monkeypatch):
        def boom(repo):
            raise ValueError("config/dynamic_analysis.json is not valid JSON")
        monkeypatch.setattr(clamd.dynamic_analysis, "load", boom)
        res = client.post(
            "/api/clamd/submit",
            data={"file": (io.BytesIO(b"MZ"), "x.exe")},
            content_type="multipart/form-data")
        assert res.status_code == 400
        assert res.get_json()["code"] == "config-error"

    def test_no_file_is_a_400_and_says_what_to_send(self, client):
        res = client.post("/api/clamd/submit", data={},
                          content_type="multipart/form-data")
        assert res.status_code == 400
        body = res.get_json()
        assert body["code"] == "no-file"
        assert "multipart" in body["error"]

    def test_an_oversized_upload_is_a_413(self, client, monkeypatch):
        monkeypatch.setattr(clamd, "SUBMIT_MAX_BYTES", 8)
        res = client.post(
            "/api/clamd/submit",
            data={"file": (io.BytesIO(b"M" * 64), "big.exe")},
            content_type="multipart/form-data")
        assert res.status_code == 413
        assert res.get_json()["code"] == "too-large"

