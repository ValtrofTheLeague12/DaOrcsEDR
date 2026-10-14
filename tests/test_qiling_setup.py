import io
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "admin-terminal"))
import core
import qiling_setup
import vms


def make_rootfs(root: Path) -> None:
    for arch in ("x86_windows", "x8664_windows"):
        windows = root / "examples" / "rootfs" / arch / "Windows"
        system32 = windows / "System32"
        registry = windows / "registry"
        system32.mkdir(parents=True)
        registry.mkdir()
        (system32 / "kernel32.dll").write_bytes(b"kernel")
        (system32 / "ntdll.dll").write_bytes(b"ntdll")
        (registry / "SYSTEM").write_bytes(b"hive")


class QilingSetupTests(unittest.TestCase):
    def test_default_analysis_vm_configuration(self):
        # vms.json is machine-local and may override the defaults; the defaults
        # themselves live in vms.DEFAULT_VMS.
        config = vms.DEFAULT_VMS["qiling"]
        self.assertEqual(config["host"], "192.168.56.105")
        self.assertEqual(config["port"], 22)
        self.assertEqual(config["known_hosts_file"], "~/.ssh/known_hosts")
        self.assertEqual(config["remote_dir"], "qiling_dlls")

    def test_known_hosts_path_defaults_to_current_user(self):
        expected = Path.home() / ".ssh" / "known_hosts"
        self.assertEqual(Path(core.known_hosts_path("")), expected)
        self.assertEqual(Path(core.known_hosts_path("~/.ssh/known_hosts")),
                         expected)
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(core, "REPO", directory):
                self.assertEqual(Path(core.known_hosts_path("legacy/known")),
                                 Path(directory) / "legacy" / "known")

    def test_rootfs_check_requires_core_files_for_both_architectures(self):
        with tempfile.TemporaryDirectory() as directory:
            qiling_dir = Path(directory) / "qiling_dlls"
            make_rootfs(qiling_dir)
            with patch.object(qiling_setup, "ROOTFS",
                              qiling_dir / "examples" / "rootfs"):
                self.assertTrue(qiling_setup.rootfs_exists())
                (qiling_dir / "examples" / "rootfs" / "x86_windows"
                 / "Windows" / "System32" / "kernel32.dll").unlink()
                self.assertFalse(qiling_setup.rootfs_exists())

    def test_setup_packages_rootfs_without_elevation_when_present(self):
        with tempfile.TemporaryDirectory() as directory:
            qiling_dir = Path(directory) / "qiling_dlls"
            make_rootfs(qiling_dir)
            archive = qiling_dir / "rootfs.tar.gz"
            with patch.object(qiling_setup, "QILING_DIR", qiling_dir), \
                    patch.object(qiling_setup, "ROOTFS",
                                 qiling_dir / "examples" / "rootfs"), \
                    patch.object(qiling_setup, "ARCHIVE", archive), \
                    patch.object(qiling_setup, "_run_elevated_collector") as run:
                qiling_setup.setup_rootfs()
                self.assertTrue(archive.is_file())
                run.assert_not_called()

    def test_collector_uses_an_elevated_cmd_prompt(self):
        with tempfile.TemporaryDirectory() as directory:
            collector = Path(directory) / "dll_collector.bat"
            collector.write_text("@echo off\n", encoding="utf-8")
            with patch.object(qiling_setup, "COLLECTOR", collector), \
                    patch.object(qiling_setup, "QILING_DIR",
                                 Path(directory)), \
                    patch.object(qiling_setup.subprocess, "run",
                                 return_value=Mock(returncode=0)) as run, \
                    patch.object(qiling_setup, "rootfs_exists",
                                 return_value=True):
                qiling_setup._run_elevated_collector()
            arguments = run.call_args.args[0]
            self.assertIn("-Command", arguments)
            script = arguments[-1]
            self.assertIn("-Verb RunAs", script)
            self.assertIn("$env:ComSpec", script)
            self.assertIn(str(collector), script)

    def test_remote_settings_restrict_address_and_paths(self):
        config = {"host": "192.168.56.105", "username": "analyst",
                  "port": 22, "remote_dir": "qiling_dlls"}
        self.assertEqual(qiling_setup._remote_settings(config)[1], "analyst")
        for update in ({"host": "192.168.57.105"},
                       {"remote_dir": "../outside"},
                       {"username": "YOUR_VM_USERNAME"}):
            with self.subTest(update=update), self.assertRaises(
                    qiling_setup.QilingSetupError):
                qiling_setup._remote_settings({**config, **update})

    def test_ssh_auto_adds_unknown_host_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            known_hosts = root / "qiling_dlls" / "known_hosts.ssh"
            known_hosts.parent.mkdir()
            known_hosts.write_text("# pending trust\n", encoding="utf-8")
            config = {
                "host": "192.168.56.105", "username": "analyst",
                "port": 22, "remote_dir": "qiling_dlls",
                "known_hosts_file": "qiling_dlls/known_hosts.ssh",
            }
            with patch.object(qiling_setup.core, "REPO", str(root)), \
                    patch.object(qiling_setup, "_ensure_vm_key") as ensure:
                ssh, sftp, _remote = qiling_setup._ssh_base(config)
                self.assertIn("StrictHostKeyChecking=accept-new", ssh)
                configured_file = next(value for value in ssh
                                       if value.startswith("UserKnownHostsFile="))
                self.assertEqual(Path(configured_file.split("=", 1)[1]),
                                 known_hosts.resolve())
                self.assertIn("StrictHostKeyChecking=accept-new", sftp)
                ensure.assert_called_once()

            # an absent known_hosts file no longer blocks the connection
            known_hosts.unlink()
            with patch.object(qiling_setup.core, "REPO", str(root)), \
                    patch.object(qiling_setup, "_ensure_vm_key"):
                qiling_setup._ssh_base(config)
            self.assertTrue(known_hosts.parent.is_dir())

    def test_vm_password_prefers_config_then_vm_info(self):
        self.assertEqual(
            qiling_setup._vm_password({"password": "inline"}), "inline")
        with tempfile.TemporaryDirectory() as directory:
            info = Path(directory) / "vm_info.json"
            info.write_text('{"VM_PASSWORD": "from-vm-info"}',
                            encoding="utf-8")
            with patch.object(qiling_setup, "QILING_DIR", Path(directory)):
                self.assertEqual(qiling_setup._vm_password({}),
                                 "from-vm-info")
            with patch.object(qiling_setup, "QILING_DIR",
                              Path(directory) / "missing"):
                self.assertEqual(qiling_setup._vm_password({}), "")

    def test_sample_arch_detection_uses_pe_coff_machine(self):
        def pe(machine: int) -> bytes:
            header = bytearray(b"MZ" + b"\x00" * 0x3A)
            header += (0x80).to_bytes(4, "little")
            header += b"\x00" * (0x80 - len(header))
            header += b"PE\x00\x00" + machine.to_bytes(2, "little")
            return bytes(header)

        with tempfile.TemporaryDirectory() as directory:
            x86 = Path(directory) / "x86.exe"
            x86.write_bytes(pe(0x014C))
            x64 = Path(directory) / "x64.exe"
            x64.write_bytes(pe(0x8664))
            not_pe = Path(directory) / "note.txt"
            not_pe.write_bytes(b"MZ" + b"\x00" * 64)
            self.assertTrue(qiling_setup._sample_is_x86(x86))
            self.assertFalse(qiling_setup._sample_is_x86(x64))
            self.assertFalse(qiling_setup._sample_is_x86(not_pe))

    def test_sftp_batch_puts_options_before_the_destination(self):
        """sftp parses options only before the destination; -b after it
        makes sftp print its usage and exit 1."""
        with patch.object(qiling_setup.subprocess, "run",
                          return_value=Mock(returncode=0)) as run:
            qiling_setup._sftp_batch(
                ["sftp", "-P", "22", "-o", "BatchMode=yes",
                 "qilin@192.168.56.105"], "ls\n")
        argv = run.call_args.args[0]
        self.assertLess(argv.index("-b"), argv.index("qilin@192.168.56.105"))
        self.assertEqual(argv[-1], "qilin@192.168.56.105")

    def test_deploy_uploads_archive_only_when_vm_rootfs_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / "sample.exe"
            sample.write_bytes(b"PE sample")
            uploads = []
            commands = []
            ssh = ["ssh", "-p", "22", "analyst@192.168.56.105"]
            base = '"$HOME"/qiling_dlls'
            with patch.object(qiling_setup, "SCRIPT", Path(directory) / "_qiling_script.py"), \
                    patch.object(qiling_setup, "ARCHIVE", Path(directory) / "rootfs.tar.gz"), \
                    patch.object(qiling_setup, "RESULTS", Path(directory) / "results"), \
                    patch.object(qiling_setup, "rootfs_exists", return_value=True), \
                    patch.object(qiling_setup, "_package_rootfs"), \
                    patch.object(qiling_setup, "_ssh_base",
                                 return_value=(ssh, ["sftp"], base)), \
                    patch.object(qiling_setup, "remote_rootfs_exists",
                                 return_value=False), \
                    patch.object(qiling_setup, "_ssh", return_value=Mock(
                        returncode=0)), \
                    patch.object(qiling_setup, "_upload",
                                 side_effect=lambda _cfg, files: uploads.extend(files)), \
                    patch.object(qiling_setup.subprocess, "run",
                                 return_value=Mock(returncode=0, stdout="",
                                                   stderr="")), \
                    patch.object(qiling_setup.core, "run_stream",
                                 side_effect=lambda cmd, *_a, **_k: commands.append(cmd) or 0), \
                    patch.object(qiling_setup, "_download"):
                Path(directory, "_qiling_script.py").write_text("pass", encoding="utf-8")
                Path(directory, "rootfs.tar.gz").write_bytes(b"archive")
                result = qiling_setup.deploy_and_run(
                    {"host": "192.168.56.105", "username": "analyst",
                     "remote_dir": "qiling_dlls"}, str(sample),
                    harness_args=["--timeout", "30"])

            self.assertEqual(len(uploads), 3)
            self.assertEqual(uploads[-1][1], "qiling_dlls/rootfs.tar.gz")
            remote_command = commands[0][-1]
            self.assertIn('cd "$HOME"/qiling_dlls', remote_command)
            self.assertIn("x8664_windows", remote_command)
            self.assertIn("--timeout 30", remote_command)
            self.assertLess(remote_command.index("--timeout 30"),
                            remote_command.index("sample.exe"))
            self.assertNotIn("'$HOME'", remote_command)
            self.assertTrue(result.endswith("sample_qiling_out.zip"))

    def test_network_blocked_detection_is_narrow(self):
        self.assertTrue(qiling_setup.network_blocked(
            subprocess.TimeoutExpired("ssh", 8)))
        self.assertFalse(qiling_setup.network_blocked(
            qiling_setup.QilingSetupError("host key verification failed")))


class QilingUploadCliTests(unittest.TestCase):
    """qiling_upload.py - the command-line upload/run/download driver."""

    def run_cli(self, argv, deploy):
        import qiling_upload
        config = {"host": "192.168.56.105", "username": "qilin", "port": 22}
        with patch.object(qiling_upload.vms, "load_vms",
                          return_value={"qiling": config}), \
                patch.object(qiling_upload, "_ensure_vm_running",
                             return_value=True), \
                patch.object(qiling_upload, "_prepare_rootfs",
                             return_value=True), \
                patch.object(qiling_upload.qiling_setup, "deploy_and_run",
                             side_effect=deploy) as run, \
                redirect_stdout(io.StringIO()) as output:
            code = qiling_upload.main(argv)
        return code, run, output.getvalue()

    def test_upload_forwards_harness_flags_and_reports_the_zip(self):
        code, run, output = self.run_cli(
            ["sample.exe", "--timeout", "30", "--no-peb-patch"],
            lambda _cfg, _sample, harness_args=(): "results\\sample.zip")
        self.assertEqual(code, 0)
        self.assertEqual(run.call_args.kwargs["harness_args"],
                         ["--timeout", "30", "--no-peb-patch"])
        self.assertIn("sample.zip", output)
        self.assertIn("1 report(s)", output)

    def test_upload_keeps_going_after_a_failed_sample(self):
        from qiling_setup import QilingSetupError

        def broken(_cfg, _sample, harness_args=()):
            raise QilingSetupError("boom")

        code, run, output = self.run_cli(
            ["a.exe", "b.exe", "--no-firewall"], broken)
        self.assertEqual(code, 1)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(output.count("boom"), 2)
        self.assertIn("2 of 2 sample(s) failed", output)


if __name__ == "__main__":
    unittest.main()
