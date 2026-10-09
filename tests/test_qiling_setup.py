import subprocess
import sys
import tempfile
import unittest
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

    def test_ssh_requires_known_host_entry_and_strict_checking(self):
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
                    self.assertRaisesRegex(qiling_setup.QilingSetupError,
                                           "no trusted host keys"):
                qiling_setup._ssh_base(config)
            known_hosts.write_text(
                "192.168.56.105 ssh-ed25519 AAAATEST\n", encoding="utf-8")
            with patch.object(qiling_setup.core, "REPO", str(root)):
                ssh, sftp, _remote = qiling_setup._ssh_base(config)
                self.assertIn("StrictHostKeyChecking=yes", ssh)
                configured_file = next(value for value in ssh
                                       if value.startswith("UserKnownHostsFile="))
                self.assertEqual(Path(configured_file.split("=", 1)[1]),
                                 known_hosts.resolve())
                self.assertIn("StrictHostKeyChecking=yes", sftp)

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
                     "remote_dir": "qiling_dlls"}, str(sample))

            self.assertEqual(len(uploads), 3)
            self.assertEqual(uploads[-1][1], "qiling_dlls/rootfs.tar.gz")
            remote_command = commands[0][-1]
            self.assertIn('cd "$HOME"/qiling_dlls', remote_command)
            self.assertNotIn("'$HOME'", remote_command)
            self.assertTrue(result.endswith("sample_qiling_out.zip"))

    def test_network_blocked_detection_is_narrow(self):
        self.assertTrue(qiling_setup.network_blocked(
            subprocess.TimeoutExpired("ssh", 8)))
        self.assertFalse(qiling_setup.network_blocked(
            qiling_setup.QilingSetupError("host key verification failed")))


if __name__ == "__main__":
    unittest.main()
