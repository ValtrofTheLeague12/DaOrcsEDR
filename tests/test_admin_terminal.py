import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "admin-terminal"))
import admin
import activate
import builder
import core
import netcfg
import stop
import vms


class AdminTerminalTests(unittest.TestCase):
    def test_cli_options_reach_interactive_status(self):
        with patch.object(admin.core, "services", return_value=[
                Mock(key="analyzer")]), patch.object(admin, "menu",
                                                      return_value=0) as menu:
            self.assertEqual(admin.main([
                "--only", "analyzer", "--interval", "2.5"
            ]), 0)
        menu.assert_called_once_with(only={"analyzer"}, interval=2.5)

    def test_cli_rejects_empty_filter_and_nonpositive_interval(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(admin.main(["--only", " , "]), 2)
        for interval in ("0", "-1", "nan", "inf"):
            with self.subTest(interval=interval), redirect_stdout(io.StringIO()), \
                    patch("sys.stderr", new=io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    admin.main(["--interval", interval])
                self.assertEqual(raised.exception.code, 2)

    def test_numeric_prompt_exits_on_eof(self):
        with patch("builtins.input", side_effect=EOFError):
            with self.assertRaises(EOFError):
                core.ask_int("port", None)

    def test_invalid_vm_fields_fall_back_to_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "vms.json"
            config.write_text(json.dumps({
                "capev2": {
                    "host": None,
                    "port": "not-a-port",
                    "kind": "invalid",
                    "path": "missing-leading-slash",
                }
            }), encoding="utf-8")
            with patch.object(vms, "VMS_FILE", str(config)):
                result = vms.load_vms()
        self.assertEqual(result["capev2"]["host"], "127.0.0.1")
        self.assertEqual(result["capev2"]["port"], 8090)
        self.assertEqual(result["capev2"]["kind"], "http")
        self.assertEqual(result["capev2"]["path"], "/apiv2/")

    def test_ipv6_vm_probe_builds_valid_url(self):
        response = Mock()
        response.status = 200
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        with patch("urllib.request.urlopen", return_value=response) as open_url:
            reachable, detail, _elapsed = vms._probe_endpoint(
                "::1", 8090, "/apiv2/")
        self.assertTrue(reachable)
        self.assertEqual(detail, "HTTP 200")
        self.assertEqual(open_url.call_args.args[0], "http://[::1]:8090/apiv2/")

    def test_clean_build_reports_removal_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "build-ucrt").mkdir()
            with patch.object(builder.core, "REPO", directory), \
                    patch.object(builder.shutil, "rmtree",
                                 side_effect=PermissionError("in use")):
                with self.assertRaises(PermissionError):
                    builder._remove_build_dir()

    def test_malapi_uses_project_venv(self):
        command, needs, _hint = activate._malapi_cmd()
        self.assertEqual(command, [core.PY_VENV, "api/server.py"])
        self.assertEqual(needs, core.PY_VENV)

    def test_spawn_detached_hides_the_service_console(self):
        """A service started without a console re-execs itself (venv
        launcher -> real interpreter) into a fresh, visible cmd window whose
        closure kills the listener; a hidden console is inherited instead."""
        with tempfile.TemporaryDirectory() as directory:
            log = str(Path(directory) / "start.log")
            with patch.object(core.subprocess, "Popen") as popen:
                popen.return_value.pid = 4242
                self.assertEqual(
                    core.spawn_detached(["svc"], directory, log), 4242)
        flags = popen.call_args.kwargs["creationflags"]
        self.assertTrue(flags & getattr(subprocess, "CREATE_NO_WINDOW",
                                        0x08000000))
        self.assertFalse(flags & getattr(subprocess, "DETACHED_PROCESS", 0x8))

    def test_activation_accepts_service_key_selection(self):
        starters = [
            activate.Starter("analyzer", "Analyzer API", [], "", 1),
            activate.Starter("ml", "ML scorer", [], "", 1),
        ]
        services = [
            core.Service("analyzer", "Analyzer API", "127.0.0.1:1"),
            core.Service("ml", "ML scorer", "127.0.0.1:2"),
        ]
        with patch.object(activate, "_starter_list", return_value=starters), \
                patch.object(activate.core, "services",
                             side_effect=[services, services]), \
                patch.object(activate.core, "probe_all"), \
                patch.object(activate.core, "render_services", return_value=""), \
                patch.object(activate.core, "ask", return_value="ml"), \
                patch.object(activate.core, "pause"), \
                patch.object(activate, "_blocker", return_value=""), \
                patch.object(activate, "_start") as start:
            activate.screen()
        start.assert_called_once_with(starters[1])

    def test_activation_status_table_uses_probed_services(self):
        starter = activate.Starter("analyzer", "Analyzer API", [], "", 1)
        service = core.Service("analyzer", "Analyzer API", "127.0.0.1:1")
        service.up = True
        with patch.object(activate, "_starter_list", return_value=[starter]), \
                patch.object(activate.core, "services", return_value=[service]), \
                patch.object(activate.core, "probe_all"), \
                patch.object(activate.core, "render_services",
                             return_value="service status"), \
                patch.object(activate.core, "ask") as ask, \
                patch.object(activate.core, "pause"), \
                redirect_stdout(io.StringIO()) as output:
            activate.screen()
        self.assertIn("all services are already up", output.getvalue())
        ask.assert_not_called()

    def test_stop_services_is_reachable_from_the_menu(self):
        self.assertIn(("9", "Stop Services", "stop"), admin.MENU)

    def test_bind_addr_widens_off_loopback_and_probe_host_dials_it(self):
        """A configured external IP binds 0.0.0.0 so the analyzer's own
        127.0.0.1 client keeps working; 0.0.0.0 itself is not dialable."""
        self.assertEqual(core.bind_addr("127.0.0.1"), "127.0.0.1")
        self.assertEqual(core.bind_addr("::1"), "::1")
        self.assertEqual(core.bind_addr("localhost"), "localhost")
        self.assertEqual(core.bind_addr("100.95.199.25"), "0.0.0.0")
        self.assertEqual(core.bind_addr("fe80::1"), "::")
        self.assertEqual(core.bind_addr("mybox.local"), "0.0.0.0")
        self.assertEqual(core.probe_host("0.0.0.0"), "127.0.0.1")
        self.assertEqual(core.probe_host("::"), "::1")
        self.assertEqual(core.probe_host("100.95.199.25"), "100.95.199.25")

    def test_service_endpoints_follow_the_env(self):
        values = {
            "SA_API_HOST": "100.95.199.25", "SA_API_PORT": "60025",
            "MALAPI_HOST": "100.95.199.25", "MALAPI_PORT": "60100",
            "ML_HOST": "100.95.199.25", "ML_PORT": "60110",
        }
        with patch.object(core, "setting",
                          side_effect=lambda name, default:
                          values.get(name, default)):
            svcs = {s.key: s for s in core.services()}
        self.assertEqual(svcs["analyzer"].endpoint,
                         "100.95.199.25:60025/health")
        self.assertEqual(svcs["malapi"].endpoint,
                         "100.95.199.25:60100/malapi/AdjustTokenPrivileges/")
        self.assertEqual(svcs["ml"].endpoint, "100.95.199.25:60110/health")

        values["MALAPI_HOST"] = "0.0.0.0"
        with patch.object(core, "setting",
                          side_effect=lambda name, default:
                          values.get(name, default)):
            svcs = {s.key: s for s in core.services()}
        self.assertEqual(svcs["malapi"].endpoint,
                         "127.0.0.1:60100/malapi/AdjustTokenPrivileges/")

    def test_netcfg_rewrites_only_the_named_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            env_file.write_text("# keep me\nSA_API_HOST=old\n"
                                "MALAPI_HOST=127.0.0.1\n", encoding="utf-8")
            netcfg._rewrite_env({"MALAPI_HOST": "100.95.199.25",
                                 "ML_PORT": "60110"}, str(env_file))
            text = env_file.read_text(encoding="utf-8")
            backup = Path(str(env_file) + ".bak").read_text(encoding="utf-8")
        self.assertIn("# keep me", text)
        self.assertIn("SA_API_HOST=old", text)
        self.assertIn("MALAPI_HOST=100.95.199.25", text)
        self.assertIn("ML_PORT=60110", text)
        self.assertIn("MALAPI_HOST=127.0.0.1", backup)

    def test_netcfg_port_must_not_collide_with_another_service(self):
        self.assertTrue(netcfg.valid_port("60000", "malapi")[0])
        self.assertTrue(netcfg.valid_port("60025", "analyzer")[0])
        ok, why_ = netcfg.valid_port("60000", "analyzer")
        self.assertFalse(ok)
        self.assertIn("MalAPI", why_)
        self.assertFalse(netcfg.valid_port("60001", "malapi")[0])
        self.assertFalse(netcfg.valid_port("0", "malapi")[0])
        self.assertFalse(netcfg.valid_port("nope", "malapi")[0])

    def test_netcfg_screen_keeps_everything_on_enter(self):
        with patch.object(core, "ask", side_effect=["1", "", ""]), \
                patch.object(core, "pause"), \
                patch.object(netcfg, "_rewrite_env") as rewrite, \
                redirect_stdout(io.StringIO()) as output:
            netcfg.screen()
        self.assertIn("nothing changed", output.getvalue())
        rewrite.assert_not_called()

    def test_netcfg_mints_a_token_only_for_exposed_ml(self):
        with patch.object(core, "ml_token", return_value=""), \
                redirect_stdout(io.StringIO()) as output:
            values = netcfg._note_bind("ML scorer", "100.95.199.25", 60010)
        self.assertIn("ML_SERVE_TOKEN", values)
        self.assertGreaterEqual(len(values["ML_SERVE_TOKEN"]), 20)
        self.assertIn("Authorization: Bearer", output.getvalue())
        with patch.object(core, "ml_token", return_value="tok"), \
                redirect_stdout(io.StringIO()):
            self.assertEqual(
                netcfg._note_bind("ML scorer", "100.95.199.25", 60110), {})
            self.assertEqual(
                netcfg._note_bind("MalAPI", "100.95.199.25", 60000), {})
            self.assertEqual(
                netcfg._note_bind("MalAPI", "127.0.0.1", 60000), {})

    def test_ml_starter_binds_the_configured_endpoint(self):
        with patch.object(core, "ml_host", return_value="100.95.199.25"), \
                patch.object(core, "ml_port", return_value=60110):
            starters = {s.key: s for s in activate._starter_list()}
        cmd = starters["ml"].cmd
        self.assertEqual(cmd[cmd.index("--host") + 1], "0.0.0.0")
        self.assertEqual(cmd[cmd.index("--port") + 1], "60110")

    def test_stop_choice_defaults_to_the_running_services(self):
        running = ["analyzer", "ml"]
        self.assertEqual(stop.choose("all", running), running)
        self.assertEqual(stop.choose("ALL", running), running)
        self.assertEqual(stop.choose("ml", running), ["ml"])
        self.assertEqual(stop.choose(" ml , analyzer ", running), running)
        with self.assertRaises(ValueError) as raised:
            stop.choose("cyberchef", running)
        self.assertEqual(str(raised.exception), "cyberchef")
        with self.assertRaises(ValueError):
            stop.choose("", running)

    def test_stop_reports_a_quiet_port_as_nothing_to_do(self):
        with patch.object(core, "listener_pid", return_value=None):
            ok, detail = stop._stop("malapi")
        self.assertFalse(ok)
        self.assertIn(str(core.malapi_port()), detail)

    def test_ml_token_exempts_local_callers_only(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ml"))
        import serve
        self.assertTrue(serve._authorised("s3cret", "127.0.0.1", ""))
        self.assertTrue(serve._authorised("s3cret", "::1", ""))
        self.assertTrue(serve._authorised(None, "10.0.0.7", ""))
        self.assertTrue(serve._authorised("s3cret", "10.0.0.7",
                                          "Bearer s3cret"))
        self.assertFalse(serve._authorised("s3cret", "10.0.0.7", ""))
        self.assertFalse(serve._authorised("s3cret", "10.0.0.7",
                                           "Bearer wrong"))


if __name__ == "__main__":
    unittest.main()
