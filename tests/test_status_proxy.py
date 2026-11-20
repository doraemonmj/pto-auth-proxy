import contextlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import status_proxy


class StatusTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        for name in ("access_dir", "config_dir"):
            patch = mock.patch.object(status_proxy.user_proxy, name, return_value=self.directory)
            patch.start()
            self.addCleanup(patch.stop)
        environment = mock.patch.dict(os.environ, {
            "PTO_AUTH_PROXY_UPSTREAM_HOST": "127.0.0.1",
            "PTO_AUTH_PROXY_UPSTREAM_PORT": "7895",
            "PTO_AUTH_PROXY_GUARD_PORTS": "7895",
        })
        self.probe_patch = mock.patch.object(status_proxy, "https_probe", return_value="ok")
        self.probe_patch.start()
        self.addCleanup(self.probe_patch.stop)
        self.git_patch = mock.patch.object(status_proxy, "git_proxy_configured", return_value=False)
        self.git_patch.start()
        self.addCleanup(self.git_patch.stop)
        environment.start()
        self.addCleanup(environment.stop)

    def test_guard_default_tracks_only_the_upstream(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(status_proxy.guard_ports(7895), (7895,))
        with mock.patch.dict(os.environ, {"PTO_AUTH_PROXY_GUARD_PORTS": ""}, clear=True):
            self.assertEqual(status_proxy.guard_ports(7895), (7895,))

    def test_missing_upstream_fails_without_network_probe(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(status_proxy, "authenticated_connect") as connect, \
             contextlib.redirect_stdout(io.StringIO()) as output:
            result = status_proxy.main("doctor")
        self.assertEqual(result, 1)
        self.assertIn("upstream=unconfigured", output.getvalue())
        connect.assert_not_called()

    def test_guard_ports_follow_configuration(self):
        with mock.patch.dict(
                os.environ, {"PTO_AUTH_PROXY_GUARD_PORTS": "5000,5001"},
                clear=True):
            self.assertEqual(status_proxy.guard_ports(4780), (5000, 5001))

    def test_invalid_guard_ports_fail_closed(self):
        with mock.patch.dict(
                os.environ, {"PTO_AUTH_PROXY_GUARD_PORTS": "4780,bad"},
                clear=True):
            self.assertEqual(status_proxy.guard_ports(4780), ())

    def test_proxy_url_ignores_direct_upstream_configuration(self):
        environment = {
            "HTTPS_PROXY": "http://user:secret@127.0.0.1:4780",
            "HTTP_PROXY": "http://user:secret@127.0.0.1:20809",
        }
        with mock.patch.dict(os.environ, environment, clear=True):
            url, source = status_proxy.proxy_url("user", "127.0.0.1", 20809)
        self.assertEqual(url, environment["HTTP_PROXY"])
        self.assertEqual(source, "env")

    def test_ready_output_contains_no_credential(self):
        output = io.StringIO()
        with mock.patch.object(status_proxy, "group_member", return_value=True), \
             mock.patch.object(status_proxy, "access_disabled", return_value=False), \
             mock.patch.object(status_proxy, "authd_capability",
                               return_value=(True, "token")), \
             mock.patch.object(status_proxy, "proxy_url",
                               return_value=("http://user:top-secret@127.0.0.1:20809",
                                             "file")), \
             mock.patch.object(status_proxy, "authenticated_connect",
                               return_value="200"), \
             mock.patch.object(status_proxy, "direct_access_is_correct",
                               return_value=True), \
             mock.patch.object(status_proxy, "guard_service_active",
                               return_value=True), \
             contextlib.redirect_stdout(output):
            result = status_proxy.main("doctor")
        self.assertEqual(result, 0)
        self.assertIn("READY", output.getvalue())
        self.assertNotIn("top-secret", output.getvalue())
        self.assertIn("upstream=127.0.0.1:7895", output.getvalue())

    def test_stale_guard_cannot_report_ready(self):
        os.environ["PTO_AUTH_PROXY_GUARD_PORTS"] = "4780,4781"
        output = io.StringIO()
        with mock.patch.object(status_proxy, "group_member", return_value=True), \
             mock.patch.object(status_proxy, "access_disabled", return_value=False), \
             mock.patch.object(status_proxy, "authd_capability",
                               return_value=(True, "token")), \
             mock.patch.object(status_proxy, "proxy_url",
                               return_value=("http://user:top-secret@127.0.0.1:20809",
                                             "file")), \
             mock.patch.object(status_proxy, "authenticated_connect",
                               return_value="200"), \
             mock.patch.object(status_proxy, "direct_access_is_correct",
                               return_value=True), \
             mock.patch.object(status_proxy, "guard_service_active",
                               return_value=True), \
             contextlib.redirect_stdout(output):
            result = status_proxy.main("doctor")
        self.assertEqual(result, 1)
        self.assertIn("NOT_READY", output.getvalue())
        self.assertIn("guard=upstream-unprotected", output.getvalue())
        self.assertNotIn("top-secret", output.getvalue())
        self.assertIn("upstream=127.0.0.1:7895", output.getvalue())

    def test_left_state_skips_authenticated_connection(self):
        output = io.StringIO()
        with mock.patch.object(status_proxy, "group_member", return_value=True), \
             mock.patch.object(status_proxy, "access_disabled", return_value=True), \
             mock.patch.object(status_proxy, "authd_capability",
                               return_value=(True, "token")), \
             mock.patch.object(status_proxy, "proxy_url",
                               return_value=(None, "missing")), \
             mock.patch.object(status_proxy, "authenticated_connect") as connect, \
             mock.patch.object(status_proxy, "direct_access_is_correct",
                               return_value=True), \
             mock.patch.object(status_proxy, "guard_service_active",
                               return_value=True), \
             contextlib.redirect_stdout(output):
            result = status_proxy.main("doctor")
        self.assertEqual(result, 1)
        self.assertIn("LEFT", output.getvalue())
        self.assertIn("proxy=disabled", output.getvalue())
        connect.assert_not_called()

    def test_proxy_url_rejects_non_http_scheme(self):
        environment = {
            "HTTPS_PROXY": "socks5h://user:secret@127.0.0.1:20809",
        }
        with mock.patch.dict(os.environ, environment, clear=True), \
             mock.patch.object(status_proxy.Path, "home",
                               return_value=status_proxy.Path("/missing-home")):
            url, source = status_proxy.proxy_url("user", "127.0.0.1", 20809)
        self.assertIsNone(url)
        self.assertEqual(source, "missing")

    def test_empty_xdg_config_home_uses_home_default(self):
        environment = {"XDG_CONFIG_HOME": ""}
        with mock.patch.dict(os.environ, environment, clear=True), \
             mock.patch.object(status_proxy.Path, "home",
                               return_value=status_proxy.Path("/home/test")), \
             mock.patch.object(status_proxy.Path, "read_text",
                               side_effect=OSError):
            url, source = status_proxy.proxy_url("user", "127.0.0.1", 20809)
        self.assertIsNone(url)
        self.assertEqual(source, "missing")

    def test_status_reports_direct_choice_without_external_or_guard_probes(self):
        (self.directory / "default-mode").write_text("direct\n")
        output = io.StringIO()
        with mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(status_proxy, "access_disabled", return_value=False), \
             mock.patch.object(status_proxy, "group_member", return_value=True), \
             mock.patch.object(status_proxy, "authd_capability", return_value=(True, "token")), \
             mock.patch.object(status_proxy, "proxy_url", return_value=(None, "missing")), \
             mock.patch.object(status_proxy, "authenticated_connect") as connect, \
             mock.patch.object(status_proxy, "direct_access_is_correct") as direct, \
             mock.patch.object(status_proxy, "guard_service_active") as guard, \
             contextlib.redirect_stdout(output):
            self.assertEqual(status_proxy.main(), 0)
        self.assertIn("shell=direct default=direct", output.getvalue())
        self.assertNotIn("READY:", output.getvalue())
        connect.assert_not_called()
        direct.assert_not_called()
        guard.assert_not_called()

    def test_logout_marker_uses_account_home_even_when_home_is_overridden(self):
        (self.directory / "access.disabled").touch()
        with mock.patch.object(status_proxy.Path, "home", return_value=Path("/unrelated-home")):
            self.assertTrue(status_proxy.access_disabled())

    def test_shell_mode_detects_external_mixed_and_bypassed_environments(self):
        for environment, expected in (
            ({}, "direct"),
            ({"HTTP_PROXY": "http://elsewhere:3128"}, "external"),
            ({"HTTP_PROXY": "http://user:secret@127.0.0.1:20809"}, "mixed"),
            ({"HTTP_PROXY": "http://user:secret@127.0.0.1:20809", "NO_PROXY": "*"}, "bypassed"),
            ({"HTTP_PROXY": "http://user:secret@127.0.0.1:bad"}, "external"),
        ):
            with self.subTest(expected=expected), mock.patch.dict(os.environ, environment, clear=True):
                self.assertEqual(status_proxy.shell_mode("127.0.0.1", 20809, 20808), expected)

    def test_status_distinguishes_auto_from_forced_proxy(self):
        for mode, http_port, socks_port in (("auto", 20811, 20810), ("proxy", 20809, 20808)):
            environment = {key: f"socks5h://user:token@127.0.0.1:{socks_port}" if key.lower() == "all_proxy"
                           else f"http://user:token@127.0.0.1:{http_port}" for key in status_proxy.user_proxy.PROXY_KEYS}
            with mock.patch.dict(os.environ, environment, clear=True):
                self.assertEqual(status_proxy.shell_mode("127.0.0.1", 20809, 20808), mode)

    def test_stopped_doctor_skips_new_authentication(self):
        (self.directory / "authd.stopped").touch()
        output = io.StringIO()
        with mock.patch.object(status_proxy, "access_disabled", return_value=False), \
             mock.patch.object(status_proxy, "group_member", return_value=True), \
             mock.patch.object(status_proxy, "authd_capability", return_value=(False, "down")), \
             mock.patch.object(status_proxy, "proxy_url", return_value=(None, "missing")), \
             mock.patch.object(status_proxy, "authenticated_connect") as connect, \
             mock.patch.object(status_proxy, "direct_access_is_correct", return_value=True), \
             mock.patch.object(status_proxy, "guard_service_active", return_value=True), \
             contextlib.redirect_stdout(output):
            self.assertEqual(status_proxy.main("doctor"), 1)
        self.assertIn("STOPPED:", output.getvalue())
        self.assertIn("pto-auth-proxy start", output.getvalue())
        connect.assert_not_called()


class HttpsProbeTest(unittest.TestCase):
    def test_probe_uses_default_trust_and_target_hostname(self):
        client = mock.MagicMock()
        client.__enter__.return_value = client
        client.recv.side_effect = [bytes([byte]) for byte in b"HTTP/1.1 200 OK\r\n\r\n"]
        context = mock.MagicMock()
        tls = context.wrap_socket.return_value.__enter__.return_value
        tls.recv.return_value = b"HTTP/1.1 403 Forbidden\r\n"
        with mock.patch.object(status_proxy.socket, "create_connection", return_value=client), \
             mock.patch.object(status_proxy.ssl, "create_default_context", return_value=context) as create:
            self.assertEqual(status_proxy.https_probe("http://alice:private-token@127.0.0.1:20809"), "ok")
        create.assert_called_once_with()
        context.wrap_socket.assert_called_once_with(client, server_hostname="api.github.com")
        self.assertIn(b"HEAD / HTTP/1.1", tls.sendall.call_args.args[0])

    def test_probe_rejects_tls_errors_without_echoing_secrets(self):
        client = mock.MagicMock()
        client.__enter__.return_value = client
        client.recv.side_effect = [bytes([byte]) for byte in b"HTTP/1.1 200 OK\r\n\r\n"]
        context = mock.MagicMock()
        context.wrap_socket.side_effect = status_proxy.ssl.SSLError("private-token")
        with mock.patch.object(status_proxy.socket, "create_connection", return_value=client), \
             mock.patch.object(status_proxy.ssl, "create_default_context", return_value=context):
            self.assertEqual(status_proxy.https_probe("http://alice:private-token@127.0.0.1:20809"), "tls-failed")


if __name__ == "__main__":
    unittest.main()
