import contextlib
import io
import os
import unittest
from unittest import mock

import status_proxy


class StatusTest(unittest.TestCase):
    def setUp(self):
        environment = mock.patch.dict(os.environ, {
            "PTO_AUTH_PROXY_UPSTREAM_HOST": "127.0.0.1",
            "PTO_AUTH_PROXY_UPSTREAM_PORT": "7895",
            "PTO_AUTH_PROXY_GUARD_PORTS": "7895",
        })
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
            result = status_proxy.main()
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
            result = status_proxy.main()
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
            result = status_proxy.main()
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
            result = status_proxy.main()
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


if __name__ == "__main__":
    unittest.main()
