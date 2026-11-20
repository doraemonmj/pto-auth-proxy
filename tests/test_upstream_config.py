"""Regression checks for explicit backend selection without device/network access."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class UpstreamConfigTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.environment = {k: v for k, v in os.environ.items()
                            if not k.startswith("PTO_AUTH_PROXY_")}
        self.config = self.directory / "auth-proxy.env"
        self.base_config = (
            f"PTO_AUTH_PROXY_OWNER={subprocess.check_output(['id', '-un'], text=True).strip()}\n"
            f"PTO_AUTH_PROXY_WHITELIST={ROOT / 'config/whitelist.txt'}\n"
        )

    def validate(self, extra):
        self.config.write_text(self.base_config + extra)
        return subprocess.run(
            [str(ROOT / 'bin/pto-auth-proxy'), '--config', str(self.config), 'validate'],
            env=self.environment, capture_output=True, text=True)

    def test_missing_or_empty_port_cannot_select_legacy_upstream(self):
        for extra in ('', 'PTO_AUTH_PROXY_UPSTREAM_PORT=\n'):
            with self.subTest(extra=extra):
                result = self.validate(extra)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('PTO_AUTH_PROXY_UPSTREAM_PORT', result.stderr)

    def test_configured_ports_work_with_implicit_guard(self):
        for port in (7895, 4780, 19080):
            with self.subTest(port=port):
                result = self.validate(f'PTO_AUTH_PROXY_UPSTREAM_PORT={port}\n')
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_stale_guard_is_rejected_and_custom_guard_is_accepted(self):
        result = self.validate('PTO_AUTH_PROXY_UPSTREAM_PORT=7895\n'
                               'PTO_AUTH_PROXY_GUARD_PORTS=4780,4781\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('7895', result.stderr)
        result = self.validate('PTO_AUTH_PROXY_UPSTREAM_PORT=7895\n'
                               'PTO_AUTH_PROXY_GUARD_PORTS=7895,7896\n')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_python_entry_rejects_missing_upstream(self):
        result = subprocess.run(
            ['python3', '-c', 'import auth_proxy'], cwd=ROOT,
            env=self.environment, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('must be explicitly configured', result.stderr)

    def test_guard_rejects_stale_ports_before_touching_firewall(self):
        result = subprocess.run(
            ['bash', str(ROOT / 'scripts/egress-guard.sh'), 'start', 'pypto', '4780,4781'],
            env=dict(self.environment, PTO_AUTH_PROXY_UPSTREAM_PORT='7895'),
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('must include PTO_AUTH_PROXY_UPSTREAM_PORT', result.stderr)

    def test_guard_has_no_legacy_default(self):
        result = subprocess.run(
            ['bash', str(ROOT / 'scripts/egress-guard.sh'), 'check'],
            env=self.environment, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('ports must not be empty', result.stderr)

    def test_updater_reads_current_backend_on_each_invocation(self):
        # Simulate root ownership for this temporary fixture only. The template
        # still checks real mode bits and never runs the updater or firewall.
        fake_bin = self.directory / 'bin'
        fake_bin.mkdir()
        stat = fake_bin / 'stat'
        stat.write_text('#!/bin/bash\nif [[ "$2" == %u ]]; then echo 0; '
                        'else exec /usr/bin/stat "$@"; fi\n')
        stat.chmod(0o755)
        tool = self.directory / 'tool'
        (tool / 'config').mkdir(parents=True)
        auth = tool / 'config/auth-proxy.env'
        updater = self.directory / 'updater.env'
        updater.write_text((ROOT / 'config/auto-update.env.in').read_text()
                           .replace('@TOOL_DIR@', str(tool))
                           .replace('@PREFIX@', str(tool / 'app'))
                           .replace('@PROXY_USER@', 'pypto'))
        env = dict(self.environment, PATH=str(fake_bin) + ':' + self.environment['PATH'])
        command = ['bash', '-euc',
                   'source "$1"; printf "%s" "$REPO_AUTO_UPDATE_FETCH_ALL_PROXY"',
                   'test', str(updater)]
        for host, port, expected_host in (('127.0.0.1', 7895, '127.0.0.1'),
                                           ('127.0.0.1', 19080, '127.0.0.1'),
                                           ('::1', 7895, '[::1]')):
            auth.write_text(f'PTO_AUTH_PROXY_UPSTREAM_HOST={host}\n'
                            f'PTO_AUTH_PROXY_UPSTREAM_PORT={port}\n')
            auth.chmod(0o644)
            result = subprocess.run(command, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, f'socks5h://{expected_host}:{port}')
        auth.chmod(0o666)
        result = subprocess.run(command, env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('unsafe auth-proxy configuration', result.stderr)
        auth.chmod(0o644)
        auth.write_text('PTO_AUTH_PROXY_UPSTREAM_PORT=\n')
        result = subprocess.run(command, env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('configure the SOCKS5 upstream port', result.stderr)


if __name__ == '__main__':
    unittest.main()
