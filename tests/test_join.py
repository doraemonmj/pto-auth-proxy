"""Exercise join with synthetic credentials and an isolated authd fixture.

No real PAM call, systemd operation, account-state mutation or authd cleanup.
"""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]


class JoinTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.config = self.home / ".config/pto-auth-proxy"
        self.config.mkdir(parents=True)
        self.component = self.root / "component"
        self.component.mkdir()
        for filename in ("configure-shell.sh", "shell-integration.sh"):
            shutil.copy2(ROOT / filename, self.component / filename)
        (self.component / "user_proxy.py").write_text("raise SystemExit(0)\n")
        (self.component / "bin").mkdir()
        command = self.component / "bin/pto-auth-proxy"
        command.write_text("#!/bin/bash\nexit 0\n")
        command.chmod(0o755)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.user = "pto-fixture-" + uuid.uuid4().hex[:12]
        self.environment = {
            "PATH": str(self.bin) + ":" + os.environ["PATH"],
            "HOME": str(self.home), "SHELL": "/bin/bash",
            "FIXTURE_USER": self.user, "FIXTURE_HOME": str(self.home),
            "PYTHONPATH": str(self.root), "PTO_AUTH_PROXY_SOURCE_DIR": str(self.component),
        }
        (self.root / "pam.py").write_text("# No real PAM is used by this fixture.\n")
        self.script("id", '''case "$1" in
  -un) echo "$FIXTURE_USER" ;;
  -u) echo 987654321 ;;
  -nG) echo proxyusers ;;
  *) exit 1 ;;
esac
''')
        self.script("getent", 'printf "%s:x:987654321:123::%s:/bin/bash\\n" "$FIXTURE_USER" "$FIXTURE_HOME"\n')
        self.script("systemctl", '''case "$1" in
  show) echo loaded ;;
  is-enabled) echo disabled; exit 1 ;;
  is-active) exit 0 ;;
  *) exit 1 ;;
esac
''')
        self.script("sleep", "exit 0\n")
        self.socket_path = f"/tmp/authproxy-{self.user}.sock"
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(self.socket_path)
        self.listener.listen()
        self.listener.settimeout(0.1)
        self.requests = []
        self.password_ok = True
        self.failure_reason = "synthetic authentication failure"
        self.issue_clears_logout = False
        self.done = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)

    def script(self, name, content):
        path = self.bin / name
        path.write_text("#!/bin/bash\n" + content)
        path.chmod(0o755)

    def close_server(self):
        self.done.set()
        self.listener.close()
        self.thread.join(timeout=2)
        Path(self.socket_path).unlink(missing_ok=True)

    def serve(self):
        while not self.done.is_set():
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with client:
                client.settimeout(2)
                data = b""
                while b"\n" not in data:
                    chunk = client.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                if not data:
                    continue
                request = json.loads(data)
                self.requests.append(request)
                if request.get("op") == "capabilities":
                    response = {"ok": True, "capabilities": ["token-v1"]}
                elif self.password_ok:
                    if self.issue_clears_logout:
                        (self.config / "access.disabled").unlink(missing_ok=True)
                    response = {"ok": True, "token": "pto_" + "A" * 43}
                else:
                    response = {"ok": False, "reason": self.failure_reason}
                client.sendall((json.dumps(response) + "\n").encode())

    def join(self):
        return subprocess.run(["bash", str(ROOT / "join-proxy.sh")],
                              input="synthetic-password\n", env=self.environment,
                              text=True, capture_output=True, timeout=10)

    def test_successful_join_creates_token_and_default_auto_hook(self):
        result = self.join()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.config / "secret-uri").read_text(), "pto_" + "A" * 43)
        self.assertIn("_PTO_PROXY_AUTO_HTTP_PORT=20811", (self.config / "env.sh").read_text())
        self.assertFalse((self.config / "default-mode").exists())
        self.assertNotIn("synthetic-password", result.stdout + result.stderr)

    def test_failed_join_keeps_previously_stopped_access_disabled(self):
        (self.config / "authd.stopped").write_text("stopped\n")
        self.password_ok = False
        result = self.join()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.config / "authd.stopped").exists())
        self.assertFalse((self.config / "secret-uri").exists())

    def test_inherited_xtrace_does_not_disclose_password_or_issued_token(self):
        self.environment["SHELLOPTS"] = "xtrace"
        result = self.join()
        self.assertEqual(result.returncode, 0)
        self.assertNotIn("synthetic-password", result.stdout + result.stderr)
        self.assertNotIn("pto_" + "A" * 43, result.stdout + result.stderr)

    def test_allexport_cannot_put_password_or_token_in_child_environments(self):
        self.environment["SHELLOPTS"] = "allexport:xtrace"
        self.environment["PW"] = "inherited-placeholder"
        self.environment["AUTH_RESULT"] = "inherited-placeholder"
        self.environment["PROXY_CREDENTIAL"] = "inherited-placeholder"
        leaked = self.root / "leaked"
        self.environment["FIXTURE_LEAK"] = str(leaked)
        (self.root / "sitecustomize.py").write_text('''
import os
from pathlib import Path
if any("synthetic-password" in value or "pto_" + "A" * 43 in value for value in os.environ.values()):
    Path(os.environ["FIXTURE_LEAK"]).touch()
''')
        result = self.join()
        self.assertEqual(result.returncode, 0)
        self.assertFalse(leaked.exists())

    def test_raw_authentication_error_cannot_echo_password(self):
        self.password_ok = False
        self.failure_reason = "unexpected synthetic-password echoed by backend"
        result = self.join()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("synthetic-password", result.stdout + result.stderr)

    def test_shell_setup_failure_restores_previous_logout_after_token_issue(self):
        (self.config / "access.disabled").touch()
        self.issue_clears_logout = True
        # Malformed managed blocks are rejected by configure-shell before writing.
        (self.home / ".bashrc").write_text("# >>> pto-auth-proxy managed environment >>>\n")
        result = self.join()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.config / "access.disabled").exists())

    def test_foreign_uid_socket_receives_no_password_or_auth_request(self):
        (self.root / "sitecustomize.py").write_text('''
import os, socket, struct
OriginalSocket = socket.socket
class FixtureSocket(OriginalSocket):
    def getsockopt(self, level, option, *args):
        if level == socket.SOL_SOCKET and option == socket.SO_PEERCRED:
            return struct.pack("iII", 123, os.getuid() + 1, 123)
        return super().getsockopt(level, option, *args)
socket.socket = FixtureSocket
''')
        result = self.join()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.requests, [])
