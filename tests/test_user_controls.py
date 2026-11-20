import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import types
import unittest
from unittest import mock

import user_proxy

ROOT = Path(__file__).resolve().parents[1]


class UserControlTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        self.directory = self.home / ".config/pto-auth-proxy"
        self.directory.mkdir(parents=True)
        self.user = types.SimpleNamespace(pw_name="test-user", pw_dir=str(self.home), pw_gid=123)
        for patch in (
            mock.patch.object(user_proxy, "account", return_value=self.user),
            mock.patch.object(user_proxy, "config_dir", return_value=self.directory),
            mock.patch.object(user_proxy.grp, "getgrnam",
                              return_value=types.SimpleNamespace(gr_gid=123, gr_mem=[])),
        ):
            patch.start()
            self.addCleanup(patch.stop)
        (self.directory / "secret-uri").write_text("private-test-token")
        (self.directory / "endpoints.json").write_text(json.dumps(
            {"host": "::1", "http_port": 20909, "socks_port": 20908}))

    def test_proxy_exec_builds_child_environment_without_mutating_parent(self):
        original = {"HTTPS_PROXY": "http://original", "NO_PROXY": "*,internal.example"}
        with mock.patch.dict(os.environ, original, clear=True), \
             mock.patch.object(user_proxy.os, "execvpe", side_effect=SystemExit(42)) as execute:
            with self.assertRaises(SystemExit):
                user_proxy.exec_command(["--proxy", "--", "program", "arg with spaces"])
            self.assertEqual(dict(os.environ), original)
        command, args, environment = execute.call_args.args
        self.assertEqual(command, "program")
        self.assertEqual(args, ["program", "arg with spaces"])
        self.assertEqual(environment["HTTPS_PROXY"], "http://test-user:private-test-token@[::1]:20909")
        self.assertEqual(environment["all_proxy"], "socks5h://test-user:private-test-token@[::1]:20908")
        self.assertNotIn("*", environment["NO_PROXY"].split(","))
        self.assertIn("internal.example", environment["NO_PROXY"].split(","))

    def test_direct_exec_removes_every_proxy_spelling_and_preserves_exit_status(self):
        environment = os.environ.copy()
        environment.update({key: "http://private-test-token" for key in user_proxy.PROXY_KEYS})
        program = (
            "import os,sys; "
            "assert not any(os.environ.get(k) for k in " + repr(user_proxy.PROXY_KEYS) + "); "
            "assert os.environ['NO_PROXY'] == os.environ['no_proxy'] == '*'; sys.exit(37)"
        )
        result = subprocess.run([str(ROOT / "bin/pto-auth-proxy"), "exec", "--direct", "--",
                                 "python3", "-c", program], env=environment,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 37, result.stderr)
        self.assertNotIn("private-test-token", result.stdout + result.stderr)

    def test_no_proxy_exec_after_stop_or_logout(self):
        for marker in ("authd.stopped", "access.disabled"):
            with self.subTest(marker=marker):
                (self.directory / marker).touch()
                with self.assertRaises(ValueError):
                    user_proxy.proxy_environment({})
                (self.directory / marker).unlink()

    def test_stop_persists_and_start_preserves_credentials_and_preferences(self):
        token = self.directory / "token.sha256"
        token.write_text("digest")
        user_proxy.atomic_write(self.directory / "default-mode", "direct\n")
        with mock.patch.object(user_proxy, "system_managed", return_value=True), \
             mock.patch.object(user_proxy, "stop_compatibility"), \
             mock.patch.object(user_proxy, "authd_ready", return_value=True), \
             mock.patch.object(user_proxy.subprocess, "run",
                               return_value=types.SimpleNamespace(returncode=0)) as run, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(user_proxy.lifecycle("stop"), 0)
            self.assertTrue((self.directory / "authd.stopped").exists())
            self.assertEqual(user_proxy.lifecycle("start"), 0)
            self.assertFalse((self.directory / "authd.stopped").exists())
        self.assertEqual(token.read_text(), "digest")
        self.assertEqual(user_proxy.default_mode(), "direct")
        self.assertEqual(run.call_args_list[0].args[0],
                         ["systemctl", "--no-ask-password", "stop", r"pto-auth-proxy-authd@test\x2duser.service"])
        self.assertEqual(run.call_args_list[1].args[0][2], "start")

    def test_failed_start_restores_persistent_stop(self):
        (self.directory / "authd.stopped").touch()
        with mock.patch.object(user_proxy, "system_managed", return_value=True), \
             mock.patch.object(user_proxy, "stop_compatibility"), \
             mock.patch.object(user_proxy.subprocess, "run",
                               return_value=types.SimpleNamespace(returncode=1)):
            with self.assertRaisesRegex(ValueError, "install-user-controls"):
                user_proxy.lifecycle("start")
        self.assertTrue((self.directory / "authd.stopped").exists())

    def test_restart_never_clears_logout_or_targets_another_user(self):
        (self.directory / "access.disabled").touch()
        with mock.patch.object(user_proxy.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "revoked"):
                user_proxy.lifecycle("restart")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(user_proxy.main(["restart", "other-user"]), 1)
            run.assert_not_called()
        self.assertTrue((self.directory / "access.disabled").exists())

    def test_nonmember_cannot_start_service_or_change_stop_marker(self):
        with mock.patch.object(user_proxy.grp, "getgrnam",
                               return_value=types.SimpleNamespace(gr_gid=456, gr_mem=[])), \
             mock.patch.object(user_proxy.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "authorized"):
                user_proxy.lifecycle("stop")
            run.assert_not_called()
        self.assertFalse((self.directory / "authd.stopped").exists())

    def test_failed_system_manager_does_not_launch_duplicate_watchdog(self):
        with mock.patch.object(user_proxy.subprocess, "run", side_effect=OSError), \
             mock.patch.object(Path, "exists", return_value=True):
            self.assertTrue(user_proxy.system_managed(user_proxy.system_unit()))

    def test_setup_shell_reuses_decoded_legacy_credential_without_rotation(self):
        (self.directory / "secret-uri").write_text("legacy%3Fpassword")
        with mock.patch.object(user_proxy.subprocess, "run",
                               return_value=types.SimpleNamespace(returncode=0)) as run:
            self.assertEqual(user_proxy.setup_shell(), 0)
        self.assertEqual(run.call_args.kwargs["input"], "legacy?password")
        self.assertNotIn("legacy", str(run.call_args.args))

    def test_instance_escape_matches_systemd(self):
        for name in ("alice", "test-user", ".hidden", "user_name", "a.b"):
            self.user.pw_name = name
            expected = subprocess.check_output(
                ["systemd-escape", "--template=pto-auth-proxy-authd@.service", name], text=True).strip()
            self.assertEqual(user_proxy.system_unit(), expected)

    def test_compatibility_cleanup_matches_script_arguments_not_command_text(self):
        process_root = self.home / "proc"
        process_root.mkdir()
        watchdog = str(self.home / ".local/bin/authproxy-watchdog.sh")
        daemon = str(self.home / ".local/bin/authproxy-authd.py")
        arguments = (
            ["bash", watchdog],
            ["python3", daemon],
            ["python3", "other.py", daemon],
            ["bash", "-c", "echo " + watchdog],
            ["python3", str(ROOT / "authd.py")],
        )
        paths = []
        for pid, argv in enumerate(arguments, 110):
            path = process_root / str(pid)
            path.mkdir()
            (path / "cmdline").write_bytes(b"\0".join(os.fsencode(arg) for arg in argv))
            paths.append(path)
        with mock.patch.object(Path, "iterdir", return_value=paths):
            self.assertEqual(user_proxy.compatibility_pids(), [110, 111])


class ShellControlTest(unittest.TestCase):
    def run_shell(self, body, shell=None):
        if shell is None:
            for candidate in ("bash", "zsh"):
                if shutil.which(candidate):
                    with self.subTest(shell=candidate):
                        self.run_shell(body, candidate)
            return
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            (home / ".bashrc").touch()
            environment = {key: value for key, value in os.environ.items()
                           if key not in user_proxy.PROXY_KEYS + ("NO_PROXY", "no_proxy", "XDG_CONFIG_HOME")}
            environment.update(HOME=str(home), SHELL=f"/bin/{shell}")
            subprocess.run(["bash", str(ROOT / "configure-shell.sh"), "testuser"],
                           input="test-secret", text=True, env=environment,
                           capture_output=True, check=True)
            command = [shell, "--noprofile", "--norc", "-c"] if shell == "bash" else [shell, "-f", "-c"]
            result = subprocess.run(command + [body], env=environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn("test-secret", result.stdout + result.stderr)

    def test_switch_restores_values_empty_values_and_unset_variables(self):
        self.run_shell('''
set -eu
export HTTP_PROXY='http://original.invalid:3128'
export HTTPS_PROXY=''
export NO_PROXY='custom.example'
unset ALL_PROXY http_proxy https_proxy all_proxy no_proxy
source "$HOME/.config/pto-auth-proxy/env.sh"
[[ "$HTTP_PROXY" == http://testuser:*@127.0.0.1:20809 ]]
pto-auth-proxy on
source "$HOME/.config/pto-auth-proxy/env.sh"
pto-auth-proxy off
[[ "$HTTP_PROXY" == 'http://original.invalid:3128' ]]
[[ ${HTTPS_PROXY+x} == x && -z "$HTTPS_PROXY" ]]
[[ "$NO_PROXY" == custom.example ]]
[[ ${ALL_PROXY+x}${http_proxy+x}${https_proxy+x}${all_proxy+x}${no_proxy+x} == '' ]]
pto-auth-proxy on
pto-auth-proxy off
[[ "$HTTP_PROXY" == 'http://original.invalid:3128' ]]
''')

    def test_installed_layout_setup_shell_keeps_credential_and_default(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tool = root / "pto-auth-proxy"
            app = tool / "app"
            (app / "bin").mkdir(parents=True)
            component = app / "auth-proxy"
            component.mkdir()
            (tool / "config").mkdir()
            (tool / "config/auth-proxy.env").write_text("PTO_AUTH_PROXY_HTTP_PORT=20909\n")
            shutil.copy2(ROOT / "bin/pto-auth-proxy", app / "bin/pto-auth-proxy")
            for file in ("user_proxy.py", "configure-shell.sh", "shell-integration.sh"):
                shutil.copy2(ROOT / file, component / file)
            home = root / "home"
            settings = home / ".config/pto-auth-proxy"
            settings.mkdir(parents=True)
            (home / ".bashrc").touch()
            (settings / "secret-uri").write_text("legacy%3Fcredential")
            (settings / "default-mode").write_text("direct\n")
            environment = os.environ.copy()
            environment.pop("XDG_CONFIG_HOME", None)
            environment.update(HOME=str(home), SHELL="/bin/bash")
            command = str(app / "bin/pto-auth-proxy")
            result = subprocess.run([command, "setup-shell"], env=environment,
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((settings / "secret-uri").read_text(), "legacy%3Fcredential")
            self.assertEqual((settings / "default-mode").read_text(), "direct\n")
            self.assertIn(str(app / "bin/pto-auth-proxy"), (settings / "env.sh").read_text())
            self.assertEqual(json.loads((settings / "endpoints.json").read_text())["http_port"], 20909)
            self.assertNotIn("legacy%3Fcredential", result.stdout + result.stderr)

    def test_persistent_direct_default_clears_inherited_pto_proxy(self):
        self.run_shell('''
set -eu
source "$HOME/.config/pto-auth-proxy/env.sh"
pto-auth-proxy off --default
[[ -z ${HTTP_PROXY+x} ]]
source "$HOME/.config/pto-auth-proxy/env.sh"
[[ -z ${HTTP_PROXY+x} ]]
pto-auth-proxy on
bash --noprofile --norc -c 'source "$HOME/.config/pto-auth-proxy/env.sh"; [[ -z ${HTTP_PROXY+x}${ALL_PROXY+x} ]]'
pto-auth-proxy on --default
[[ $(cat "$HOME/.config/pto-auth-proxy/default-mode") == proxy ]]
pto-auth-proxy off
''')

    def test_catch_all_bypass_is_removed_on_and_restored_off(self):
        self.run_shell('''
set -eu
export NO_PROXY='*,*.internal,*,custom.example,*'
source "$HOME/.config/pto-auth-proxy/env.sh"
[[ ",$NO_PROXY," != *',*,'* ]]
[[ ",$NO_PROXY," == *',*.internal,'* ]]
pto-auth-proxy off
[[ "$NO_PROXY" == '*,*.internal,*,custom.example,*' ]]
''')

    def test_switch_does_not_leak_credentials_under_xtrace(self):
        self.run_shell('''
set -eux
source "$HOME/.config/pto-auth-proxy/env.sh"
pto-auth-proxy off
pto-auth-proxy on
pto-auth-proxy off
''')

    @unittest.skipUnless(shutil.which("zsh"), "zsh is not installed")
    def test_zsh_switch(self):
        self.run_shell('''
set -eu
export HTTP_PROXY='http://original.invalid:3128'
source "$HOME/.config/pto-auth-proxy/env.sh"
pto-auth-proxy off
[[ "$HTTP_PROXY" == 'http://original.invalid:3128' ]]
pto-auth-proxy on
pto-auth-proxy off --default
''', "zsh")


@unittest.skipUnless(shutil.which("node"), "node is needed for the polkit rule harness")
class PolkitRuleTest(unittest.TestCase):
    def test_only_own_instance_and_allowed_verbs_are_authorized(self):
        policy = (ROOT / "config/50-pto-auth-proxy-self.rules.in").read_text().replace("@PROXY_GROUP@", "proxyusers")
        program = '''
const assert = require('assert');
let rule;
const polkit = { Result: {YES:'yes', NOT_HANDLED:'unhandled'}, addRule: fn => rule = fn };
''' + policy + '''
function call(user, member, unit, verb, id='org.freedesktop.systemd1.manage-units') {
    return rule({id, lookup: name => ({unit, verb})[name]},
                {user, isInGroup: group => group === 'proxyusers' && member});
}
for (const verb of ['start','stop','restart']) {
    assert.equal(call('alice', true, 'pto-auth-proxy-authd@alice.service', verb), 'yes');
    assert.equal(call('test-user', true, 'pto-auth-proxy-authd@test\\\\x2duser.service', verb), 'yes');
    assert.equal(call('alice', true, 'pto-auth-proxy-authd@bob.service', verb), 'unhandled');
    assert.equal(call('alice', false, 'pto-auth-proxy-authd@alice.service', verb), 'unhandled');
    for (const unit of ['pto-auth-proxy.service','pto-auth-proxy-egress-guard.service','ssh.service'])
        assert.equal(call('alice', true, unit, verb), 'unhandled');
}
assert.equal(call('alice', true, 'pto-auth-proxy-authd@alice.service', 'set-property'), 'unhandled');
assert.equal(call('alice', true, 'pto-auth-proxy-authd@alice.service', 'start',
                  'org.freedesktop.systemd1.manage-unit-files'), 'unhandled');
'''
        subprocess.run(["node", "-e", program], check=True, capture_output=True)
