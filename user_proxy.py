#!/usr/bin/env python3
"""Current-user controls. Never accepts a target user or prints proxy URLs."""
from __future__ import annotations

import fcntl
import grp
import json
import os
from pathlib import Path
import pwd
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
from urllib.parse import quote, unquote

PROXY_KEYS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
              "http_proxy", "https_proxy", "all_proxy")


def account():
    return pwd.getpwuid(os.getuid())


def access_dir() -> Path:
    # authd deliberately uses the account database, independently of XDG/HOME.
    return Path(account().pw_dir) / ".config" / "pto-auth-proxy"


def config_dir() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "pto-auth-proxy"


def atomic_write(path: Path, value: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".control-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(value)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def default_mode() -> str:
    try:
        mode = (config_dir() / "default-mode").read_text().strip()
    except FileNotFoundError:
        return "auto"  # Explicit saved proxy/direct preferences remain unchanged.
    if mode not in {"auto", "proxy", "direct"}:
        raise ValueError("invalid default-mode; use auto/on/off --default")
    return mode


def credential() -> str:
    if (access_dir() / "access.disabled").exists():
        raise ValueError("proxy access was revoked; run pto-auth-proxy join locally")
    if (access_dir() / "authd.stopped").exists():
        raise ValueError("your authd is stopped; run pto-auth-proxy start")
    try:
        secret = (config_dir() / "secret-uri").read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        raise ValueError("no proxy credential; run pto-auth-proxy join locally") from None
    if not secret or any(c.isspace() or c in "@:/" for c in secret):
        raise ValueError("invalid proxy credential file; run pto-auth-proxy join locally")
    return secret


def proxy_environment(environment: dict[str, str], mode: str = "proxy") -> dict[str, str]:
    secret = credential()
    try:
        endpoints = json.loads((config_dir() / "endpoints.json").read_text())
        host = endpoints["host"]
        http_port = int(endpoints["auto_http_port" if mode == "auto" else "http_port"])
        socks_port = int(endpoints["auto_socks_port" if mode == "auto" else "socks_port"])
        if not isinstance(host, str) or not host or any(c in host for c in "/@\r\n"):
            raise ValueError
        if not (1 <= http_port <= 65535 and 1 <= socks_port <= 65535):
            raise ValueError
    except (OSError, ValueError, KeyError, TypeError):
        raise ValueError("missing/invalid endpoints; run pto-auth-proxy setup-shell") from None
    host = f"[{host}]" if ":" in host else host
    user = quote(account().pw_name, safe="")
    result = environment.copy()
    for name in PROXY_KEYS:
        scheme, port = ("socks5h", socks_port) if name.lower() == "all_proxy" else ("http", http_port)
        result[name] = f"{scheme}://{user}:{secret}@{host}:{port}"
    bypass = ([value for value in result.get("NO_PROXY", result.get("no_proxy", "")).split(",")
               if value and value != "*"] if mode == "auto" else [])
    for value in ("localhost", "127.0.0.1", "127.0.0.0/8", "::1", "169.254.169.254", "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"):
        if value not in bypass:
            bypass.append(value)
    result["NO_PROXY"] = result["no_proxy"] = ",".join(bypass)
    return result


def exec_command(args: list[str]) -> int:
    if args and args[0] == "--":
        args = ["--auto", *args]
    if len(args) < 3 or args[0] not in {"--auto", "--direct", "--proxy"} or args[1] != "--":
        raise ValueError("usage: pto-auth-proxy exec [--auto|--direct|--proxy] -- COMMAND [ARGS]")
    environment = os.environ.copy()
    if args[0] == "--direct":
        for name in PROXY_KEYS:
            environment.pop(name, None)
        environment["NO_PROXY"] = environment["no_proxy"] = "*"
    else:
        environment = proxy_environment(environment, mode=args[0][2:])
    try:
        os.execvpe(args[2], args[2:], environment)
    except FileNotFoundError:
        print("command not found", file=sys.stderr)
        return 127
    except OSError:
        print("cannot execute command", file=sys.stderr)
        return 126


def setup_shell() -> int:
    """Upgrade an existing enrollment without PAM or token rotation."""
    try:
        secret = (config_dir() / "secret-uri").read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        raise ValueError("no proxy credential; run pto-auth-proxy join locally") from None
    if not secret:
        raise ValueError("no proxy credential; run pto-auth-proxy join locally")
    result = subprocess.run(["bash", str(Path(__file__).parent / "configure-shell.sh"), account().pw_name],
                            input=unquote(secret), text=True, check=False)
    return result.returncode


def system_unit() -> str:
    name = account().pw_name
    instance = "".join(chr(byte) if (chr(byte).isascii() and
                       (chr(byte).isalnum() or chr(byte) in "_:.") and
                       not (index == 0 and byte == ord(".")))
                       else f"\\x{byte:02x}" for index, byte in enumerate(name.encode()))
    return f"pto-auth-proxy-authd@{instance}.service"


def system_managed(unit: str) -> bool:
    try:
        result = subprocess.run(["systemctl", "show", "--property=LoadState", "--value", unit],
                                capture_output=True, text=True, timeout=5, check=False)
        if result.returncode == 0 and result.stdout.strip() == "loaded":
            return True
    except (OSError, subprocess.SubprocessError):
        pass
    # A temporarily unavailable manager is not permission to launch a duplicate.
    return any((Path(root) / "pto-auth-proxy-authd@.service").exists()
               for root in ("/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"))


def compatibility_pids() -> list[int]:
    """Match exact per-home executable paths, never arbitrary command substrings."""
    home_bin = Path(account().pw_dir) / ".local" / "bin"
    watchdog = str(home_bin / "authproxy-watchdog.sh")
    daemon = str(home_bin / "authproxy-authd.py")
    result = []
    for path in Path("/proc").iterdir():
        if not path.name.isdigit():
            continue
        try:
            if path.stat().st_uid != os.getuid():
                continue
            argv = path.joinpath("cmdline").read_bytes().split(b"\0")
            if len(argv) < 2:
                continue
            interpreter = Path(os.fsdecode(argv[0])).name
            script = os.fsdecode(argv[1])
            # Reading/printing the script is not the same as executing it.
            if ((script == watchdog and interpreter == "bash") or
                    (script == daemon and re.fullmatch(r"python3(?:\.\d+)?", interpreter))):
                result.append(int(path.name))
        except (OSError, ValueError):
            continue
    return result


def stop_compatibility() -> None:
    # PAM workers can delay process exit. Do not launch a replacement until all
    # matching processes have left; re-scan for children spawned during shutdown.
    deadline = time.monotonic() + 10
    signalled = set()
    while True:
        pids = compatibility_pids()
        if not pids:
            return
        if time.monotonic() >= deadline:
            raise ValueError("compatibility authd is still stopping; retry shortly")
        for pid in pids:
            if pid in signalled:
                continue
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            signalled.add(pid)
        time.sleep(0.1)


def authd_ready() -> bool:
    paths = (f"/run/pto-auth-proxy/{os.getuid()}/authd.sock",
             f"/tmp/authproxy-{account().pw_name}.sock")
    for path in paths:
        try:
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(0.3)
                client.connect(path)
                client.sendall(b'{"op":"capabilities"}\n')
                reply = json.loads(client.recv(4096))
                # Pre-capabilities daemons still answer a well-formed self-call
                # with wrong-user/unsupported-op. No credential is needed here.
                if reply.get("ok") or reply.get("code") in {-1, -7}:
                    return True
        except (OSError, ValueError):
            continue
    return False


def lifecycle(action: str) -> int:
    user = account()
    group = grp.getgrnam(os.environ.get("PTO_AUTH_PROXY_GROUP", "proxyusers"))
    if user.pw_gid != group.gr_gid and user.pw_name not in group.gr_mem:
        raise ValueError("not an authorized proxy group member; contact the administrator")
    directory = access_dir()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (directory / "control.lock").open("a") as lock:
        os.chmod(lock.name, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("another personal service operation is running; retry shortly") from None
        stopped = directory / "authd.stopped"
        was_stopped = stopped.exists()
        if action != "stop" and (directory / "access.disabled").exists():
            raise ValueError("proxy access was revoked; run pto-auth-proxy join locally")
        if action == "stop":
            # Also deny new auth if the manager is unavailable or a legacy daemon survives.
            atomic_write(stopped, "stopped by current user\n")
        else:
            stopped.unlink(missing_ok=True)
            tool_dir = os.environ.get("PTO_AUTH_PROXY_TOOL_DIR")
            if tool_dir and (Path(tool_dir) / "update/pending-activation").is_file():
                print("update=pending-activation; starting your authd may load staged code.")
        try:
            unit = system_unit()
            managed = system_managed(unit)
            if managed:
                stop_compatibility()
                result = subprocess.run(["systemctl", "--no-ask-password", action, unit],
                                        capture_output=True, timeout=20, check=False)
                if result.returncode:
                    raise ValueError("cannot control your authd; ask the administrator to install "
                                     "user controls with scripts/install.sh --install-user-controls")
            else:
                if action in {"stop", "restart"}:
                    stop_compatibility()
                if action != "stop" and not compatibility_pids():
                    watchdog = Path(user.pw_dir) / ".local/bin/authproxy-watchdog.sh"
                    if not watchdog.is_file():
                        raise ValueError("no authd service or compatibility watchdog; run pto-auth-proxy join locally")
                    log_path = Path(user.pw_dir) / ".local/authproxy-authd.log"
                    with log_path.open("ab") as log:
                        subprocess.Popen(["bash", str(watchdog)], stdin=subprocess.DEVNULL,
                                         stdout=log, stderr=log, start_new_session=True, close_fds=True)
            if action != "stop":
                deadline = time.monotonic() + 8
                while not authd_ready():
                    if time.monotonic() >= deadline:
                        raise ValueError("your authd did not become ready; run pto-auth-proxy doctor")
                    time.sleep(0.2)
        except (OSError, subprocess.SubprocessError, ValueError):
            if was_stopped:
                atomic_write(stopped, "stopped; previous start/restart failed\n")
            raise
    if action == "stop":
        print("STOPPED: your authd; new authentication is disabled across reboot. Existing connections continue.")
    else:
        print(f"READY: your authd ({action}); credentials and shell mode were preserved.")
    return 0


def main(args: list[str] | None = None) -> int:
    args = sys.argv[1:] if args is None else args
    try:
        command, *rest = args
        if command == "exec":
            return exec_command(rest)
        if command == "setup-shell" and not rest:
            return setup_shell()
        if command == "stop-compatibility" and not rest:
            stop_compatibility()
            return 0
        if command == "shell-ready" and not rest:
            credential()
            return 0
        if command == "restore" and not rest:
            raise ValueError("restore requires shell integration; source your env.sh")
        if command in {"auto", "on", "off"}:
            if rest not in ([], ["--default"]):
                raise ValueError(f"usage: pto-auth-proxy {command} [--default]")
            if command in {"auto", "on"}:
                credential()
            if rest:
                mode = {"auto": "auto", "on": "proxy", "off": "direct"}[command]
                atomic_write(config_dir() / "default-mode", mode + "\n")
                print(f"Future shells: {mode}.")
                print("This process cannot change the parent shell; run setup-shell, then source your env.sh.")
                return 0
            raise ValueError("shell integration is not loaded; run pto-auth-proxy setup-shell, then source "
                             '"${XDG_CONFIG_HOME:-$HOME/.config}/pto-auth-proxy/env.sh" '
                             "or use pto-auth-proxy exec")
        if command in {"start", "stop", "restart"} and not rest:
            return lifecycle(command)
        raise ValueError("invalid user control command or arguments")
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        # These messages are controlled here; no subprocess output/proxy environment is printed.
        if isinstance(error, ValueError):
            print(str(error), file=sys.stderr)
        else:
            print("user control failed; run pto-auth-proxy doctor or contact the administrator", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
