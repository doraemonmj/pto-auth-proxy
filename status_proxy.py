#!/usr/bin/env python3
"""One-line readiness check for an auth-proxy user."""
from __future__ import annotations

import base64
import grp
import json
import os
import pwd
import socket
import subprocess
import ssl
import sys

import user_proxy
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit


TIMEOUT = 5


def group_member(user: str, group_name: str) -> bool:
    try:
        account = pwd.getpwnam(user)
        group = grp.getgrnam(group_name)
    except KeyError:
        return False
    return account.pw_gid == group.gr_gid or user in group.gr_mem


def authd_capability(user: str) -> tuple[bool, str]:
    try:
        uid = pwd.getpwnam(user).pw_uid
    except KeyError:
        return False, "down"
    candidates = (
        f"/run/pto-auth-proxy/{uid}/authd.sock",
        f"/tmp/authproxy-{user}.sock",
    )
    for path in candidates:
        if not os.path.exists(path):
            continue
        try:
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(TIMEOUT)
                client.connect(path)
                request = json.dumps({"op": "capabilities"}) + "\n"
                client.sendall(request.encode())
                response = json.loads(client.recv(4096).decode())
            capabilities = response.get("capabilities", [])
            return True, "token" if "token-v1" in capabilities else "legacy"
        except (OSError, ValueError, json.JSONDecodeError):
            continue
    return False, "down"


def proxy_url(user: str, host: str, port: int) -> tuple[str | None, str]:
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        value = os.environ.get(name, "")
        try:
            parsed = urlsplit(value)
            parsed.port  # Access may itself raise on malformed URLs.
        except ValueError:
            continue
        if parsed.scheme == "http" \
                and parsed.hostname in {host, "localhost"} and parsed.port == port \
                and parsed.username and parsed.password and unquote(parsed.username) == user:
            return value, "env"

    xdg_config_home = os.environ.get("XDG_CONFIG_HOME", "")
    config_home = Path(xdg_config_home) if xdg_config_home \
        else Path.home() / ".config"
    candidates = [
        config_home / "pto-auth-proxy" / "secret-uri",
        Path.home() / ".proxy-secret-uri",
    ]
    url_host = f"[{host}]" if ":" in host else host
    for secret_file in candidates:
        try:
            secret_uri = secret_file.read_text(encoding="ascii").strip()
        except OSError:
            continue
        if secret_uri:
            return (f"http://{quote(user, safe='')}:{secret_uri}@"
                    f"{url_host}:{port}"), "file"
    return None, "missing"


def authenticated_connect(url: str, target: str = "api.github.com:443") -> str:
    parsed = urlsplit(url)
    if not parsed.hostname or not parsed.port or parsed.username is None \
            or parsed.password is None:
        return "bad-url"
    credentials = f"{unquote(parsed.username)}:{unquote(parsed.password)}"
    authorization = base64.b64encode(credentials.encode()).decode("ascii")
    request = (
        f"CONNECT {target} HTTP/1.1\r\n"
        f"Host: {target}\r\n"
        f"Proxy-Authorization: Basic {authorization}\r\n"
        "Connection: close\r\n\r\n"
    )
    try:
        with socket.create_connection((parsed.hostname, parsed.port), TIMEOUT) as client:
            client.settimeout(TIMEOUT)
            client.sendall(request.encode("ascii"))
            response = b""
            while b"\r\n" not in response and len(response) < 4096:
                chunk = client.recv(1024)
                if not chunk:
                    break
                response += chunk
    except OSError:
        return "down"
    try:
        return response.split(b"\r\n", 1)[0].split()[1].decode("ascii")
    except (IndexError, UnicodeDecodeError):
        return "bad-response"


def direct_access_is_correct(user: str, owner: str, host: str,
                             ports: tuple[int, ...]) -> bool:
    expected_open = user == owner
    for port in ports:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as client:
            client.settimeout(1)
            is_open = client.connect_ex((host, port)) == 0
        if is_open != expected_open:
            return False
    return True


def guard_service_active() -> bool:
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "--quiet",
             "pto-auth-proxy-egress-guard.service"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=TIMEOUT, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def guard_ports(upstream_port: int) -> tuple[int, ...]:
    raw = os.environ.get("PTO_AUTH_PROXY_GUARD_PORTS") or str(upstream_port)
    try:
        ports = tuple(int(value) for value in raw.split(","))
    except ValueError:
        return ()
    if not ports or any(port < 1 or port > 65535 for port in ports):
        return ()
    return ports


def access_disabled() -> bool:
    return (Path.home() / ".config" / "pto-auth-proxy" /
            "access.disabled").exists()


def shell_mode(host: str, http_port: int, socks_port: int) -> str:
    present = [key for key in user_proxy.PROXY_KEYS if os.environ.get(key)]
    if not present:
        return "direct"
    ours = []
    for key in present:
        try:
            url = urlsplit(os.environ[key])
            expected_port = socks_port if key.lower() == "all_proxy" else http_port
            expected_scheme = "socks5h" if key.lower() == "all_proxy" else "http"
            ours.append(url.hostname in {host, "localhost"} and url.port == expected_port
                        and url.scheme == expected_scheme and url.username is not None)
        except ValueError:
            ours.append(False)
    if not any(ours):
        return "external"
    if any("*" in os.environ.get(key, "").split(",") for key in ("NO_PROXY", "no_proxy")):
        return "bypassed"
    return "proxy" if all(ours) and len(present) == len(user_proxy.PROXY_KEYS) else "mixed"


def https_probe(url: str) -> str:
    """Verify TLS with the normal system trust store through authenticated CONNECT."""
    parsed = urlsplit(url)
    credentials = f"{unquote(parsed.username or '')}:{unquote(parsed.password or '')}"
    authorization = base64.b64encode(credentials.encode()).decode("ascii")
    request = ("CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n"
               f"Proxy-Authorization: Basic {authorization}\r\n\r\n")
    try:
        with socket.create_connection((parsed.hostname, parsed.port), TIMEOUT) as client:
            client.settimeout(TIMEOUT)
            client.sendall(request.encode("ascii"))
            header = b""
            while b"\r\n\r\n" not in header and len(header) < 16384:
                chunk = client.recv(1)
                if not chunk:
                    return "bad-connect"
                header += chunk
            if header.split(b"\r\n", 1)[0].split()[1] != b"200":
                return "connect-failed"
            with ssl.create_default_context().wrap_socket(client, server_hostname="api.github.com") as tls:
                tls.sendall(b"HEAD / HTTP/1.1\r\nHost: api.github.com\r\nUser-Agent: pto-auth-proxy-doctor\r\nConnection: close\r\n\r\n")
                response = b""
                while b"\r\n" not in response and len(response) < 4096:
                    chunk = tls.recv(1024)
                    if not chunk:
                        break
                    response += chunk
                status = int(response.split(b"\r\n", 1)[0].split()[1])
                # HTTP errors (e.g. API rate limit) still prove verified TLS reachability.
                return "ok" if 100 <= status <= 599 else "bad-http"
    except ssl.SSLError:
        return "tls-failed"
    except (OSError, ValueError, IndexError):
        return "unreachable"


def git_proxy_configured() -> bool:
    try:
        result = subprocess.run(
            ["git", "config", "--get-regexp", r"^(http(\..*)?\.proxy|remote\..*\.proxy)$"],
            capture_output=True, timeout=TIMEOUT, check=False)
        return result.returncode == 0 and bool(result.stdout)
    except (OSError, subprocess.SubprocessError):
        return False


def main(command: str = "status") -> int:
    user = pwd.getpwuid(os.getuid()).pw_name
    group_name = os.environ.get("PTO_AUTH_PROXY_GROUP", "proxyusers")
    owner = os.environ.get("PTO_AUTH_PROXY_OWNER", "pypto")
    host = os.environ.get("PTO_AUTH_PROXY_LISTEN_HOST", "127.0.0.1")
    port = int(os.environ.get("PTO_AUTH_PROXY_HTTP_PORT", "20809"))
    socks_port = int(os.environ.get("PTO_AUTH_PROXY_SOCKS_PORT", "20808"))
    upstream_host = os.environ.get("PTO_AUTH_PROXY_UPSTREAM_HOST", "127.0.0.1")
    disabled = access_disabled()
    stopped = (user_proxy.access_dir() / "authd.stopped").exists()
    member_ok = group_member(user, group_name)
    authd_ok, authd_mode = authd_capability(user)
    url, config_source = proxy_url(user, host, port)
    mode = shell_mode(host, port, socks_port)
    try:
        default = user_proxy.default_mode()
    except (OSError, ValueError):
        default = "invalid"
    state = "LEFT" if disabled else "STOPPED" if stopped else "CONFIGURED" if url else "NOT_JOINED"
    print(f"{state}: shell={mode} default={default} "
          f"group={'ok' if member_ok else 'missing'} authd={authd_mode} credential={config_source}")
    pending = Path(os.environ.get("PTO_AUTH_PROXY_TOOL_DIR", ".")) / "update/pending-activation"
    if pending.is_file():
        print("update=pending-activation; a service restart may load staged code")
    if command == "status":
        # No external connections; a deliberately direct/stopped user is not a fault.
        print("Use pto-auth-proxy doctor for shared proxy, upstream and HTTPS checks.")
        return 0
    try:
        upstream_port = int(os.environ.get("PTO_AUTH_PROXY_UPSTREAM_PORT", ""))
        if not 1 <= upstream_port <= 65535:
            raise ValueError
    except ValueError:
        print("NOT_READY: upstream=unconfigured; set PTO_AUTH_PROXY_UPSTREAM_PORT (administrator)")
        return 1
    protected_ports = guard_ports(upstream_port)
    if disabled or stopped:
        connect_status = "disabled" if disabled else "stopped"
    else:
        connect_status = authenticated_connect(url) if url else "no-credential"
    guard_service_ok = guard_service_active()
    direct_ok = bool(protected_ports) and direct_access_is_correct(user, owner, upstream_host, protected_ports)
    coverage_ok = upstream_port in protected_ports
    guard_ok = guard_service_ok and direct_ok and coverage_ok
    tls_state = https_probe(url) if connect_status == "200" else "skipped"
    ready = member_ok and authd_ok and connect_status == "200" and guard_ok and tls_state == "ok"
    result = "READY" if ready else "LEFT" if disabled else "STOPPED" if stopped else "NOT_READY"
    if not guard_service_ok:
        guard_state = "service-down"
    elif not coverage_ok:
        guard_state = "upstream-unprotected"
    elif not direct_ok:
        guard_state = "rule-wrong"
    else:
        guard_state = "owner-allowed" if user == owner else "blocked"
    print(f"{result}: proxy={connect_status} https={tls_state} guard={guard_state} "
          f"upstream={upstream_host}:{upstream_port}")
    if disabled:
        print("Next: pto-auth-proxy join (interactive local password entry).")
    elif stopped:
        print("Next: pto-auth-proxy start.")
    elif not member_ok:
        print("Next: ask the administrator to authorize group membership.")
    elif not authd_ok:
        print("Next: pto-auth-proxy restart (only your authd).")
    elif connect_status == "407" or not url:
        print("Next: pto-auth-proxy join to repair your credential locally.")
    elif connect_status == "502":
        print("Next: ask the administrator to inspect the upstream SOCKS service/tunnel.")
    elif connect_status == "403":
        print("Next: ask the administrator to inspect the whitelist for the diagnostic target api.github.com.")
    elif connect_status != "200":
        print("Next: ask the administrator to inspect the shared proxy listener.")
    elif tls_state != "ok":
        print("Next: check upstream reachability and the system TLS trust store.")
    if not guard_ok:
        print("Next: ask the administrator to inspect the egress guard; do not bypass it.")
    if git_proxy_configured():
        print("git=explicit-proxy-config; environment switches may not override Git settings (values redacted).")
    print("Existing applications keep their environment; use a new process or Reload Window when appropriate.")
    return 0 if ready else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "status"))
