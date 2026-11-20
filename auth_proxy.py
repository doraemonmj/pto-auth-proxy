#!/usr/bin/env python3
"""SOCKS5 auth proxy — PAM-authenticated, group-gated, whitelist-filtered.

Runs on shared Linux hosts. Users authenticate through their per-user authd.
Only members of PROXY_GROUP are allowed in, even with correct credentials.
Auto listeners route selected domains through an explicitly configured SOCKS5
upstream and other public HTTP(S) targets directly. Forced proxy listeners retain
whitelist-only upstream access. All forwarding requires user authentication.

Per-connection facts append to stats.jsonl; a plain text log lands in
auth_proxy.log. SIGHUP reloads the whitelist file (if present); SIGTERM/INT
stop cleanly.

Dependencies: Python 3 stdlib + libpam.so.0 (present on any Linux with PAM).
"""
from __future__ import annotations
import asyncio
import fnmatch
from functools import partial
import grp
import ipaddress
import json
import os
import pwd
import signal
import socket
import struct
import sys
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit
# NOTE: this proxy no longer imports the pam module directly. Cross-user PAM
# verification is refused by unix_chkpwd on openEuler for unprivileged
# callers, so we delegate password checks to a per-user authd daemon (see
# authd.py). pam_check_async() below opens the target user's private
# /run/user/<uid>/authproxy-authd.sock and asks THAT daemon to run PAM.

# ---- config knobs --------------------------------------------------------
def _env_port(name: str, default: Optional[int] = None) -> int:
    raw = os.environ.get(name, "" if default is None else str(default))
    if not raw:
        raise SystemExit(f"{name} must be explicitly configured; no default upstream port")
    try:
        value = int(raw)
    except ValueError as exc:
        raise SystemExit(f"{name} must be an integer, got {raw!r}") from exc
    if not 1 <= value <= 65535:
        raise SystemExit(f"{name} must be between 1 and 65535, got {value}")
    return value


def _env_seconds(name: str, default: float) -> float:
    raw = os.environ.get(name, str(default))
    try:
        value = float(raw)
    except ValueError as exc:
        raise SystemExit(f"{name} must be a number, got {raw!r}") from exc
    if not 0.1 <= value <= 300:
        raise SystemExit(f"{name} must be between 0.1 and 300 seconds, got {value}")
    return value


BASE_DIR       = Path(os.environ.get("AUTHPROXY_DIR",
                                     Path.home() / "auth-proxy")).resolve()
WHITELIST_FILE = Path(os.environ.get(
    "PTO_AUTH_PROXY_WHITELIST", BASE_DIR / "whitelist.txt")).resolve()
PROXY_DOMAINS_FILE = Path(os.environ.get(
    "PTO_AUTH_PROXY_PROXY_DOMAINS") or WHITELIST_FILE.with_name("proxy-domains.txt")).resolve()
STATS_FILE     = Path(os.environ.get(
    "PTO_AUTH_PROXY_STATS_FILE", BASE_DIR / "stats.jsonl")).resolve()
LOG_FILE       = Path(os.environ.get(
    "PTO_AUTH_PROXY_LOG_FILE", BASE_DIR / "auth_proxy.log")).resolve()
ALERTS_FILE    = Path(os.environ.get(
    "PTO_AUTH_PROXY_ALERTS_FILE", BASE_DIR / "alerts.jsonl")).resolve()
REPORTS_DIR    = Path(os.environ.get(
    "PTO_AUTH_PROXY_REPORTS_DIR", BASE_DIR / "reports")).resolve()

# ---- anomaly-detection thresholds (see anomaly_scan()) -------------------
WINDOW_SECONDS         = 300     # rolling window we look at
SCAN_INTERVAL_SECONDS  = 60      # how often we scan
ANOMALY_BYTES_UP       = 100 * 1024 * 1024   # >100 MB up in one window
ANOMALY_QPS_THRESHOLD  = 20                  # per-user sustained rate
ANOMALY_AUTHFAIL_COUNT = 20                  # auth failures in one window
ANOMALY_DENY_COUNT     = 30                  # non-whitelist attempts in one window
# ---- daily report ---------------------------------------------------------
REPORT_HOUR   = 0                # 00:05 local time
REPORT_MINUTE = 5
# --------------------------------------------------------------------------

LISTEN_HOST    = os.environ.get("PTO_AUTH_PROXY_LISTEN_HOST", "127.0.0.1")
LISTEN_PORT    = _env_port("PTO_AUTH_PROXY_SOCKS_PORT", 20808)
HTTP_LISTEN_PORT = _env_port("PTO_AUTH_PROXY_HTTP_PORT", 20809)
AUTO_SOCKS_PORT = _env_port("PTO_AUTH_PROXY_AUTO_SOCKS_PORT", 20810)
AUTO_HTTP_PORT = _env_port("PTO_AUTH_PROXY_AUTO_HTTP_PORT", 20811)
DIRECT_PORTS = {int(value) for value in os.environ.get("PTO_AUTH_PROXY_DIRECT_PORTS", "80,443").split(",")}
if not DIRECT_PORTS or any(not 1 <= port <= 65535 for port in DIRECT_PORTS):
    raise SystemExit("PTO_AUTH_PROXY_DIRECT_PORTS must contain valid ports")
# Every allowed business connection is chained through this SOCKS5 endpoint.
# The endpoint may be a local SOCKS5 service or an SSH RemoteForward.
# Do not infer the backend implementation or silently choose a legacy port.
UPSTREAM_HOST  = os.environ.get("PTO_AUTH_PROXY_UPSTREAM_HOST", "127.0.0.1")
UPSTREAM_PORT  = _env_port("PTO_AUTH_PROXY_UPSTREAM_PORT")
PROXY_OWNER    = os.environ.get("PTO_AUTH_PROXY_OWNER", "pypto")
PROXY_GROUP    = os.environ.get("PTO_AUTH_PROXY_GROUP", "proxyusers")
PAM_SERVICE    = os.environ.get("PTO_AUTH_PROXY_PAM_SERVICE", "sshd")
CLIENT_HANDSHAKE_TIMEOUT = _env_seconds(
    "PTO_AUTH_PROXY_CLIENT_HANDSHAKE_TIMEOUT", 15)
UPSTREAM_CONNECT_TIMEOUT = _env_seconds(
    "PTO_AUTH_PROXY_UPSTREAM_CONNECT_TIMEOUT", 5)
UPSTREAM_HANDSHAKE_TIMEOUT = _env_seconds(
    "PTO_AUTH_PROXY_UPSTREAM_HANDSHAKE_TIMEOUT", 10)
RELAY_HALF_CLOSE_TIMEOUT = _env_seconds(
    "PTO_AUTH_PROXY_RELAY_HALF_CLOSE_TIMEOUT", 30)
CLOSE_TIMEOUT = _env_seconds("PTO_AUTH_PROXY_CLOSE_TIMEOUT", 2)

DEFAULT_WHITELIST = [
    # Anthropic / Claude
    "anthropic.com", "*.anthropic.com",
    "claude.ai",     "*.claude.ai",
    "claude.com",    "*.claude.com",
    # OpenAI / Codex / ChatGPT
    "openai.com",         "*.openai.com",
    "chatgpt.com",        "*.chatgpt.com",
    "oaistatic.com",      "*.oaistatic.com",
    "oaiusercontent.com", "*.oaiusercontent.com",
    # GitHub
    "github.com",              "*.github.com",
    "githubusercontent.com",   "*.githubusercontent.com",
    "githubassets.com",        "*.githubassets.com",
    "codeload.github.com",
    # npm (needed if users npm install through the proxy)
    "npmjs.org", "*.npmjs.org",
    "npmjs.com", "*.npmjs.com",
    # Google (broad)
    "google.com",           "*.google.com",
    "googleapis.com",       "*.googleapis.com",
    "gstatic.com",          "*.gstatic.com",
    "googleusercontent.com","*.googleusercontent.com",
    "gvt1.com",             "*.gvt1.com",
]
# IP literals that are always allowed (localhost variants -- Claude Code
# uses these for its OAuth callback server).
ALLOW_IPS_DEFAULT = {"127.0.0.1", "::1"}

_whitelist: list[str] = []
_group_members: set[str] = set()
_group_mtime = 0.0


# ============================================================
# PAM via per-user authd (no privilege needed by this proxy)
# ============================================================
# The proxy runs as pypto and cannot verify other users' passwords itself
# (unix_chkpwd refuses cross-user requests). Instead, each proxyusers member
# runs their own authd daemon that listens on a private unix socket
# /run/user/<their-uid>/authproxy-authd.sock (mode 0600). We connect there.
# Because only that user can create/write that socket, the reply is trusted.

import json as _json_pam  # avoid shadowing the top-level import


async def pam_check_async(user: str, password: str) -> bool:
    """Ask user's own authd to verify their Linux password."""
    try:
        pwent = pwd.getpwnam(user)
    except KeyError:
        log(f"pam_check_async: unknown user {user!r}")
        return False

    # System-managed authd instances use a root-created per-user directory.
    # Keep the /tmp location as a compatibility fallback for old joins.
    socket_candidates = (
        f"/run/pto-auth-proxy/{pwent.pw_uid}/authd.sock",
        f"/tmp/authproxy-{user}.sock",
    )
    sock_path = None
    r = w = None
    connect_errors = []
    for candidate in socket_candidates:
        if not os.path.exists(candidate):
            continue
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_unix_connection(candidate), timeout=3)
            sock_path = candidate
            break
        except (OSError, asyncio.TimeoutError) as exc:
            connect_errors.append(f"{candidate}: {exc}")

    if sock_path is None:
        log(f"pam_check_async: {user}'s authd not running "
            f"({'; '.join(connect_errors) if connect_errors else 'missing sockets'})")
        return False
    assert r is not None and w is not None

    try:
        # Verify the socket really is owned by the claimed user.
        try:
            st = os.stat(sock_path)
            if st.st_uid != pwent.pw_uid:
                log(f"pam_check_async: SPOOF? {sock_path} owned by uid={st.st_uid}"
                    f" but user {user!r} has uid={pwent.pw_uid}")
                return False
        except OSError:
            pass

        req = _json_pam.dumps({"user": user, "pass": password}) + "\n"
        w.write(req.encode("utf-8"))
        await w.drain()

        line = await asyncio.wait_for(r.readline(), timeout=10)
        reply = _json_pam.loads(line.decode("utf-8"))
        if not reply.get("ok"):
            log(f"pam_check FAIL user={user} code={reply.get('code')}"
                f" reason={reply.get('reason')!r}")
            return False
        return True
    except Exception as e:
        log(f"pam_check_async exception user={user}: {e!r}")
        return False
    finally:
        await _close_writer(w)


def pam_check(user: str, password: str) -> bool:
    """Blocking wrapper for compatibility with old call sites."""
    return asyncio.run(pam_check_async(user, password))


# ============================================================
# Group membership (proxyusers)
# ============================================================
def load_group() -> None:
    """Refresh the cached member list of PROXY_GROUP if /etc/group changed."""
    global _group_members, _group_mtime
    try:
        mtime = os.path.getmtime("/etc/group")
    except OSError:
        mtime = 0
    if mtime == _group_mtime and _group_members:
        return
    try:
        gr = grp.getgrnam(PROXY_GROUP)
    except KeyError:
        log(f"WARNING: group {PROXY_GROUP!r} does not exist")
        _group_members, _group_mtime = set(), mtime
        return
    members = set(gr.gr_mem)
    # Also include users whose PRIMARY group is proxyusers
    for u in pwd.getpwall():
        if u.pw_gid == gr.gr_gid:
            members.add(u.pw_name)
    _group_members = members
    _group_mtime = mtime
    log(f"loaded {len(members)} members of group {PROXY_GROUP!r}: {sorted(members)}")


def in_group(user: str) -> bool:
    load_group()
    return user in _group_members


# ============================================================
# Whitelist
# ============================================================
def load_whitelist() -> None:
    global _whitelist
    if WHITELIST_FILE.exists():
        entries = [ln.strip().lower() for ln in WHITELIST_FILE.read_text().splitlines()
                   if ln.strip() and not ln.strip().startswith("#")]
        _whitelist = entries
        log(f"loaded {len(entries)} whitelist entries from {WHITELIST_FILE}")
    else:
        _whitelist = [p.lower() for p in DEFAULT_WHITELIST]
        log(f"using built-in whitelist ({len(_whitelist)} entries)")


def host_allowed(host: str) -> bool:
    h = host.lower().rstrip(".")
    try:
        ipaddress.ip_address(h)
        # Loopback + explicitly-allowed IPs pass. Everything else is denied
        # (public IP literals almost never legit, and they bypass domain rules).
        return h in ALLOW_IPS_DEFAULT
    except ValueError:
        pass
    return any(fnmatch.fnmatch(h, pat) for pat in _whitelist)


_proxy_domains: list[str] = []


def load_proxy_domains() -> None:
    global _proxy_domains
    path = PROXY_DOMAINS_FILE
    if not path.exists():
        if os.environ.get("PTO_AUTH_PROXY_PROXY_DOMAINS"):
            raise ValueError("configured proxy-domains file is missing")
        # Upgrades preserve config. Missing optional routing config uses the
        # shipped defaults, without overwriting administrator-owned files.
        path = Path(__file__).parent / "proxy-domains.txt"
        if not path.exists():
            path = Path(__file__).parent / "config/proxy-domains.txt"
    _proxy_domains = [line.strip().lower() for line in path.read_text().splitlines()
                      if line.strip() and not line.lstrip().startswith("#")]
    log(f"loaded {len(_proxy_domains)} auto proxy domains from {path}")


def target_route(host: str, mode: str) -> str:
    if mode == "proxy":
        return "proxy"
    if mode != "auto":
        raise ValueError("invalid routing mode")
    return "proxy" if any(fnmatch.fnmatch(host.lower().rstrip("."), pattern)
                          for pattern in _proxy_domains) else "direct"


class DirectDenied(Exception):
    pass


async def open_direct(host: str, port: int):
    """Resolve once and connect only to checked numeric public addresses.

    The shared owner has privileged access to the loopback upstream. This
    forwarding path must never become a route to that endpoint or internal IPs.
    """
    if port not in DIRECT_PORTS:
        raise DirectDenied("direct destination port is not enabled")

    async def connect():
        addresses = await asyncio.get_running_loop().getaddrinfo(
            host, port, type=socket.SOCK_STREAM)
        if not addresses:
            raise OSError("no destination addresses")
        targets = set()
        for family, _, _, _, address in addresses:
            ip = ipaddress.ip_address(address[0].split("%", 1)[0])
            if not ip.is_global or ip.is_multicast or ip.is_loopback or ip.is_link_local:
                raise DirectDenied("direct destinations must resolve only to public addresses")
            targets.add((family, address[0]))
        for family, address in sorted(targets):
            try:
                return await asyncio.wait_for(
                    asyncio.open_connection(address, port, family=family),
                    timeout=UPSTREAM_CONNECT_TIMEOUT / len(targets))
            except (OSError, asyncio.TimeoutError):
                continue
        raise OSError("direct destination unreachable")

    return await asyncio.wait_for(connect(), timeout=UPSTREAM_CONNECT_TIMEOUT)


# ============================================================
# Logging / stats
# ============================================================
def log(msg: str) -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


def record(entry: dict) -> None:
    entry["ts"] = int(time.time())
    try:
        with open(STATS_FILE, "a") as f:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")
    except OSError as e:
        log(f"stats write failed: {e}")


def require_proxy_owner() -> None:
    """Refuse to run the shared proxy under the wrong Unix account."""
    uid = os.getuid()
    try:
        current_user = pwd.getpwuid(uid).pw_name
    except KeyError:
        current_user = f"uid={uid}"

    if current_user != PROXY_OWNER:
        log(f"ERROR: auth_proxy must run as user {PROXY_OWNER!r}, "
            f"not {current_user!r}")
        log(f"Current: {current_user} (uid={uid})")
        log(f"Required: {PROXY_OWNER}")
        log(f"To fix: sudo -u {PROXY_OWNER} pto-auth-proxy run")
        raise SystemExit(1)


# ============================================================
# SOCKS5 request handling
# ============================================================
async def _close_writer(writer: Optional[asyncio.StreamWriter]) -> None:
    if writer is None:
        return
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), timeout=CLOSE_TIMEOUT)
    except (AttributeError, OSError, asyncio.TimeoutError):
        pass


async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter,
                counter: list[int]) -> None:
    reached_eof = False
    try:
        while True:
            data = await src.read(65536)
            if not data:
                reached_eof = True
                break
            counter[0] += len(data)
            dst.write(data)
            await dst.drain()
    except asyncio.CancelledError:
        raise
    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
        pass
    finally:
        if reached_eof:
            try:
                if dst.can_write_eof():
                    dst.write_eof()
                    await asyncio.wait_for(
                        dst.drain(), timeout=CLOSE_TIMEOUT)
            except (AttributeError, OSError, RuntimeError,
                    asyncio.TimeoutError):
                pass


async def _relay(left_reader: asyncio.StreamReader,
                 left_writer: asyncio.StreamWriter,
                 right_reader: asyncio.StreamReader,
                 right_writer: asyncio.StreamWriter,
                 left_to_right: list[int],
                 right_to_left: list[int]) -> None:
    """Relay both directions, preserving TCP half-close with a bounded wait."""
    tasks = {
        asyncio.create_task(_pipe(left_reader, right_writer, left_to_right)),
        asyncio.create_task(_pipe(right_reader, left_writer, right_to_left)),
    }
    try:
        _done, pending = await asyncio.wait(
            tasks, return_when=asyncio.FIRST_COMPLETED)
        if pending:
            _finished, pending = await asyncio.wait(
                pending, timeout=RELAY_HALF_CLOSE_TIMEOUT)
        for task in pending:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def _client_readexactly(reader: asyncio.StreamReader, count: int) -> bytes:
    return await asyncio.wait_for(
        reader.readexactly(count), timeout=CLIENT_HANDSHAKE_TIMEOUT)


async def _upstream_readexactly(reader: asyncio.StreamReader, count: int) -> bytes:
    return await asyncio.wait_for(
        reader.readexactly(count), timeout=UPSTREAM_HANDSHAKE_TIMEOUT)


async def _upstream_drain(writer: asyncio.StreamWriter) -> None:
    await asyncio.wait_for(
        writer.drain(), timeout=UPSTREAM_HANDSHAKE_TIMEOUT)


async def _read_addr(r: asyncio.StreamReader, atyp: int) -> str:
    if atyp == 0x01:
        return socket.inet_ntoa(await _client_readexactly(r, 4))
    if atyp == 0x03:
        ln = (await _client_readexactly(r, 1))[0]
        return (await _client_readexactly(r, ln)).decode(
            "ascii", errors="replace")
    if atyp == 0x04:
        return socket.inet_ntop(
            socket.AF_INET6, await _client_readexactly(r, 16))
    raise ValueError(f"bad atyp {atyp}")


async def handle(cr: asyncio.StreamReader, cw: asyncio.StreamWriter, *, route_mode: str = "proxy") -> None:
    peer = cw.get_extra_info("peername")
    peer_str = f"{peer[0]}:{peer[1]}" if peer else "?"
    user, host, port = "-", "", 0
    verdict = "?"
    route = "-"
    up_writer: Optional[asyncio.StreamWriter] = None
    up_bytes, down_bytes = [0], [0]
    t0 = time.monotonic()

    try:
        # 1. Greeting
        ver, nmethods = await _client_readexactly(cr, 2)
        if ver != 0x05:
            return
        methods = await _client_readexactly(cr, nmethods)
        if 0x02 not in methods:
            cw.write(b"\x05\xFF")
            await cw.drain()
            verdict = "no_auth_offered"
            return
        cw.write(b"\x05\x02")
        await cw.drain()

        # 2. USERNAME/PASSWORD (RFC 1929)
        v = (await _client_readexactly(cr, 1))[0]
        if v != 0x01:
            return
        ulen = (await _client_readexactly(cr, 1))[0]
        user = (await _client_readexactly(cr, ulen)).decode(
            "utf-8", errors="replace")
        plen = (await _client_readexactly(cr, 1))[0]
        pw = (await _client_readexactly(cr, plen)).decode(
            "utf-8", errors="replace")

        # 2a. Must be a member of PROXY_GROUP
        if not in_group(user):
            cw.write(b"\x01\x01")
            await cw.drain()
            verdict = "not_in_group"
            log(f"DENY-GROUP {peer_str} user={user!r}")
            return

        # 2b. PAM check via user's own authd (no privilege on our side)
        ok = await pam_check_async(user, pw)
        if not ok:
            cw.write(b"\x01\x01")
            await cw.drain()
            verdict = "auth_fail"
            log(f"AUTH-FAIL {peer_str} user={user!r}")
            return
        cw.write(b"\x01\x00")
        await cw.drain()

        # 3. Request header
        hdr = await _client_readexactly(cr, 4)
        if hdr[0] != 0x05 or hdr[1] != 0x01:
            cw.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            await cw.drain()
            verdict = "cmd_unsupp"
            return
        atyp = hdr[3]
        try:
            host = await _read_addr(cr, atyp)
        except ValueError:
            cw.write(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            await cw.drain()
            verdict = "atyp_unsupp"
            return
        port = struct.unpack("!H", await _client_readexactly(cr, 2))[0]

        # Routing does not grant upstream access: both modes retain whitelist checks.
        route = target_route(host, route_mode)
        if route == "proxy" and not host_allowed(host):
            cw.write(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
            await cw.drain()
            verdict = "denied"
            log(f"DENY  user={user} -> {host}:{port}")
            return

        if route == "direct":
            try:
                up_reader, up_writer = await open_direct(host, port)
            except DirectDenied:
                verdict = "direct_denied"
                cw.write(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
                await cw.drain()
                return
            except OSError:
                verdict = "direct_dead"
                cw.write(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
                await cw.drain()
                return
            cw.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await cw.drain()
        else:
            try:
                up_reader, up_writer = await asyncio.wait_for(
                    asyncio.open_connection(UPSTREAM_HOST, UPSTREAM_PORT),
                    timeout=UPSTREAM_CONNECT_TIMEOUT)
            except (OSError, asyncio.TimeoutError) as e:
                cw.write(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                await cw.drain()
                verdict = "upstream_dead"
                log(f"UPSTREAM-DEAD user={user} -> {host}:{port}: {e}")
                return

            up_writer.write(b"\x05\x01\x00")
            await _upstream_drain(up_writer)
            if (await _upstream_readexactly(up_reader, 2)) != b"\x05\x00":
                cw.write(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                await cw.drain()
                verdict = "upstream_authneg"
                return

            if atyp == 0x03:
                addr_bytes = bytes([len(host)]) + host.encode("ascii")
            elif atyp == 0x01:
                addr_bytes = socket.inet_aton(host)
            else:
                addr_bytes = socket.inet_pton(socket.AF_INET6, host)
            up_writer.write(b"\x05\x01\x00" + bytes([atyp]) + addr_bytes
                            + struct.pack("!H", port))
            await _upstream_drain(up_writer)

            rep = await _upstream_readexactly(up_reader, 4)
            cw.write(rep)
            rep_atyp = rep[3]
            if rep_atyp == 0x01:
                cw.write(await _upstream_readexactly(up_reader, 4 + 2))
            elif rep_atyp == 0x03:
                ln = (await _upstream_readexactly(up_reader, 1))[0]
                cw.write(bytes([ln]) + await _upstream_readexactly(up_reader, ln + 2))
            elif rep_atyp == 0x04:
                cw.write(await _upstream_readexactly(up_reader, 16 + 2))
            else:
                verdict = "upstream_bad_reply"
                return
            await cw.drain()
            if rep[1] != 0x00:
                verdict = f"upstream_rep_{rep[1]}"
                log(f"UPSTREAM-REJECT user={user} -> {host}:{port} rep={rep[1]}")
                return

        verdict = "ok"
        log(f"ALLOW user={user} -> {host}:{port} route={route}")

        # 6. Full-duplex
        await _relay(cr, cw, up_reader, up_writer, up_bytes, down_bytes)

    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    except asyncio.TimeoutError:
        verdict = "timeout"
        log(f"TIMEOUT user={user} host={host}:{port}")
    except Exception as e:
        log(f"ERROR user={user} host={host}:{port}: {e!r}")
    finally:
        await _close_writer(cw)
        await _close_writer(up_writer)
        record({
            "user": user,
            "peer": peer_str,
            "host": host,
            "port": port,
            "verdict": verdict,
            "route": route,
            "mode": route_mode,
            "bytes_up":   up_bytes[0],
            "bytes_down": down_bytes[0],
            "duration":   round(time.monotonic() - t0, 3),
        })


# ============================================================
# HTTP CONNECT proxy handler (for Node.js / undici / anything that only
# speaks HTTP proxy, e.g. Claude Code). Listens on HTTP_LISTEN_PORT.
# Flow:
#   1. Read request line + headers
#   2. CONNECT tunnels HTTPS; absolute-form http:// requests are forwarded
#   3. Enforce Proxy-Authorization: Basic user:pw   -> authd
#   4. Enforce whitelist on the CONNECT target
#   5. Open SOCKS5 to the configured UPSTREAM and hand it the target
#   6. Reply "HTTP/1.1 200 Connection Established" and pipe both ways
# ============================================================
import base64 as _b64

async def _read_http_headers(reader: asyncio.StreamReader,
                             max_bytes: int = 16 * 1024
                             ) -> tuple[bytes, list[bytes], bytes]:
    """Return request line, headers, and any coalesced tunnel payload."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = await asyncio.wait_for(
            reader.read(4096), timeout=CLIENT_HANDSHAKE_TIMEOUT)
        if not chunk:
            break
        buf += chunk
        if len(buf) > max_bytes:
            raise ValueError("headers too large")
    if b"\r\n\r\n" not in buf:
        raise ValueError("incomplete headers")
    head, _, tail = buf.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    return lines[0], lines[1:], tail


async def handle_http(cr: asyncio.StreamReader, cw: asyncio.StreamWriter, *, route_mode: str = "proxy") -> None:
    peer = cw.get_extra_info("peername")
    peer_str = f"{peer[0]}:{peer[1]}" if peer else "?"
    user, host, port = "-", "", 0
    verdict = "?"
    route = "-"
    up_writer: Optional[asyncio.StreamWriter] = None
    up_bytes, down_bytes = [0], [0]
    t0 = time.monotonic()

    async def _reply(status: str, body: str = "", extra: str = "") -> None:
        msg = (f"HTTP/1.1 {status}\r\n"
               f"Content-Length: {len(body)}\r\n"
               f"Connection: close\r\n"
               f"{extra}"
               f"\r\n{body}").encode("utf-8")
        try:
            cw.write(msg)
            await cw.drain()
        except Exception:
            pass

    try:
        request_line, header_lines, initial_payload = await _read_http_headers(cr)
        parts = request_line.split(b" ")
        if len(parts) < 3:
            verdict = "bad_request"
            await _reply("400 Bad Request", "malformed request line\n")
            return
        method, target, _ = parts[0], parts[1], parts[2]

        # Parse headers into dict (lowercase key)
        headers: dict[str, str] = {}
        for h in header_lines:
            if b":" in h:
                k, _, v = h.partition(b":")
                headers[k.strip().lower().decode("ascii", "replace")] = \
                    v.strip().decode("utf-8", "replace")

        tunnel = method.upper() == b"CONNECT"
        if tunnel:
            if b":" not in target:
                verdict = "bad_target"
                await _reply("400 Bad Request", "CONNECT target must be host:port\n")
                return
            host_b, _, port_b = target.rpartition(b":")
            host = host_b.decode("ascii", "strict")
            if host.startswith("[") and host.endswith("]"):
                host = host[1:-1]
            try:
                port = int(port_b)
            except ValueError:
                port = 0
        else:
            parsed = urlsplit(target.decode("ascii", "strict"))
            if parsed.scheme != "http" or not parsed.hostname or parsed.username is not None or parsed.password is not None:
                verdict = "bad_target"
                await _reply("400 Bad Request", "absolute http:// target required\n")
                return
            host = parsed.hostname
            port = parsed.port or 80
        if not 1 <= port <= 65535:
            verdict = "bad_target"
            await _reply("400 Bad Request", "invalid port\n")
            return

        # Auth
        pa = headers.get("proxy-authorization", "")
        if not pa.lower().startswith("basic "):
            verdict = "no_auth"
            await _reply("407 Proxy Authentication Required",
                         "Proxy-Authorization required (Basic)\n",
                         extra='Proxy-Authenticate: Basic realm="authproxy"\r\n')
            return
        try:
            decoded = _b64.b64decode(pa[6:].strip()).decode("utf-8", "replace")
            user, _, pw = decoded.partition(":")
        except Exception:
            verdict = "bad_auth_header"
            await _reply("400 Bad Request", "malformed Proxy-Authorization\n")
            return

        # Group check
        if not in_group(user):
            verdict = "not_in_group"
            log(f"HTTP DENY-GROUP {peer_str} user={user!r}")
            await _reply("407 Proxy Authentication Required",
                         "user not in proxyusers\n",
                         extra='Proxy-Authenticate: Basic realm="authproxy"\r\n')
            return

        # PAM via user's authd
        ok = await pam_check_async(user, pw)
        if not ok:
            verdict = "auth_fail"
            log(f"HTTP AUTH-FAIL {peer_str} user={user!r}")
            await _reply("407 Proxy Authentication Required",
                         "bad credentials\n",
                         extra='Proxy-Authenticate: Basic realm="authproxy"\r\n')
            return

        route = target_route(host, route_mode)
        if route == "proxy" and not host_allowed(host):
            verdict = "denied"
            log(f"HTTP DENY user={user} -> {host}:{port}")
            await _reply("403 Forbidden",
                         f"destination {host} not on whitelist\n")
            return

        if route == "direct":
            try:
                up_reader, up_writer = await open_direct(host, port)
            except DirectDenied:
                verdict = "direct_denied"
                await _reply("403 Forbidden", "direct target must be public and use an enabled port\n")
                return
            except OSError:
                verdict = "direct_dead"
                await _reply("502 Bad Gateway", "direct destination unreachable\n")
                return
        else:
            try:
                up_reader, up_writer = await asyncio.wait_for(
                    asyncio.open_connection(UPSTREAM_HOST, UPSTREAM_PORT),
                    timeout=UPSTREAM_CONNECT_TIMEOUT)
            except (OSError, asyncio.TimeoutError) as e:
                verdict = "upstream_dead"
                log(f"HTTP UPSTREAM-DEAD user={user} -> {host}:{port}: {e}")
                await _reply("502 Bad Gateway", "upstream tunnel unreachable\n")
                return

            # SOCKS5 no-auth handshake
            up_writer.write(b"\x05\x01\x00")
            await _upstream_drain(up_writer)
            if (await _upstream_readexactly(up_reader, 2)) != b"\x05\x00":
                verdict = "upstream_authneg"
                await _reply("502 Bad Gateway", "upstream socks handshake failed\n")
                return

            try:
                ip = ipaddress.ip_address(host)
                address = (b"\x01" if ip.version == 4 else b"\x04") + ip.packed
            except ValueError:
                encoded = host.encode("idna")
                address = b"\x03" + bytes([len(encoded)]) + encoded
            up_writer.write(b"\x05\x01\x00" + address + struct.pack("!H", port))
            await _upstream_drain(up_writer)

            rep = await _upstream_readexactly(up_reader, 4)
            rep_atyp = rep[3]
            if rep_atyp == 0x01:
                await _upstream_readexactly(up_reader, 4 + 2)
            elif rep_atyp == 0x03:
                ln = (await _upstream_readexactly(up_reader, 1))[0]
                await _upstream_readexactly(up_reader, ln + 2)
            elif rep_atyp == 0x04:
                await _upstream_readexactly(up_reader, 16 + 2)

            if rep[1] != 0x00:
                verdict = f"upstream_rep_{rep[1]}"
                log(f"HTTP UPSTREAM-REJECT user={user} -> {host}:{port} rep={rep[1]}")
                await _reply("502 Bad Gateway",
                             f"upstream refused (socks rep={rep[1]})\n")
                return

        if tunnel:
            cw.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await cw.drain()
        else:
            # Remove proxy credentials and hop-by-hop control from origin requests.
            origin = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
            outgoing = method + b" " + origin.encode("ascii") + b" HTTP/1.1\r\n"
            for header in header_lines:
                name = header.partition(b":")[0].strip().lower()
                if name not in {b"proxy-authorization", b"proxy-connection", b"connection", b"keep-alive", b"host"}:
                    outgoing += header + b"\r\n"
            host_header = f"[{host}]" if ":" in host else host
            outgoing += f"Host: {host_header}:{port}\r\nConnection: close\r\n\r\n".encode("ascii")
            up_bytes[0] += len(outgoing)
            up_writer.write(outgoing)
            await up_writer.drain()
        verdict = "ok"
        log(f"HTTP ALLOW user={user} -> {host}:{port} route={route}")

        # A client may coalesce the first TLS bytes with the CONNECT headers.
        # Preserve them instead of silently dropping them during header parsing.
        if initial_payload:
            up_bytes[0] += len(initial_payload)
            up_writer.write(initial_payload)
            await up_writer.drain()

        await _relay(cr, cw, up_reader, up_writer, up_bytes, down_bytes)

    except (asyncio.IncompleteReadError, ConnectionResetError, ValueError) as e:
        if verdict == "?":
            verdict = f"proto_err:{type(e).__name__}"
    except asyncio.TimeoutError:
        verdict = "timeout"
        log(f"HTTP TIMEOUT user={user} host={host}:{port}")
        await _reply("504 Gateway Timeout", "proxy operation timed out\n")
    except Exception as e:
        log(f"HTTP ERROR user={user} host={host}:{port}: {e!r}")
        if verdict == "?":
            verdict = f"exc:{type(e).__name__}"
    finally:
        await _close_writer(cw)
        await _close_writer(up_writer)
        record({
            "user": user,
            "peer": peer_str,
            "host": host,
            "port": port,
            "verdict": verdict,
            "route": route,
            "mode": route_mode,
            "bytes_up":   up_bytes[0],
            "bytes_down": down_bytes[0],
            "duration":   round(time.monotonic() - t0, 3),
            "proto":      "http",
        })


# ============================================================
# Anomaly detection + daily report
# ============================================================
# We keep everything in-process to avoid a second daemon. The scan reads the
# tail of stats.jsonl every SCAN_INTERVAL_SECONDS and looks at events in the
# last WINDOW_SECONDS. Alerts land in alerts.jsonl (JSON per line) and are
# ALSO copied to the plain-text auth_proxy.log with a "[ALERT] " prefix so
# `grep '\[ALERT\]' auth_proxy.log` shows a clean incident list.
# Reports are generated shortly after midnight for the previous local day.

import collections as _collections
import datetime as _dt


def _emit_alert(entry: dict) -> None:
    entry = dict(entry)
    entry["ts"] = int(time.time())
    try:
        with open(ALERTS_FILE, "a") as f:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")
    except OSError as e:
        log(f"alert write failed: {e}")
    # Human-readable line in the main log for easy tail-grep
    log(f"[ALERT] {entry.get('kind','?')} user={entry.get('user','-')} "
        f"detail={entry.get('detail','')}")


def _iter_recent_stats(since_ts: int):
    """Yield stats entries whose ts >= since_ts. Reads the tail of stats.jsonl."""
    if not STATS_FILE.exists():
        return
    # Read from the end backwards so we don't parse GBs on old files.
    # Simple approach: mmap-ish tail via seek from end, one MB at a time.
    with open(STATS_FILE, "rb") as f:
        f.seek(0, 2)
        size = f.tell()
        chunk = 2 * 1024 * 1024
        buf = b""
        pos = size
        entries = []
        while pos > 0 and (not entries or entries[0].get("ts", 0) >= since_ts):
            read_from = max(0, pos - chunk)
            f.seek(read_from)
            data = f.read(pos - read_from)
            pos = read_from
            buf = data + buf
            # Peel off full lines
            lines = buf.split(b"\n")
            buf = lines[0]  # possibly-partial
            new_entries = []
            for line in lines[1:]:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                new_entries.append(e)
            entries = new_entries + entries
            if entries and entries[0].get("ts", 0) < since_ts:
                break
        # At offset zero, ``buf`` is a complete first line rather than a
        # partial line from the preceding chunk.
        if pos == 0 and buf.strip():
            try:
                entries.insert(0, json.loads(buf))
            except Exception:
                pass
    for e in entries:
        if e.get("ts", 0) >= since_ts:
            yield e


def recent_download_ranking(window_seconds: int = 30 * 60,
                            now: Optional[int] = None) -> list[dict]:
    """Return per-user download totals for the trailing time window."""
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    end_ts = int(time.time()) if now is None else int(now)
    since_ts = end_ts - window_seconds
    per_user = _collections.defaultdict(lambda: {
        "bytes_down": 0, "connections": 0,
    })

    for entry in _iter_recent_stats(since_ts):
        if entry.get("ts", 0) > end_ts:
            continue
        user = entry.get("user")
        if not user or user == "-":
            continue
        try:
            bytes_down = max(0, int(entry.get("bytes_down", 0)))
        except (TypeError, ValueError):
            continue
        item = per_user[user]
        item["bytes_down"] += bytes_down
        item["connections"] += 1

    return [
        {"rank": rank, "user": user, **values}
        for rank, (user, values) in enumerate(
            sorted(per_user.items(),
                   key=lambda item: (-item[1]["bytes_down"], item[0])),
            start=1)
    ]


def _format_bytes(value: int) -> str:
    amount = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or unit == "TiB":
            return f"{int(amount)} {unit}" if unit == "B" else f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{amount:.1f} TiB"


def print_download_ranking(minutes: int = 30, as_json: bool = False) -> None:
    """Print the recent per-user download ranking to stdout."""
    generated_at = int(time.time())
    ranking = recent_download_ranking(minutes * 60, now=generated_at)
    if as_json:
        print(json.dumps({
            "generated_at": generated_at,
            "window_minutes": minutes,
            "users": ranking,
        }, ensure_ascii=False, separators=(",", ":")))
        return

    print(f"最近 {minutes} 分钟用户下行流量排行")
    print(f"{'排名':>4}  {'用户':<20} {'下行流量':>12} {'连接数':>8}")
    if not ranking:
        print("（暂无已完成连接的流量记录）")
        return
    for item in ranking:
        print(f"{item['rank']:>4}  {item['user']:<20} "
              f"{_format_bytes(item['bytes_down']):>12} "
              f"{item['connections']:>8}")


async def anomaly_scan_loop() -> None:
    log(f"anomaly watcher: scan every {SCAN_INTERVAL_SECONDS}s, "
        f"window {WINDOW_SECONDS}s")
    while True:
        try:
            await asyncio.sleep(SCAN_INTERVAL_SECONDS)
            _run_anomaly_scan()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log(f"anomaly scan error: {e!r}")


# De-dupe: same (kind, user) fired within the same window shouldn't spam.
# Keep the last-emit ts per key.
_last_emit: dict[tuple[str, str], int] = {}


def _throttle(kind: str, user: str, min_interval: int = WINDOW_SECONDS) -> bool:
    now = int(time.time())
    key = (kind, user)
    last = _last_emit.get(key, 0)
    if now - last < min_interval:
        return False
    _last_emit[key] = now
    return True


def _run_anomaly_scan() -> None:
    now = int(time.time())
    since = now - WINDOW_SECONDS

    per_user_bytes_up   = _collections.Counter()
    per_user_bytes_down = _collections.Counter()
    per_user_conns      = _collections.Counter()
    per_user_authfail   = _collections.Counter()
    per_user_deny       = _collections.Counter()
    per_user_deny_hosts: dict[str, set[str]] = _collections.defaultdict(set)

    for e in _iter_recent_stats(since):
        u = e.get("user", "-")
        v = e.get("verdict", "?")
        per_user_bytes_up[u]   += e.get("bytes_up", 0)
        per_user_bytes_down[u] += e.get("bytes_down", 0)
        per_user_conns[u]      += 1
        if v == "auth_fail":
            per_user_authfail[u] += 1
        elif v in {"denied", "direct_denied"}:
            per_user_deny[u] += 1
            host = e.get("host") or ""
            if host:
                per_user_deny_hosts[u].add(host)

    # 1. Data exfiltration burst (bytes up in the window)
    for u, b in per_user_bytes_up.items():
        if b >= ANOMALY_BYTES_UP and _throttle("bytes_up", u):
            _emit_alert({
                "kind": "bytes_up_burst", "user": u,
                "bytes_up": b, "window_sec": WINDOW_SECONDS,
                "detail": f"{b/1_048_576:.1f} MB up in {WINDOW_SECONDS}s"})

    # 2. Sustained high QPS (whole window average)
    for u, c in per_user_conns.items():
        qps = c / WINDOW_SECONDS
        if qps >= ANOMALY_QPS_THRESHOLD and _throttle("high_qps", u):
            _emit_alert({
                "kind": "high_qps", "user": u,
                "connections": c, "window_sec": WINDOW_SECONDS,
                "qps_avg": round(qps, 2),
                "detail": f"{c} conns in {WINDOW_SECONDS}s (avg {qps:.1f} QPS)"})

    # 3. Auth failure spike (password brute-force suspicion)
    for u, c in per_user_authfail.items():
        if c >= ANOMALY_AUTHFAIL_COUNT and _throttle("auth_fail_burst", u):
            _emit_alert({
                "kind": "auth_fail_burst", "user": u,
                "auth_failures": c, "window_sec": WINDOW_SECONDS,
                "detail": f"{c} auth failures in {WINDOW_SECONDS}s"})

    # 4. Whitelist-miss burst (probing / scanning)
    for u, c in per_user_deny.items():
        if c >= ANOMALY_DENY_COUNT and _throttle("scan_probe", u):
            _emit_alert({
                "kind": "scan_probe", "user": u,
                "denied_count": c,
                "distinct_hosts": len(per_user_deny_hosts.get(u, ())),
                "sample_hosts": sorted(per_user_deny_hosts.get(u, ()))[:10],
                "window_sec": WINDOW_SECONDS,
                "detail": f"{c} denied attempts to "
                          f"{len(per_user_deny_hosts.get(u, ()))} hosts in "
                          f"{WINDOW_SECONDS}s"})


# ---- daily report --------------------------------------------------------
async def daily_report_loop() -> None:
    log(f"daily-report scheduler: next run at {REPORT_HOUR:02d}:{REPORT_MINUTE:02d}")
    while True:
        try:
            now = _dt.datetime.now()
            # Next fire = today's REPORT_HOUR:REPORT_MINUTE, else tomorrow
            target = now.replace(hour=REPORT_HOUR, minute=REPORT_MINUTE,
                                 second=0, microsecond=0)
            if target <= now:
                target += _dt.timedelta(days=1)
            wait = (target - now).total_seconds()
            await asyncio.sleep(wait)
            yesterday = (_dt.datetime.now() - _dt.timedelta(hours=1)).date()
            try:
                _generate_report(yesterday)
            except Exception as e:
                log(f"report generation error: {e!r}")
        except asyncio.CancelledError:
            raise


def _generate_report(day: _dt.date) -> None:
    """Write reports/YYYY-MM-DD.{md,json} covering the given local calendar day."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    md_path   = REPORTS_DIR / f"{day.isoformat()}.md"
    json_path = REPORTS_DIR / f"{day.isoformat()}.json"

    start = int(_dt.datetime.combine(day, _dt.time.min).timestamp())
    end   = int(_dt.datetime.combine(day + _dt.timedelta(days=1),
                                     _dt.time.min).timestamp())

    per_user = _collections.defaultdict(lambda: {
        "connections": 0, "ok": 0, "auth_fail": 0, "denied": 0,
        "bytes_up": 0, "bytes_down": 0,
        "hosts": _collections.Counter(),
    })
    totals = {"connections": 0, "ok": 0, "auth_fail": 0, "denied": 0,
              "bytes_up": 0, "bytes_down": 0}
    proto_split = _collections.Counter()

    if STATS_FILE.exists():
        with open(STATS_FILE) as f:
            for line in f:
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                ts = e.get("ts", 0)
                if ts < start or ts >= end:
                    continue
                u = e.get("user", "-")
                v = e.get("verdict", "?")
                pu = per_user[u]
                pu["connections"] += 1
                totals["connections"] += 1
                proto_split[e.get("proto", "socks")] += 1
                if v == "ok":
                    pu["ok"] += 1; totals["ok"] += 1
                elif v == "auth_fail":
                    pu["auth_fail"] += 1; totals["auth_fail"] += 1
                elif v in {"denied", "direct_denied"}:
                    pu["denied"] += 1; totals["denied"] += 1
                bu = e.get("bytes_up", 0); bd = e.get("bytes_down", 0)
                pu["bytes_up"] += bu; pu["bytes_down"] += bd
                totals["bytes_up"] += bu; totals["bytes_down"] += bd
                host = e.get("host") or ""
                if host:
                    pu["hosts"][host] += 1

    # Alerts for this day
    alerts_today = []
    if ALERTS_FILE.exists():
        with open(ALERTS_FILE) as f:
            for line in f:
                try:
                    a = json.loads(line)
                except Exception:
                    continue
                if start <= a.get("ts", 0) < end:
                    alerts_today.append(a)

    # ---- JSON report ----
    json_report = {
        "date": day.isoformat(),
        "totals": totals,
        "protocol_breakdown": dict(proto_split),
        "per_user": {u: {"connections":  d["connections"],
                         "ok":           d["ok"],
                         "auth_fail":    d["auth_fail"],
                         "denied":       d["denied"],
                         "bytes_up":     d["bytes_up"],
                         "bytes_down":   d["bytes_down"],
                         "top_hosts":    d["hosts"].most_common(10)}
                     for u, d in per_user.items()},
        "alerts": alerts_today,
    }
    with open(json_path, "w") as f:
        json.dump(json_report, f, indent=2)

    # ---- Markdown report ----
    def fmt_bytes(n):
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024 or unit == "GB":
                return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} {unit}"
            n /= 1024
        return f"{n:.1f} GB"

    lines = []
    lines.append(f"# Auth-Proxy Daily Report — {day.isoformat()}")
    lines.append("")
    lines.append("## Totals")
    lines.append("")
    lines.append(f"- Connections: **{totals['connections']}**")
    lines.append(f"- OK / auth-fail / denied: "
                 f"{totals['ok']} / {totals['auth_fail']} / {totals['denied']}")
    lines.append(f"- Bytes up / down: "
                 f"{fmt_bytes(totals['bytes_up'])} / "
                 f"{fmt_bytes(totals['bytes_down'])}")
    lines.append(f"- Protocol split: {dict(proto_split)}")
    lines.append("")
    lines.append("## Per-user")
    lines.append("")
    lines.append("| User | Conns | OK | AuthFail | Denied | Up | Down | Top hosts |")
    lines.append("|------|-------|----|----------|--------|----|------|-----------|")
    for u, d in sorted(per_user.items(),
                       key=lambda kv: -kv[1]["bytes_up"] - kv[1]["bytes_down"]):
        top = ", ".join(f"{h}({c})" for h, c in d["hosts"].most_common(3))
        lines.append(f"| {u} | {d['connections']} | {d['ok']} | "
                     f"{d['auth_fail']} | {d['denied']} | "
                     f"{fmt_bytes(d['bytes_up'])} | {fmt_bytes(d['bytes_down'])} | "
                     f"{top} |")
    lines.append("")
    lines.append("## Anomaly alerts")
    lines.append("")
    if alerts_today:
        for a in alerts_today:
            when = _dt.datetime.fromtimestamp(a.get("ts", 0)).strftime("%H:%M:%S")
            lines.append(f"- **{when}** `{a.get('kind')}` user=`{a.get('user')}` "
                         f"— {a.get('detail','')}")
    else:
        lines.append("_No anomalies detected._")
    lines.append("")

    with open(md_path, "w") as f:
        f.write("\n".join(lines))

    # Best-effort: make both files group-readable so proxyusers can inspect
    # them without needing pypto's help. Failures (e.g. read-only FS) are
    # non-fatal.
    for p in (md_path, json_path):
        try:
            os.chmod(p, 0o640)
        except OSError:
            pass

    log(f"daily report written: {md_path.name}")



# ============================================================
async def main() -> None:
    require_proxy_owner()
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    # Best-effort chgrp so proxyusers can read reports/alerts (needs the
    # process's primary/secondary group to include proxyusers; if not, we
    # silently skip and rely on manual chmod).
    try:
        import grp as _grp
        gid = _grp.getgrnam(PROXY_GROUP).gr_gid
        try:
            os.chown(REPORTS_DIR, -1, gid)
            os.chmod(REPORTS_DIR, 0o750)
        except (OSError, PermissionError):
            pass
    except KeyError:
        pass
    load_whitelist()
    load_proxy_domains()
    load_group()

    loop = asyncio.get_running_loop()

    def _on_hup():
        log("SIGHUP: reloading whitelist and group")
        load_whitelist()
        load_proxy_domains()
        load_group()

    stop = asyncio.Event()
    loop.add_signal_handler(signal.SIGHUP, _on_hup)
    loop.add_signal_handler(signal.SIGTERM,
                            lambda: (log("SIGTERM: stopping"), stop.set()))
    loop.add_signal_handler(signal.SIGINT,
                            lambda: (log("SIGINT: stopping"), stop.set()))

    # Bind every endpoint before serving; close earlier sockets if a later bind fails.
    servers = []
    try:
        for handler, port, mode in ((handle, LISTEN_PORT, "proxy"),
                                    (handle_http, HTTP_LISTEN_PORT, "proxy"),
                                    (handle, AUTO_SOCKS_PORT, "auto"),
                                    (handle_http, AUTO_HTTP_PORT, "auto")):
            server = await asyncio.start_server(partial(handler, route_mode=mode), LISTEN_HOST, port,
                                                start_serving=False)
            servers.append(server)
            log(f"{mode} {handler.__name__} listening on {LISTEN_HOST}:{port}")
        log(f"upstream {UPSTREAM_HOST}:{UPSTREAM_PORT}; direct ports={sorted(DIRECT_PORTS)}")
        for server in servers:
            await server.start_serving()
        tasks = [asyncio.create_task(server.serve_forever()) for server in servers]
        tasks += [asyncio.create_task(anomaly_scan_loop()), asyncio.create_task(daily_report_loop())]
        try:
            await stop.wait()
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        for server in servers:
            server.close()
        await asyncio.gather(*(server.wait_closed() for server in servers))


if __name__ == "__main__":
    # `--traffic [MINUTES] [--json]` is an offline stats query and does not
    # touch the running proxy.
    if len(sys.argv) >= 2 and sys.argv[1] == "--traffic":
        args = sys.argv[2:]
        as_json = "--json" in args
        values = [arg for arg in args if arg != "--json"]
        try:
            if len(values) > 1:
                raise ValueError
            minutes = int(values[0]) if values else 30
            if minutes <= 0:
                raise ValueError
        except ValueError:
            print("usage: auth_proxy.py --traffic [MINUTES] [--json]",
                  file=sys.stderr)
            sys.exit(2)
        print_download_ranking(minutes, as_json=as_json)
        sys.exit(0)

    # `--report YYYY-MM-DD` (or `--report today`) generates one report and
    # exits, without touching the running proxy. Useful for spot-checks.
    if len(sys.argv) >= 2 and sys.argv[1] == "--report":
        arg = sys.argv[2] if len(sys.argv) > 2 else "today"
        if arg == "today":
            day = _dt.date.today()
        elif arg == "yesterday":
            day = _dt.date.today() - _dt.timedelta(days=1)
        else:
            day = _dt.date.fromisoformat(arg)
        BASE_DIR.mkdir(parents=True, exist_ok=True)
        _generate_report(day)
        print(f"wrote {REPORTS_DIR / (day.isoformat() + '.md')}")
        sys.exit(0)

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
