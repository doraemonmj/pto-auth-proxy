"""Offline route-policy tests and actual loopback HTTP/SOCKS protocol tests."""
import asyncio
import base64
from functools import partial
from pathlib import Path
import socket
import struct
import tempfile
import unittest
from unittest import mock

with mock.patch.dict("os.environ", {"PTO_AUTH_PROXY_UPSTREAM_PORT": "7895"}):
    import auth_proxy


ROOT = Path(__file__).resolve().parents[1]


def patterns(name):
    return [line.strip() for line in (ROOT / "config" / name).read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


class RoutePolicyTest(unittest.IsolatedAsyncioTestCase):
    def test_explicit_missing_routing_policy_is_an_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing.txt"
            with mock.patch.object(auth_proxy, "PROXY_DOMAINS_FILE", missing), \
                 mock.patch.dict("os.environ", {"PTO_AUTH_PROXY_PROXY_DOMAINS": str(missing)}):
                with self.assertRaisesRegex(ValueError, "missing"):
                    auth_proxy.load_proxy_domains()

    def test_selected_services_use_proxy_and_other_services_use_direct(self):
        with mock.patch.object(auth_proxy, "_proxy_domains", patterns("proxy-domains.txt")):
            for host in ("github.com", "api.github.com", "raw.githubusercontent.com",
                         "api.openai.com", "chatgpt.com", "api.anthropic.com", "claude.ai"):
                self.assertEqual(auth_proxy.target_route(host, "auto"), "proxy")
            for host in ("example.com", "api.deepseek.com", "gitcode.com", "evilgithub.com",
                         "github.com.evil.example"):
                self.assertEqual(auth_proxy.target_route(host, "auto"), "direct")
                self.assertEqual(auth_proxy.target_route(host, "proxy"), "proxy")

    async def test_direct_rejects_private_mixed_and_multicast_dns_before_connecting(self):
        for addresses in (("127.0.0.1",), ("10.1.2.3",), ("169.254.169.254",),
                          ("::1",), ("::ffff:127.0.0.1",), ("224.0.0.1",),
                          ("93.184.216.34", "192.168.0.1")):
            records = [(socket.AF_INET6 if ":" in address else socket.AF_INET,
                        socket.SOCK_STREAM, 6, "", (address, 443)) for address in addresses]
            with self.subTest(addresses=addresses), \
                 mock.patch.object(asyncio.get_running_loop(), "getaddrinfo", return_value=records), \
                 mock.patch.object(auth_proxy.asyncio, "open_connection") as connect:
                with self.assertRaises(auth_proxy.DirectDenied):
                    await auth_proxy.open_direct("untrusted.example", 443)
                connect.assert_not_called()

    async def test_direct_connects_to_checked_numeric_address_without_second_dns_lookup(self):
        records = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        with mock.patch.object(asyncio.get_running_loop(), "getaddrinfo", return_value=records) as resolve, \
             mock.patch.object(auth_proxy.asyncio, "open_connection", return_value=("reader", "writer")) as connect:
            self.assertEqual(await auth_proxy.open_direct("public.example", 443), ("reader", "writer"))
        resolve.assert_awaited_once()
        connect.assert_awaited_once_with("93.184.216.34", 443, family=socket.AF_INET)

    async def test_direct_rejects_unapproved_port_without_dns(self):
        with mock.patch.object(asyncio.get_running_loop(), "getaddrinfo") as resolve:
            with self.assertRaises(auth_proxy.DirectDenied):
                await auth_proxy.open_direct("public.example", auth_proxy.UPSTREAM_PORT)
            resolve.assert_not_called()

    async def test_slow_first_public_address_does_not_prevent_trying_the_next(self):
        records = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))
                   for ip in ("93.184.216.34", "93.184.216.35")]
        async def connect(address, _port, **_kwargs):
            if address.endswith("34"):
                await asyncio.sleep(1)
            return "reader", "writer"
        with mock.patch.object(asyncio.get_running_loop(), "getaddrinfo", return_value=records), \
             mock.patch.object(auth_proxy, "UPSTREAM_CONNECT_TIMEOUT", 0.1), \
             mock.patch.object(auth_proxy.asyncio, "open_connection", side_effect=connect):
            self.assertEqual(await auth_proxy.open_direct("public.example", 443), ("reader", "writer"))


class AutoProtocolTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.servers = []
        self.connections = set()
        self.errors = []
        self.upstream_requests = []
        self.origin_requests = []
        self.events = []
        self.open_connection = asyncio.open_connection
        self.origin = await self.listen(self.direct_origin)
        self.upstream = await self.listen(self.socks_upstream)
        self.http_auto = await self.listen(partial(auth_proxy.handle_http, route_mode="auto"))
        self.http_force = await self.listen(auth_proxy.handle_http)
        self.socks_auto = await self.listen(partial(auth_proxy.handle, route_mode="auto"))
        for patch in (
            mock.patch.object(auth_proxy, "UPSTREAM_HOST", "127.0.0.1"),
            mock.patch.object(auth_proxy, "UPSTREAM_PORT", self.upstream),
            mock.patch.object(auth_proxy, "_proxy_domains", patterns("proxy-domains.txt")),
            mock.patch.object(auth_proxy, "_whitelist", patterns("whitelist.txt")),
            mock.patch.object(auth_proxy, "in_group", return_value=True),
            mock.patch.object(auth_proxy, "pam_check_async", return_value=True),
            mock.patch.object(auth_proxy, "log"),
            mock.patch.object(auth_proxy, "record", side_effect=self.events.append),
            mock.patch.object(asyncio.get_running_loop(), "getaddrinfo", return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]),
            mock.patch.object(auth_proxy.asyncio, "open_connection", side_effect=self.connect),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    async def asyncTearDown(self):
        for server in self.servers:
            server.close()
        await asyncio.gather(*(server.wait_closed() for server in self.servers))
        if self.connections:
            await asyncio.wait_for(asyncio.gather(*self.connections), 3)
        self.assertEqual(self.errors, [])

    async def listen(self, callback):
        async def tracked(reader, writer):
            task = asyncio.current_task()
            self.connections.add(task)
            try:
                await callback(reader, writer)
            except Exception as error:
                self.errors.append(error)
            finally:
                self.connections.discard(task)
        server = await asyncio.start_server(tracked, "127.0.0.1", 0)
        self.servers.append(server)
        return server.sockets[0].getsockname()[1]

    async def connect(self, host, port, **kwargs):
        if host == "93.184.216.34":
            return await self.open_connection("127.0.0.1", self.origin)
        # Test traffic can only reach these local fixtures, never the Internet.
        if host != "127.0.0.1":
            raise AssertionError("unexpected network target")
        return await self.open_connection(host, port, **kwargs)

    async def direct_origin(self, reader, writer):
        try:
            request = await reader.read(4096)
            self.origin_requests.append(request)
            if request.startswith(b"GET "):
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndirect")
            else:
                writer.write(b"direct:" + request)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    async def socks_upstream(self, reader, writer):
        try:
            self.assertEqual(await reader.readexactly(3), b"\x05\x01\x00")
            writer.write(b"\x05\x00")
            await writer.drain()
            request = await reader.readexactly(4)
            self.assertEqual(request, b"\x05\x01\x00\x03")
            length = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(length)).decode()
            port = struct.unpack("!H", await reader.readexactly(2))[0]
            self.upstream_requests.append((host, port))
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            payload = await reader.read(4096)
            writer.write(b"proxy:" + payload)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    async def http_request(self, target, *, listener=None, auth=True, absolute=False):
        reader, writer = await self.open_connection("127.0.0.1", listener or self.http_auto)
        authorization = base64.b64encode(b"testuser:synthetic-token")
        request = (b"GET http://" + target + b"/path?q=1 HTTP/1.1\r\n" if absolute else
                   b"CONNECT " + target + b" HTTP/1.1\r\n")
        if auth:
            request += b"Proxy-Authorization: Basic " + authorization + b"\r\n"
        request += b"Host: original.example\r\n\r\n" + (b"" if absolute else b"hello")
        try:
            writer.write(request)
            await writer.drain()
            return await asyncio.wait_for(reader.read(), 3)
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_http_auto_routes_selected_domains_to_upstream_and_others_direct(self):
        self.assertIn(b"proxy:hello", await self.http_request(b"api.github.com:443"))
        self.assertIn(b"direct:hello", await self.http_request(b"other-ai.example:443"))
        self.assertEqual(self.upstream_requests, [("api.github.com", 443)])

    async def test_plain_http_direct_strips_proxy_credentials_and_rewrites_absolute_target(self):
        self.assertIn(b"\r\n\r\ndirect", await self.http_request(b"public.example:80", absolute=True))
        self.assertTrue(self.origin_requests[0].startswith(b"GET /path?q=1 HTTP/1.1\r\n"))
        self.assertNotIn(b"Proxy-Authorization", self.origin_requests[0])
        self.assertNotIn(b"synthetic-token", self.origin_requests[0])
        self.assertEqual(self.upstream_requests, [])

    async def test_force_proxy_keeps_whitelist_and_never_uses_direct(self):
        self.assertIn(b"403 Forbidden", await self.http_request(b"other-ai.example:443", listener=self.http_force))
        self.assertEqual(self.origin_requests, [])
        self.assertEqual(self.upstream_requests, [])

    async def test_auto_cannot_use_direct_forwarding_without_authentication(self):
        self.assertIn(b"407 Proxy Authentication Required", await self.http_request(b"public.example:443", auth=False))
        self.assertEqual(self.origin_requests, [])

    async def test_invalid_credential_cannot_use_direct_forwarding(self):
        with mock.patch.object(auth_proxy, "pam_check_async", return_value=False):
            self.assertIn(b"407 Proxy Authentication Required", await self.http_request(b"public.example:443"))
        self.assertEqual(self.origin_requests, [])

    async def test_auto_rejects_private_dns_without_contacting_any_backend(self):
        with mock.patch.object(asyncio.get_running_loop(), "getaddrinfo", return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]):
            self.assertIn(b"403 Forbidden", await self.http_request(b"private.example:443"))
        self.assertEqual(self.origin_requests, [])
        self.assertEqual(self.upstream_requests, [])

    async def test_direct_failure_does_not_fall_back_to_proxy(self):
        with mock.patch.object(auth_proxy, "open_direct", side_effect=OSError):
            self.assertIn(b"502 Bad Gateway", await self.http_request(b"public.example:443"))
        self.assertEqual(self.upstream_requests, [])

    async def test_proxy_failure_does_not_fall_back_to_direct(self):
        with mock.patch.object(auth_proxy, "UPSTREAM_PORT", 0):
            self.assertIn(b"502 Bad Gateway", await self.http_request(b"github.com:443"))
        self.assertEqual(self.origin_requests, [])

    async def test_proxy_route_still_requires_whitelist_approval(self):
        with mock.patch.object(auth_proxy, "_proxy_domains", ["other-ai.example"]):
            self.assertIn(b"403 Forbidden", await self.http_request(b"other-ai.example:443"))
        self.assertEqual(self.origin_requests, [])
        self.assertEqual(self.upstream_requests, [])

    async def test_socks_auto_routes_both_paths(self):
        for host, expected in ((b"github.com", b"proxy:hello"), (b"other-ai.example", b"direct:hello")):
            reader, writer = await self.open_connection("127.0.0.1", self.socks_auto)
            try:
                writer.write(b"\x05\x01\x02")
                await writer.drain()
                self.assertEqual(await reader.readexactly(2), b"\x05\x02")
                writer.write(b"\x01\x08testuser\x0fsynthetic-token")
                await writer.drain()
                self.assertEqual(await reader.readexactly(2), b"\x01\x00")
                writer.write(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack("!H", 443) + b"hello")
                await writer.drain()
                self.assertEqual(await reader.readexactly(10), b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                self.assertEqual(await asyncio.wait_for(reader.read(), 3), expected)
            finally:
                writer.close()
                await writer.wait_closed()
