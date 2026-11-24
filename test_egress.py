"""Tests for configurable egress: User-Agent, proxy routing, and host allow/deny."""
import os
import socket
import unittest
from unittest.mock import patch

import collectors
import egress
import public_pages


class Egress(unittest.TestCase):
    def test_user_agent_default_and_override(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("OSINT_USER_AGENT", None)
            self.assertEqual(egress.user_agent(), egress.DEFAULT_USER_AGENT)
        with patch.dict(os.environ, {"OSINT_USER_AGENT": "acme-research/2.0"}):
            self.assertEqual(egress.user_agent(), "acme-research/2.0")

    def test_proxy_url_accepts_http_and_rejects_socks(self):
        with patch.dict(os.environ, {"OSINT_HTTP_PROXY": "http://127.0.0.1:3128"}):
            self.assertEqual(egress.proxy_url(), "http://127.0.0.1:3128")
        with patch.dict(os.environ, {"OSINT_HTTP_PROXY": ""}):
            self.assertEqual(egress.proxy_url(), "")
        with patch.dict(os.environ, {"OSINT_HTTP_PROXY": "socks5://127.0.0.1:9050"}):
            with self.assertRaisesRegex(ValueError, "SOCKS is not supported"):
                egress.proxy_url()

    def test_host_allow_and_deny(self):
        with patch.dict(os.environ, {"OSINT_FETCH_DENY": "evil.test", "OSINT_FETCH_ALLOW": ""}):
            self.assertFalse(egress.host_allowed("evil.test"))
            self.assertFalse(egress.host_allowed("sub.evil.test"))
            self.assertTrue(egress.host_allowed("example.org"))
        with patch.dict(os.environ, {"OSINT_FETCH_ALLOW": "cyfirma.com,cisa.gov", "OSINT_FETCH_DENY": ""}):
            self.assertTrue(egress.host_allowed("www.cyfirma.com"))
            self.assertFalse(egress.host_allowed("example.org"))
        with patch.dict(os.environ, {"OSINT_FETCH_ALLOW": "", "OSINT_FETCH_DENY": ""}):
            self.assertFalse(egress.host_allowed("c2.example.org", extra_deny=["c2.example.org"]))
            self.assertTrue(egress.host_allowed("benign.example.org", extra_deny=["c2.example.org"]))

    def _record_connections(self):
        calls = []

        def fake(address, *args, **kwargs):
            calls.append(tuple(address))
            raise OSError("connection blocked for the test")

        return calls, fake

    def test_proxy_routes_connection_to_the_proxy_not_the_target(self):
        calls, fake = self._record_connections()
        with patch.dict(os.environ, {"OSINT_HTTP_PROXY": "http://127.0.0.1:3129"}), \
             patch.object(socket, "create_connection", side_effect=fake):
            with self.assertRaises(Exception):
                collectors.download("https://example.org/data.json")
        self.assertTrue(calls, "download opened no connection")
        self.assertEqual(calls[0], ("127.0.0.1", 3129))
        self.assertTrue(all(host == "127.0.0.1" for host, _ in calls),
                        "a direct connection was opened despite the proxy")

    def test_without_proxy_connects_directly_to_the_target(self):
        calls, fake = self._record_connections()
        with patch.dict(os.environ, {"OSINT_HTTP_PROXY": ""}), \
             patch.object(socket, "create_connection", side_effect=fake):
            with self.assertRaises(Exception):
                collectors.download("https://example.org/data.json")
        self.assertTrue(calls)
        self.assertEqual(calls[0][0], "example.org")

    def test_page_reader_tunnels_through_the_proxy(self):
        calls, fake = self._record_connections()
        with patch.dict(os.environ, {"OSINT_HTTP_PROXY": "http://127.0.0.1:3130", "OSINT_FETCH_DENY": "",
                                     "OSINT_FETCH_ALLOW": ""}), \
             patch.object(socket, "create_connection", side_effect=fake):
            with self.assertRaises(Exception):
                public_pages.request("https://example.org/report")
        self.assertTrue(calls, "the page reader opened no connection")
        self.assertEqual(calls[0], ("127.0.0.1", 3130))

    def test_page_reader_refuses_a_denied_host_before_connecting(self):
        calls, fake = self._record_connections()
        with patch.dict(os.environ, {"OSINT_FETCH_DENY": "example.org", "OSINT_HTTP_PROXY": ""}), \
             patch.object(socket, "create_connection", side_effect=fake):
            with self.assertRaisesRegex(ValueError, "allow/deny"):
                public_pages.request("https://example.org/report")
        self.assertEqual(calls, [], "a denied host must not open any connection")


if __name__ == "__main__":
    unittest.main()
