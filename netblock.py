"""Block non-loopback network access so the unit suite cannot reach the internet.

Importing test_support installs this guard for the whole discovery/run process. Loopback
(127.0.0.1, ::1, localhost) stays allowed so an in-process or local server keeps working;
any other host raises, turning an accidental live request into an immediate test failure.
The opt-in HTTP workflow check (test_docker_workflow.py) does not import this and is unaffected.
"""
import socket

_ALLOWED_HOSTS = {"127.0.0.1", "::1", "localhost", "", None}
_real_getaddrinfo = socket.getaddrinfo
_installed = False


def _host_of(address):
    if isinstance(address, (tuple, list)) and address:
        return address[0]
    return address


class _GuardedSocket(socket.socket):
    def connect(self, address):
        self._guard(address)
        return super().connect(address)

    def connect_ex(self, address):
        self._guard(address)
        return super().connect_ex(address)

    @staticmethod
    def _guard(address):
        if _host_of(address) not in _ALLOWED_HOSTS:
            raise RuntimeError(f"Network access is blocked during tests: {address!r}")


def _guarded_getaddrinfo(host, *args, **kwargs):
    if host not in _ALLOWED_HOSTS:
        raise RuntimeError(f"DNS resolution is blocked during tests: {host!r}")
    return _real_getaddrinfo(host, *args, **kwargs)


def install():
    global _installed
    if _installed:
        return
    socket.socket = _GuardedSocket
    socket.getaddrinfo = _guarded_getaddrinfo
    _installed = True
