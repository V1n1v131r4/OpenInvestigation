"""Configurable outbound egress: User-Agent, optional proxy, and host allow/deny.

Environment:
- OSINT_USER_AGENT  Outbound User-Agent. Neutral default when unset.
- OSINT_HTTP_PROXY  http:// (recommended) or https:// proxy for all outbound requests. When set it is
                    the only proxy used; when unset, no proxy is used (system proxy env is ignored for
                    determinism). SOCKS is not supported by the standard library and is rejected.
- OSINT_FETCH_ALLOW Comma-separated host suffixes. When set, only matching hosts may be fetched by the
                    page reader (public_pages). Empty means allow all (subject to deny).
- OSINT_FETCH_DENY  Comma-separated host suffixes always refused by the page reader.

A suffix matches a host exactly or as a parent domain: "evil.test" matches "evil.test" and "a.evil.test".
"""
import os
from urllib.parse import urlsplit
from urllib.request import ProxyHandler

DEFAULT_USER_AGENT = "OpenInvestigation/1.0 (interactive public-source research)"


def user_agent():
    return os.getenv("OSINT_USER_AGENT", "").strip() or DEFAULT_USER_AGENT


def proxy_url():
    url = os.getenv("OSINT_HTTP_PROXY", "").strip()
    if not url:
        return ""
    scheme = urlsplit(url).scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError("OSINT_HTTP_PROXY must be an http:// or https:// URL; "
                         "SOCKS is not supported by the standard library.")
    return url


def proxy_handlers():
    """Handlers to splat into urllib.request.build_opener so OSINT_HTTP_PROXY is authoritative."""
    url = proxy_url()
    return [ProxyHandler({"http": url, "https": url} if url else {})]


def _suffixes(variable):
    return [host.strip().lower().rstrip(".") for host in os.getenv(variable, "").split(",") if host.strip()]


def _matches(host, suffix):
    return host == suffix or host.endswith("." + suffix)


def host_allowed(host, extra_deny=()):
    host = (host or "").lower().rstrip(".")
    if not host:
        return False
    deny = _suffixes("OSINT_FETCH_DENY") + [str(entry).lower().rstrip(".") for entry in extra_deny]
    if any(_matches(host, suffix) for suffix in deny if suffix):
        return False
    allow = _suffixes("OSINT_FETCH_ALLOW")
    return not allow or any(_matches(host, suffix) for suffix in allow)
