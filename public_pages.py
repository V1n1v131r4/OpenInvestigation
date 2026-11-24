"""Read a confirmed public page, without crawling linked sites."""
import http.client
import ipaddress
import json
import re
import socket
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import egress


def is_official_host(host, domain):
    return bool(host and (host == domain or host.endswith("." + domain)))


def public_address(host, port):
    addresses = [entry[4][0] for entry in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)]
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError("O domínio não resolve exclusivamente para endereços públicos.")
    return list(dict.fromkeys(addresses))


def request(url, deny_hosts=()):
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.port is not None):
        raise ValueError("A coleta da referência requer HTTPS público sem porta personalizada.")
    if not egress.host_allowed(parsed.hostname, deny_hosts):
        raise ValueError("Host recusado pela política de allow/deny de coleta.")
    proxy = egress.proxy_url()
    if proxy:
        # Route through the proxy with a CONNECT tunnel; it resolves the host, so skip local IP
        # pinning. The host was validated above before anything was sent.
        endpoint = urlsplit(proxy)
        conn = http.client.HTTPSConnection(endpoint.hostname, endpoint.port or 80, timeout=6)
        conn.set_tunnel(parsed.hostname, 443)
    else:
        addresses = public_address(parsed.hostname, 443)
        conn = http.client.HTTPSConnection(parsed.hostname, timeout=6)

        def connect_pinned(_address, timeout=None, source_address=None):
            # Resolve once, connect only to a validated IP, and retain the original TLS hostname.
            for address in addresses[:3]:
                try:
                    return socket.create_connection((address, 443), timeout, source_address)
                except OSError as error:
                    last_error = error
            raise last_error

        conn._create_connection = connect_pinned
    path = (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
    try:
        conn.request("GET", path, headers={"User-Agent": egress.user_agent(), "Accept": "text/html"})
        with conn.getresponse() as response:
            if response.status in (301, 302, 303, 307, 308):
                return response.status, response.getheader("Location"), ""
            if response.status != 200:
                raise OSError(f"HTTP {response.status}")
            mime = response.headers.get_content_type()
            if mime not in ("text/html", "application/xhtml+xml"):
                raise ValueError("A referência não retornou uma página HTML.")
            body = response.read(1_500_001)
            if len(body) > 1_500_000:
                raise ValueError("Página acima do limite de 1,5 MB.")
            charset = response.headers.get_content_charset() or "utf-8"
            return response.status, None, body.decode(charset, errors="replace")
    finally:
        conn.close()


class Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.title = ""
        self.description = ""
        self.heading = []
        self.content = []
        self.section = None
        self.skip = None
        self.metadata = []
        self.current_metadata = None
        self.links = []
        self.anchors = []
        self.anchor = None
        self.canonical = ""
        self.generator = ""
        self.publication_date = ""

    def handle_starttag(self, tag, attrs):
        if self.skip:
            return
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            self.anchor = (attrs["href"], [attrs.get("aria-label") or attrs.get("title") or ""])
        if tag == "script" and (attrs.get("type") or "").lower() == "application/ld+json":
            self.current_metadata = []
        if tag in ("script", "style", "noscript", "template", "svg"):
            self.skip = tag
        if tag in ("link", "a") and "me" in (attrs.get("rel") or "").lower().split():
            self.links.append(attrs.get("href") or "")
        if tag == "link" and "canonical" in (attrs.get("rel") or "").lower().split():
            self.canonical = attrs.get("href") or ""
        if tag in ("title", "h1"):
            self.section = tag
        if tag == "meta":
            field = (attrs.get("name") or attrs.get("property") or "").lower()
            if field in ("description", "og:description") and not self.description:
                self.description = attrs.get("content") or ""
            if field == "generator" and not self.generator:
                self.generator = attrs.get("content") or ""
            if field in ("article:published_time", "datepublished") and not self.publication_date:
                self.publication_date = attrs.get("content") or ""

    def handle_endtag(self, tag):
        if tag == "a" and self.anchor:
            href, labels = self.anchor
            self.anchors.append((href, " ".join(" ".join(labels).split())))
            self.anchor = None
        if tag == self.skip:
            self.skip = None
        if tag == "script" and self.current_metadata is not None:
            try:
                self.metadata.append(json.loads("".join(self.current_metadata)))
            except (ValueError, RecursionError):
                pass
            self.current_metadata = None
        if tag == self.section:
            self.section = None

    def handle_data(self, data):
        if self.current_metadata is not None:
            self.current_metadata.append(data)
        if self.skip or not data.strip():
            return
        if self.anchor:
            self.anchor[1].append(data.strip())
        if self.section == "title":
            self.title += data.strip() + " "
        elif self.section == "h1":
            self.heading.append(data.strip())
        else:
            self.content.append(data.strip())


def secondary_page(address, domain, load=None):
    load = load or request
    for _ in range(3):
        url = urlsplit(address)
        if not is_official_host(url.hostname, domain) or url.query:
            raise ValueError("Redirecionamento fora do site institucional.")
        _, location, html = load(address)
        if location:
            address = urljoin(address, location)
            continue
        page = Page()
        page.feed(html)
        title = " ".join(page.title.split()) or " ".join(page.heading)
        content = " ".join(" ".join(page.content).split())
        excerpt = " ".join([*page.heading, page.description or content]).strip()
        if not title or not excerpt:
            raise ValueError("Página institucional sem título ou texto público.")
        return page, title[:300], address, excerpt[:900], content
    raise ValueError("Redirecionamentos demais.")
