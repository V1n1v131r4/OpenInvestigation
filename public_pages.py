"""Read the confirmed public page, without crawling linked sites."""
import http.client
import ipaddress
import json
import re
import socket
from html.parser import HTMLParser
from unicodedata import combining, normalize
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit


def name_key(value):
    return "".join(char for char in normalize("NFKD", value) if not combining(char)).casefold()


def cnpj_value(value):
    value = re.sub(r"[./\s-]", "", value).upper()
    if not re.fullmatch(r"[A-Z0-9]{12}[0-9]{2}", value) or len(set(value)) == 1:
        return ""
    base = value[:12]
    for _ in range(2):
        total = sum((ord(char) - 48) * (2 + index % 8) for index, char in enumerate(reversed(base)))
        remainder = total % 11
        base += str(0 if remainder < 2 else 11 - remainder)
    return value if base == value else ""


def linked_profile(url):
    parsed = urlsplit(url)
    if not re.fullmatch(r"(?:(?:www|[a-z]{2})\.)?linkedin\.com", parsed.hostname or ""):
        return None
    match = re.fullmatch(r"/in/([\w-]+)(?:/[a-z]{2}(?:-[a-z]{2})?)?/?", parsed.path, re.I)
    return match[1].casefold() if match else None


def same_page(left, right):
    left_profile, right_profile = linked_profile(left), linked_profile(right)
    if left_profile and right_profile:
        return left_profile == right_profile
    a, b = urlsplit(left), urlsplit(right)
    return ((a.hostname or "").removeprefix("www."), a.path.rstrip("/"), a.query) == (
        (b.hostname or "").removeprefix("www."), b.path.rstrip("/"), b.query
    )


def is_official_host(host, domain):
    return bool(host and (host == domain or host.endswith("." + domain)))


def public_address(host, port):
    addresses = [entry[4][0] for entry in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)]
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError("O domínio não resolve exclusivamente para endereços públicos.")
    return list(dict.fromkeys(addresses))


def request(url):
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.port is not None):
        raise ValueError("A coleta da referência requer HTTPS público sem porta personalizada.")
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
        conn.request("GET", path, headers={"User-Agent": "OpenInvestigation/1.0", "Accept": "text/html"})
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


def collect(identity, load=None, links=None, institutional_page=None):
    load = load or request
    organization = identity["target_type"] == "organization"
    reference = identity["reference"]
    seed = "https://" + reference + "/" if organization else reference
    profile = linked_profile(seed)
    urls = [seed]
    if profile:
        urls = [f"https://www.linkedin.com/in/{profile}/", f"https://br.linkedin.com/in/{profile}/en"]
    error = None
    for url in urls:
        try:
            for _ in range(4):
                parsed = urlsplit(url)
                if organization and not is_official_host(parsed.hostname, reference):
                    raise ValueError("Redirecionamento fora do domínio confirmado.")
                if not organization and not same_page(seed, url):
                    raise ValueError("Redirecionamento fora do perfil confirmado.")
                _, location, html = load(url)
                if location:
                    url = urljoin(url, location)
                    continue
                page = Page()
                page.feed(html)
                title = " ".join(page.title.split())
                if page.heading and (not title or (profile and title.casefold() == "linkedin")):
                    title = page.heading[0]
                body = " ".join(" ".join([*page.heading, *page.content]).split())
                detail = page.description or body
                description = " ".join(" ".join([*page.heading, detail]).split())
                if not organization:
                    name = name_key(" ".join(identity["target"].split()))
                    if name not in name_key(title + " " + description[:900]):
                        offset = name_key(body).find(name)
                        if offset >= 0:
                            description = body[max(0, offset - 180):offset + 650]
                if not title or not description:
                    raise ValueError("Página sem título ou texto público.")
                if links is not None:
                    links.extend(published_links(page, url, identity))
                    if organization:
                        links.extend(institution_details(page, url, identity, body))
                        links.extend(public_channels(page, url, reference))
                if institutional_page is not None:
                    institutional_page.extend(institutional_urls(page, url, reference))
                return title[:300], url, description[:900]
            raise ValueError("Redirecionamentos demais.")
        except (OSError, ValueError, http.client.HTTPException) as exc:
            error = exc
    raise error


def objects(value):
    return value if isinstance(value, list) else [value]


PAGE_RELEVANCE = re.compile(
    r"(?:^|[ /_.-])(?:contato|contact|sobre|about|quem-somos|institucional|termos|terms|privacidade|privacy|"
    r"politica|policy|imprensa|press|publicacoes|publications|relatorios|relatorio|faq|equipe|team)(?:$|[ /_.-])"
)


def institutional_urls(page, source, domain):
    seen = {source.rstrip("/")}
    for href, label in page.anchors:
        try:
            url = urlsplit(urljoin(source, href))
            if (url.scheme != "https" or not is_official_host(url.hostname, domain) or url.username is not None
                    or url.port is not None or url.query or not PAGE_RELEVANCE.search(name_key(url.path + " " + label))):
                continue
            if re.search(r"(?:^|/)(?:login|admin|wp-admin|dashboard|account|checkout|logout)(?:/|$)", url.path, re.I):
                continue
            address = url._replace(fragment="").geturl()
        except ValueError:
            continue
        if address.rstrip("/") not in seen and not re.search(r"\.(pdf|docx?|xlsx?|zip)$", url.path, re.I):
            seen.add(address.rstrip("/"))
            yield address


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


def public_channels(page, source, domain):
    seen = set()
    for href, label in page.anchors:
        if len(href) > 2000:
            continue
        category = ""
        try:
            parsed = urlsplit(urljoin(source, href))
            host = parsed.hostname or ""
            if parsed.scheme == "mailto":
                email = parsed.path.lower()
                if not re.fullmatch(r"(?:contato|contact|info|suporte|support|comercial|sales|atendimento|imprensa|press|dpo|privacidade|hello)@[a-z0-9.-]+", email):
                    continue
                if is_official_host(email.rsplit("@", 1)[1], domain):
                    yield "Contato institucional", email, source + "#contato-" + email.split("@")[0], f"E-mail publicado em {source}."
                continue
            if parsed.scheme == "tel":
                phone = re.sub(r"[^0-9+]", "", parsed.path)
                if re.fullmatch(r"\+?\d{8,15}", phone) and phone not in seen:
                    seen.add(phone)
                    yield "Contato institucional", phone, source + "#telefone-" + phone.lstrip("+"), f"Telefone publicado em {source}."
                continue
            if parsed.scheme not in ("https", "http") or not host or parsed.username is not None:
                continue
            address = parsed._replace(query="", fragment="").geturl()
            path = parsed.path.strip("/")
            if host in {"wa.me", "api.whatsapp.com", "www.whatsapp.com"}:
                phone = path if host == "wa.me" else parse_qs(parsed.query).get("phone", [""])[0]
                if not re.fullmatch(r"\+?\d{8,15}", phone):
                    continue
                category = "WhatsApp publicado"
                address = parsed._replace(fragment="", query="" if host == "wa.me" else urlencode({"phone": phone})).geturl()
            elif (host.removeprefix("www.") in {"linkedin.com", "br.linkedin.com"} and path.startswith("company/")) or (
                    host.removeprefix("www.") in {"instagram.com", "facebook.com", "youtube.com", "x.com"}
                    and path and not any(path.startswith(prefix) for prefix in ("share", "watch", "p/", "reel/", "intent"))
                    and name_key(label).strip() in {"instagram", "facebook", "youtube", "linkedin", "x", "twitter"}):
                category = "Canal institucional publicado"
            elif is_official_host(host, domain) and re.search(r"\.pdf$", path, re.I) and re.search(
                    r"(?:relatorio|politica|estatuto|demonstrativo|manual|guia|balanco|assembleia)", name_key(path + " " + label)):
                category = "Documento público publicado"
            elif is_official_host(host, domain) and host != urlsplit(source).hostname and "blog" in name_key(label + " " + host):
                category = "Canal institucional publicado"
            if not category or address in seen:
                continue
            seen.add(address)
            yield category, (label or host + parsed.path)[:300], address, f"Link publicado em {source}."
            if len(seen) >= 15:
                return
        except ValueError:
            continue


def published_cnpjs(body):
    pattern = r"\bCNPJ\s*(?:n[.°º]\s*)?[:#–-]?\s*((?:[A-Z0-9]{2}\.[A-Z0-9]{3}\.[A-Z0-9]{3}/[A-Z0-9]{4}-[0-9]{2}|[A-Z0-9]{12}[0-9]{2}))(?![A-Z0-9])"
    return list(dict.fromkeys(filter(None, (cnpj_value(match) for match in re.findall(pattern, body, re.I)))))


def institution_details(page, source, identity, body):
    identifiers = published_cnpjs(body)
    for identifier in identifiers[:5]:
        label = "CNPJ declarado" if len(identifiers) == 1 else "CNPJ a conferir"
        url = urlsplit(source)._replace(fragment="cnpj-" + identifier).geturl()
        yield label, f"CNPJ {identifier}", url, f"Identificador publicado em {source}."

    try:
        canonical = urlsplit(urljoin(source, page.canonical))
        if (canonical.scheme in ("http", "https") and canonical.hostname and canonical.username is None
                and not is_official_host(canonical.hostname, identity["reference"])):
            yield ("Domínio canônico declarado", canonical.hostname, canonical.geturl(),
                   f"A página {source} declara este endereço como canônico.")
    except ValueError:
        pass

    product = re.split(r"[\s/]v?\d", " ".join(page.generator.split()), maxsplit=1, flags=re.I)[0]
    if product:
        yield "Tecnologia declarada", product[:100], source, f"Gerador informado pela página pública {source}."


def published_links(page, source, identity):
    """Extract explicit declarations from a subject's page, with source provenance."""
    target = name_key(" ".join(identity["target"].split()))
    organization = identity["target_type"] == "organization"
    entities = []
    for value in page.metadata:
        for node in objects(value):
            if isinstance(node, dict):
                entities.extend(objects(node.get("@graph", [])))
                entities.extend(objects(node.get("mainEntity", [])))
                entities.append(node)
    descriptors = []
    if not organization and (linked_profile(source) or any(
            isinstance(node, dict) and "Person" in objects(node.get("@type"))
            and isinstance(node.get("name"), str) and name_key(" ".join(node["name"].split())) == target
            for node in entities
    )):
        descriptors.extend(("Perfil declarado", "", link) for link in page.links)
    for node in entities:
        if not isinstance(node, dict) or not isinstance(node.get("name"), str):
            continue
        types = objects(node.get("@type"))
        if not organization and "Person" not in types:
            continue
        if name_key(" ".join(node["name"].split())) != target:
            continue
        for field, label in (("sameAs", "Perfil declarado"), ("worksFor", "Vínculo profissional declarado"),
                             ("affiliation", "Afiliação declarada"), ("citation", "Citação publicada")):
            for raw in objects(node.get(field, [])):
                if isinstance(raw, str):
                    descriptors.append((label, "", raw))
                elif isinstance(raw, dict) and isinstance(raw.get("url"), str):
                    name = raw.get("name")
                    descriptors.append((label, name if isinstance(name, str) else "", raw["url"]))

    seen = set()
    for label, title, raw in descriptors:
        if not raw.startswith(("https://", "http://")):
            continue
        try:
            parsed = urlsplit(raw)
            host = parsed.hostname
            if not host or parsed.username is not None or len(raw) > 2000 or same_page(raw, source) or raw in seen:
                continue
        except ValueError:
            continue
        seen.add(raw)
        if (organization and label == "Perfil declarado" and not parsed.path.strip("/")
                and not is_official_host(host, identity["reference"])):
            label = "Domínio alternativo declarado"
        yield label, (title or (host + parsed.path))[:300], raw, f"{label} na página {source}"[:900]
        if len(seen) >= 20:
            break
