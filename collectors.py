"""Search adapters. Requests only go to the configured public indexes."""
import csv
import io
import json
import os
import re
import threading
import time
from html import unescape
from itertools import islice
from pathlib import Path
from urllib.parse import quote, urlencode, urlsplit
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener

import public_pages


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def download(endpoint, headers=None, limit=2_000_000):
    request = Request(endpoint, headers={
        "User-Agent": "OpenInvestigation/1.0 (interactive public-source research)",
        "Accept": "application/json",
        **(headers or {}),
    })
    with build_opener(NoRedirects()).open(request, timeout=10) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Resposta acima do limite de tamanho.")
    return data


def fetch(endpoint, params):
    return json.loads(download(endpoint + "?" + urlencode(params)))


def clean(value):
    return unescape(re.sub(r"<[^>]*>", "", str(value))).strip()


def phrase_match(text, phrase):
    terms = phrase.split()
    if not terms:
        return None
    pattern = r"(?<!\w)" + r"\s+".join(map(re.escape, terms)) + r"(?!\w)"
    return re.search(pattern, text, re.IGNORECASE)


def name_match(value, name):
    return bool(phrase_match(public_pages.name_key(value), public_pages.name_key(name)))


def identity_match(title, url, excerpt, identity):
    if not name_match(title, identity["target"]) and not name_match(excerpt, identity["target"]):
        return False
    reference = identity["reference"]
    if identity["target_type"] == "organization":
        host = urlsplit(url).hostname or ""
        if host == reference or host.endswith("." + reference):
            return True
        text = title + "\n" + excerpt
        # Match a complete DNS suffix; refuse lookalike hosts such as org.com.example.
        pattern = r"(?<![\w@-])" + re.escape(reference) + r"(?![\w-]|\.[\w-])"
        return bool(re.search(pattern, text, re.IGNORECASE))
    candidates = [url, *re.findall(r'https?://[^\s<>"]+', title + "\n" + excerpt)]
    for candidate in candidates:
        try:
            if public_pages.same_page(candidate.rstrip(".,);"), reference):
                return True
        except ValueError:
            continue
    return False


def wikipedia(query):
    data = fetch("https://pt.wikipedia.org/w/api.php", {
        "action": "query", "list": "search", "srsearch": '"' + query.replace('"', "") + '"',
        "srlimit": 6, "srnamespace": 0, "format": "json",
    })
    for item in data["query"]["search"]:
        yield item["title"], f'https://pt.wikipedia.org/?curid={int(item["pageid"])}', item["snippet"]


def crossref(query):
    data = fetch("https://api.crossref.org/works", {
        "query.bibliographic": query, "rows": 5,
        "select": "DOI,title,container-title,publisher",
    })
    for item in data["message"]["items"]:
        title = (item.get("title") or [""])[0]
        context = (item.get("container-title") or [item.get("publisher", "")])[0]
        yield title, f'https://doi.org/{item["DOI"]}', context


GDELT_DOC = "https://api.gdeltproject.org/api/v2/doc/doc"
CVM_CSV = "https://dados.cvm.gov.br/dados/cia_aberta/CAD/DADOS/cad_cia_aberta.csv"
_cvm_lock = threading.Lock()
_cvm_expires = 0
_cvm_rows = ()


def gdelt(query):
    phrase = " ".join(query.replace('"', " ").split())
    if not phrase:
        return
    data = fetch(GDELT_DOC, {
        "query": '"' + phrase + '"', "mode": "artlist", "format": "json",
        "maxrecords": 20, "timespan": "3m",
    })
    if not isinstance(data, dict):
        raise ValueError("Formato inesperado do GDELT.")
    for item in data.get("articles", []):
        metadata = [f"Consulta GDELT: {phrase}"]
        if item.get("domain"):
            metadata.append(f"Veículo: {item['domain']}")
        seen = item.get("seendate", "")
        if re.fullmatch(r"\d{8}T\d{6}Z", seen):
            metadata.append(f"Indexado em {seen[:4]}-{seen[4:6]}-{seen[6:8]} (UTC)")
        yield item.get("title", ""), item.get("url", ""), " · ".join(metadata)


def cvm_records():
    global _cvm_expires, _cvm_rows
    with _cvm_lock:
        if time.monotonic() < _cvm_expires:
            return _cvm_rows
        raw = download(CVM_CSV, {"Accept": "text/csv"}, limit=8_000_000)
        try:
            decoded = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            decoded = raw.decode("latin-1")
        reader = csv.DictReader(io.StringIO(decoded), delimiter=";")
        if not {"DENOM_SOCIAL", "CNPJ_CIA", "CD_CVM"} <= set(reader.fieldnames or ()):
            raise ValueError("Colunas do cadastro CVM indisponíveis.")
        _cvm_rows = tuple((reader.line_num, row) for row in reader)
        _cvm_expires = time.monotonic() + 3600
        return _cvm_rows


def company_name(value):
    words = re.findall(r"[^\W_]+", public_pages.name_key(value))
    if words[-2:] == ["s", "a"]:
        words = words[:-2]
    elif words[-1:] == ["sa"]:
        words = words[:-1]
    return " ".join(words)


def cvm(query):
    name = company_name(query)
    if not name:
        return
    cnpj = public_pages.cnpj_value(query)
    matches = 0
    for row_number, row in cvm_records():
        social = row["DENOM_SOCIAL"] or ""
        trade = row.get("DENOM_COMERC") or ""
        registration = row["CNPJ_CIA"] or ""
        same_cnpj = bool(cnpj) and cnpj == public_pages.cnpj_value(registration)
        if not same_cnpj and name not in {company_name(social), company_name(trade)}:
            continue
        details = [f"Consulta CVM: {query}"]
        for label, key in (("CNPJ", "CNPJ_CIA"), ("Código CVM", "CD_CVM"),
                           ("Nome comercial", "DENOM_COMERC"), ("Situação", "SIT_REG"),
                           ("Setor", "SETOR_ATIV")):
            if row.get(key):
                details.append(f"{label}: {row[key]}")
        yield social, f"{CVM_CSV}#row={row_number}", " · ".join(details)
        matches += 1
        if matches == 15:
            break


def querido_diario(query):
    phrase = " ".join(query.replace('"', " ").split())
    if not phrase:
        return
    data = fetch("https://api.queridodiario.ok.org.br/gazettes", {
        "querystring": '"' + phrase + '"', "excerpt_size": 500, "number_of_excerpts": 1, "size": 12,
    })
    for item in data["gazettes"]:
        territory = item.get("territory_name") or "município não informado"
        date = item.get("date") or "data não informada"
        snippets = " ".join(item.get("excerpts") or [])
        excerpt = f"Consulta: {phrase} · Edição de {date} · {snippets}"
        yield f"Diário oficial de {territory} · {date}", item.get("url") or "", excerpt


def camara(query):
    data = fetch("https://dadosabertos.camara.leg.br/api/v2/deputados", {"nome": query, "itens": 15})
    for item in data["dados"]:
        name = item.get("nome") or ""
        identifier = item.get("id")
        if not isinstance(identifier, int) or not name_match(name, query):
            continue
        party = item.get("siglaPartido") or ""
        uf = item.get("siglaUf") or ""
        excerpt = f"Consulta: {query} · Nome parlamentar: {name} · Partido: {party} · UF: {uf}"
        yield name, f"https://www.camara.leg.br/deputados/{identifier}", excerpt


def minha_receita(query):
    cnpj = public_pages.cnpj_value(query)
    if not cnpj:
        return
    url = "https://minhareceita.org/" + cnpj
    try:
        data = json.loads(download(url))
    except HTTPError as error:
        if error.code == 404:
            return
        raise
    if public_pages.cnpj_value(str(data.get("cnpj") or "")) != cnpj:
        raise ValueError("Resposta não corresponde ao CNPJ consultado.")
    fields = [f"CNPJ: {cnpj}"]
    for label, key in (("Nome fantasia", "nome_fantasia"), ("Situação", "descricao_situacao_cadastral"),
                       ("Atividade", "cnae_fiscal_descricao"), ("Município", "municipio"), ("UF", "uf")):
        if data.get(key):
            fields.append(f"{label}: {data[key]}")
    yield data.get("razao_social") or cnpj, url, " · ".join(fields)
    address = []
    street = " ".join(str(data[key]) for key in ("descricao_tipo_de_logradouro", "logradouro", "numero")
                      if data.get(key))
    if street:
        address.append(street)
    address.extend(str(data[key]) for key in ("complemento", "bairro", "municipio", "uf", "cep") if data.get(key))
    if address:
        yield "Endereço cadastral · " + cnpj, url + "#endereco", " · ".join(address)
    partners = []
    for row in data.get("qsa") or []:
        if not isinstance(row, dict) or not row.get("nome_socio"):
            continue
        name = str(row["nome_socio"]).strip()
        role = str(row.get("qualificacao_socio") or "").strip()
        display = f"{name} · {role}" if role else name
        if display not in partners:
            partners.append(display)
    if partners:
        for index in range(0, min(len(partners), 30), 4):
            chunk = partners[index:min(index + 4, 30)]
            title = f"QSA · {cnpj} · {index + 1}–{index + len(chunk)} de {len(partners)}"
            yield title, f"{url}#qsa-{index + 1}", " | ".join(entry[:190] for entry in chunk)


def applies(collector, identity, query):
    kind = identity["target_type"]
    if public_pages.cnpj_value(query) and collector in (gdelt, querido_diario, wikipedia, crossref, camara):
        return False
    if collector is cvm:
        return kind == "organization"
    if collector is camara:
        return kind == "individual"
    if collector is minha_receita:
        return kind == "organization" and bool(public_pages.cnpj_value(query))
    return True


def is_lead_source(collector):
    return collector in (gdelt, cvm, querido_diario, camara, minha_receita, web_search)


class SearchEnginesUnavailable(OSError):
    def __init__(self, records):
        labels = []
        for entry in records[:6]:
            if not isinstance(entry, list) or not entry or not isinstance(entry[0], str):
                continue
            engine = entry[0]
            if not re.fullmatch(r"[\w .-]{1,32}", engine):
                continue
            reason = str(entry[1]).casefold() if len(entry) > 1 else ""
            state = ("CAPTCHA" if "captcha" in reason else "rate limited" if any(
                key in reason for key in ("429", "too many", "rate limit")) else "timeout" if any(
                key in reason for key in ("timeout", "timed out")) else "unavailable")
            labels.append(f"{engine}: {state}")
        super().__init__("No search engine returned results" + (" · " + "; ".join(labels) if labels else ""))


def web_search(query):
    endpoint = os.getenv("OSINT_SEARCH_URL", "").strip()
    if not endpoint:
        return
    data = fetch(endpoint, {"q": query, "format": "json", "language": "all", "categories": "general"})
    rows = data.get("results")
    if not isinstance(rows, list):
        raise ValueError("Unexpected web search response format.")
    unavailable = data.get("unresponsive_engines")
    if not rows and isinstance(unavailable, list) and unavailable:
        raise SearchEnginesUnavailable(unavailable)
    for row in rows[:8]:
        if not isinstance(row, dict):
            continue
        excerpt = clean(row.get("content") or "")
        yield row.get("title") or "", row.get("url") or "", f"Query: {query} · {excerpt}"


def web_queries(query, identity, root):
    phrase = " ".join(query.replace('"', " ").split())
    if not phrase:
        return []
    exact = f'"{phrase}"'
    if not root:
        return [exact]
    if identity["target_type"] == "organization":
        domain = identity["reference"]
        return [
            f'{exact} CNPJ',
            f'"{domain}" "razão social"',
            f'{exact} (site:casadosdados.com.br OR site:cnpj.biz OR site:econodata.com.br OR site:transparencia.cc)',
            f'{exact} ("quadro societário" OR "contrato social" OR "ata de assembleia")',
            f'{exact} (site:in.gov.br OR site:queridodiario.ok.org.br OR site:dados.cvm.gov.br)',
            f'{exact} (site:linkedin.com/company OR site:instagram.com OR site:youtube.com)',
            f'{exact} ("entrevista" OR "evento" OR "publicação")',
        ]
    profile = public_pages.linked_profile(identity["reference"])
    anchor = f' "{profile}"' if profile else ""
    return [
        exact + anchor,
        f'{exact} (site:instagram.com OR site:github.com OR site:youtube.com)',
        f'{exact} ("empresa" OR "professor" OR "fundador")',
        f'{exact} ("palestrante" OR "entrevista" OR "publicação")',
    ]


def corpus(query):
    root = Path(os.getenv("OSINT_CORPUS_DIR", "./corpus"))
    matches = []
    for path in islice(root.iterdir(), 2000) if root.is_dir() else ():
        if path.is_symlink() or not path.is_file() or path.suffix.lower() not in {".txt", ".md", ".csv", ".json"}:
            continue
        with path.open(encoding="utf-8", errors="replace") as source:
            content = source.read(500_000)
        match = phrase_match(content, query)
        if not match and not phrase_match(path.name, query):
            continue
        offset = match.start() if match else 0
        end = max(offset + 380, match.end() if match else 0)
        excerpt = " ".join(content[max(0, offset - 140):end].split())
        matches.append((path.name, excerpt))
    for title, excerpt in sorted(matches)[:15]:
        yield title, "", excerpt


def sources():
    enabled = {"Corpus local": corpus}
    if os.getenv("OSINT_WEB", "1") == "1":
        enabled.update({"Wikipédia": wikipedia, "Crossref": crossref,
                        "GDELT": gdelt, "CVM": cvm, "Querido Diário": querido_diario,
                        "Câmara dos Deputados": camara, "Minha Receita": minha_receita})
    if os.getenv("OSINT_WEB", "1") == "1" and os.getenv("OSINT_SEARCH_URL", "").strip():
        enabled["Busca web"] = web_search
    return enabled


def items(collector, query):
    for title, url, excerpt in collector(query):
        if collector is corpus:
            yield title[:300], "corpus:" + quote(title, safe=""), excerpt[:900]
            continue
        try:
            parsed = urlsplit(url)
            valid = parsed.scheme in ("http", "https") and parsed.hostname and not parsed.username
        except ValueError:
            continue
        if valid and len(url) <= 2000 and clean(title):
            yield clean(title)[:300], url, clean(excerpt)[:900]
