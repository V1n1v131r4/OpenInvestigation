"""Local case storage, collection workers, and HTTP interface."""
import json
import runpy
import re
import os
import secrets
import socket
import sqlite3
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit

import collectors
import cti
import public_pages

STATIC = Path(__file__).parent / "static"
DB = Path(os.getenv("OSINT_DATA_DIR", "./data")) / "cases.sqlite3"
WORKERS = ThreadPoolExecutor(max_workers=3)
COLLECTORS = ThreadPoolExecutor(max_workers=6)
SESSION = secrets.token_urlsafe(24)
SOURCE_MAP = collectors.sources()
DIAGNOSTICS = ThreadPoolExecutor(max_workers=3)
DIAGNOSTIC_LOCK = Lock()
DIAGNOSTIC_ROWS = {}
DIAGNOSTIC_STARTED = None


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def database():
    with closing(sqlite3.connect(DB, timeout=10)) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        with conn:
            yield conn


def initialize():
    DB.parent.mkdir(parents=True, exist_ok=True)
    with database() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        cti.initialize(conn)
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY, target TEXT NOT NULL,
                goal TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS searches (
                id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL REFERENCES cases(id),
                parent_id INTEGER REFERENCES results(id), query TEXT NOT NULL,
                status TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY, search_id INTEGER NOT NULL REFERENCES searches(id),
                source TEXT NOT NULL, title TEXT NOT NULL, url TEXT NOT NULL,
                excerpt TEXT NOT NULL, collected_at TEXT NOT NULL,
                UNIQUE(search_id, source, url)
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY, search_id INTEGER NOT NULL REFERENCES searches(id),
                source TEXT, state TEXT NOT NULL, message TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS reviews (
                id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL REFERENCES cases(id),
                claim TEXT NOT NULL, rationale TEXT NOT NULL, evidence TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS search_case ON searches(case_id);
            CREATE INDEX IF NOT EXISTS result_search ON results(search_id);
            CREATE INDEX IF NOT EXISTS event_search ON events(search_id);
        """)
        for table, name, default in (
            ("cases", "target_type", "TEXT NOT NULL DEFAULT ''"),
            ("cases", "reference", "TEXT NOT NULL DEFAULT ''"),
            ("searches", "identity_scoped", "INTEGER NOT NULL DEFAULT 0"),
        ):
            columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
            if name not in columns:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {default}")
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(results)")}
        if "published_at" not in columns:
            conn.execute("ALTER TABLE results ADD COLUMN published_at TEXT NOT NULL DEFAULT ''")
        if "is_lead" not in columns:
            conn.execute("ALTER TABLE results ADD COLUMN is_lead INTEGER NOT NULL DEFAULT 0")
        for field in ("verified_at", "verification_note", "rejected_at"):
            if field not in columns:
                conn.execute(f"ALTER TABLE results ADD COLUMN {field} TEXT NOT NULL DEFAULT ''")
        interrupted = conn.execute("SELECT id FROM searches WHERE status IN ('queued','running')").fetchall()
        for row in interrupted:
            set_status(conn, row["id"], "interrupted", "Execução interrompida ao reiniciar o serviço.")


def event(conn, search_id, state, message, source=None):
    conn.execute("INSERT INTO events VALUES (NULL, ?, ?, ?, ?, ?)",
                 (search_id, source, state, message, now()))


def set_status(conn, search_id, status, message):
    conn.execute("UPDATE searches SET status=? WHERE id=?", (status, search_id))
    event(conn, search_id, status, message)


def source_error(error):
    if isinstance(error, (collectors.SearchEnginesUnavailable, cti.ProviderError)):
        return str(error)
    if isinstance(error, HTTPError):
        if error.code == 429:
            return "HTTP 429 · source rate limit or temporary block"
        return f"HTTP {error.code}"
    reason = error.reason if isinstance(error, URLError) else error
    if isinstance(reason, socket.gaierror):
        return "DNS lookup failed for the source"
    if isinstance(reason, ssl.SSLCertVerificationError):
        return "HTTPS certificate verification failed"
    if isinstance(reason, ssl.SSLError):
        return "TLS connection failed"
    if isinstance(reason, TimeoutError):
        return "response timed out"
    if isinstance(reason, ConnectionError):
        return "connection to the source failed"
    if isinstance(reason, OSError) and re.fullmatch(r"HTTP [0-9]{3}", str(reason)):
        return str(reason)
    return type(reason).__name__


def diagnostic_results():
    with DIAGNOSTIC_LOCK:
        return {"started_at": DIAGNOSTIC_STARTED, "checks": [row.copy() for row in DIAGNOSTIC_ROWS.values()]}


def probe_source(name, collector, query):
    started = time.monotonic()
    try:
        count = sum(1 for _ in collectors.items(collector, query))
        status = "ok" if count else "empty"
        detail = f"{count} resultado(s) na consulta de controle." if count else "A fonte respondeu sem resultados."
    except Exception as error:
        status = "error"
        detail = source_error(error)
    with DIAGNOSTIC_LOCK:
        DIAGNOSTIC_ROWS[name].update(status=status, detail=detail,
                                     elapsed_ms=round((time.monotonic() - started) * 1000))


def start_diagnostics():
    global DIAGNOSTIC_STARTED
    queries = {collectors.wikipedia: "Brasil", collectors.crossref: "machine learning",
               collectors.gdelt: "Petrobras", collectors.cvm: "Petrobras",
               collectors.querido_diario: "orçamento", collectors.camara: "Átila Lira",
               collectors.minha_receita: "33.683.111/0002-80", collectors.web_search: "Brasil"}
    with DIAGNOSTIC_LOCK:
        if not any(row["status"] == "running" for row in DIAGNOSTIC_ROWS.values()):
            DIAGNOSTIC_STARTED = now()
            DIAGNOSTIC_ROWS.clear()
            for name, collector in SOURCE_MAP.items():
                query = queries.get(collector, "exemplo")
                DIAGNOSTIC_ROWS[name] = {"source": name, "query": query, "status": "running"}
                DIAGNOSTICS.submit(probe_source, name, collector, query)
    return diagnostic_results()


def cti_stage(case_id, source, callback):
    with database() as conn:
        cti.event(conn, case_id, source, "running", "Query started.", now())
    rows = []
    saved = inserted = 0
    error = None
    incremental = source in (*cti.WEB_MENTION_SOURCES, "Verificação web")
    try:
        for row in callback():
            rows.append(row)
            if incremental and len(rows) - saved >= 4:
                with database() as conn:
                    inserted += cti.save(conn, case_id, rows[saved:])
                saved = len(rows)
            if len(rows) == 1200:
                break
    except Exception as exc:
        error = source_error(exc)
    with database() as conn:
        inserted += cti.save(conn, case_id, rows[saved:])
        message = f"{inserted} new relationship(s) · {len(rows)} found."
        if error:
            message += " Source unavailable: " + error
        cti.event(conn, case_id, source, "error" if error else "done", message, now(), found=len(rows))
    return rows, bool(error)


def submit_cti_iocs(case_id, seeds, entries, sources):
    tasks = [COLLECTORS.submit(cti_stage, case_id, "MISP local", lambda: cti.misp_matches(seeds, entries))]
    has_iocs = any(seed["kind"] in ("IP", "URL", "Domínio", "Hash") for seed in seeds)
    if "Histórico local" in sources and has_iocs:
        tasks.append(COLLECTORS.submit(cti_stage, case_id, "Histórico local", lambda: cti.local_history_matches(seeds)))
    if "Relatórios históricos na web" in sources and has_iocs:
        tasks.append(COLLECTORS.submit(cti_stage, case_id, "Relatórios históricos na web",
                                       lambda: cti.historical_web_matches(seeds)))
    if "CIRCL OSINT" in sources and has_iocs:
        tasks.append(COLLECTORS.submit(cti_stage, case_id, "CIRCL OSINT", lambda: cti.circl_matches(seeds)))
    if "ThreatDefence" in sources and (has_iocs or any(seed["kind"] == "User-Agent" for seed in seeds)):
        tasks.append(COLLECTORS.submit(cti_stage, case_id, "ThreatDefence", lambda: cti.threatdefence_matches(seeds)))
    if has_iocs:
        for source, (variable, collector) in cti.authenticated_sources().items():
            if source in sources:
                tasks.append(COLLECTORS.submit(cti_stage, case_id, source,
                                               lambda collector=collector, key=os.environ[variable]: collector(seeds, key)))
    return tasks


def submit_cti_mentions(case_id, terms, sources):
    collectors_by_source = {"Busca web": cti.keyword_matches, "GitHub público": cti.github_mentions,
                            "MISP Galaxy": cti.galaxy_matches,
                            "Official cybercrime publications": cti.official_cybercrime_mentions}
    tasks = [COLLECTORS.submit(cti_stage, case_id, source, lambda collect=collect: collect(terms))
             for source, collect in collectors_by_source.items() if source in sources]
    tasks.extend(COLLECTORS.submit(cti_stage, case_id, source,
                                  lambda source=source: cti.open_index_mentions(terms, source))
                 for source in ("Mwmbl", "Arquivo.pt") if source in sources)
    if "Ransomware.live" in sources:
        key = os.environ["RANSOMWARE_LIVE_API_KEY"].strip()
        tasks.append(COLLECTORS.submit(cti_stage, case_id, "Ransomware.live",
                                       lambda: cti.ransomware_live_matches(terms, key)))
    return tasks


def cti_assessment(case_id, targets, payload, models):
    def attempt(model, status, message):
        with database() as conn:
            cti.event(conn, case_id, "OpenCode · " + model, status, message, now())
    return cti_stage(case_id, "OpenCode", lambda: cti.enrich_case(targets, payload, models, attempt))


def run_cti(case_id, seeds):
    with database() as conn:
        conn.execute("UPDATE cti_cases SET status='running' WHERE id=?", (case_id,))
        entries = [json.loads(row["payload"]) for row in conn.execute("SELECT payload FROM cti_misp")]
        round_id = cti.begin_round(conn, case_id, now())
    sources = cti.configured_sources()
    tasks = submit_cti_iocs(case_id, seeds, entries, sources)
    terms = [seed for seed in seeds if seed["kind"] in ("Termo", "Grupo")]
    missing_search = bool(terms) and os.getenv("OSINT_WEB", "1") == "1" and "Busca web" not in sources
    if terms:
        tasks.extend(submit_cti_mentions(case_id, terms, sources))
    if missing_search:
        with database() as conn:
            cti.event(conn, case_id, "Busca web", "error", "SearXNG endpoint is not configured.", now())
    observations = []
    failed = int(missing_search)
    for task in as_completed(tasks):
        rows, error = task.result()
        observations.extend(rows)
        failed += error
    if any(row["source"] in cti.WEB_MENTION_SOURCES for row in observations):
        verified, error = cti_stage(case_id, "Verificação web", lambda: cti.verified_mentions(observations))
        observations.extend(verified)
        failed += error
        pivots = cti.automatic_pivots(seeds, verified)
        if pivots:
            with database() as conn:
                cti.event(conn, case_id, "Expansão automática", "running",
                          f"Looking up {len(pivots)} indicators and names cited by sources.", now())
            iocs = [seed for seed in pivots if seed["kind"] in cti.IOC_KINDS]
            names = [seed for seed in pivots if seed["kind"] in ("Alias", "Malware")]
            expansion = submit_cti_iocs(case_id, iocs, entries, sources) if iocs else []
            if names:
                expansion.extend(submit_cti_mentions(case_id, names, sources))
            new_rows = []
            for task in as_completed(expansion):
                rows, error = task.result()
                new_rows.extend(rows)
                failed += error
            if any(row["source"] in cti.WEB_MENTION_SOURCES for row in new_rows):
                checked, error = cti_stage(case_id, "Verificação web", lambda: cti.verified_mentions(new_rows))
                observations.extend(checked)
                failed += error
            observations.extend(new_rows)
            with database() as conn:
                cti.event(conn, case_id, "Expansão automática", "done", "Expansion completed.", now())
    if "MITRE ATT&CK" in sources:
        context = [*seeds, *({"kind": row["kind"], "value": row["target"]} for row in observations
                             if row["kind"] in ("Grupo", "Campanha", "Malware", "Alias"))]
        entities = list({(seed["kind"], seed["value"].casefold()): seed for seed in context
                         if seed["kind"] in ("Termo", "Grupo", "Campanha", "Malware", "Ferramenta", "Alias")}.values())[:25]
        if entities:
            rows, error = cti_stage(case_id, "MITRE ATT&CK", lambda: cti.attack_matches(entities, cti.attack_bundle()))
            failed += error
            observations.extend(rows)
            groups = list({row["target"]: {"kind": "Grupo", "value": row["target"]} for row in rows
                           if row["kind"] == "Grupo" and row["relationship"] == "Identificado no catálogo"}.values())
            if groups and "Menções públicas" in sources:
                mentions, error = cti_stage(case_id, "Menções públicas", lambda: cti.public_mentions(groups))
                observations.extend(mentions)
                failed += error
    models = cti.assessment_models()
    if "OpenCode" in sources and models:
        with database() as conn:
            case = cti.snapshot(conn, case_id)
        targets = case["seeds"]
        payload = cti.assessment_payload(targets, assessment_observations(case))
        if payload:
            _, error = cti_assessment(case_id, targets, payload, models)
            failed += error
        else:
            with database() as conn:
                cti.event(conn, case_id, "OpenCode", "done", "No linked public evidence to assess.", now())
    with database() as conn:
        total = conn.execute("SELECT count(*) FROM cti_relations WHERE case_id=?", (case_id,)).fetchone()[0]
        status = "partial" if failed else "done" if total else "empty"
        conn.execute("UPDATE cti_cases SET status=? WHERE id=?", (status, case_id))
        cti.event(conn, case_id, "Coleta", status, f"{total} relationship(s) recorded.", now())
        cti.finish_round(conn, case_id, round_id, now(), status)


def assessment_observations(case):
    return [item for item in case["relations"] if item["review"] != "rejected" and item["source"] != "OpenCode"]


def retry_cti_assessment(case_id, targets, payload, models):
    with database() as conn:
        conn.execute("UPDATE cti_cases SET status='running' WHERE id=?", (case_id,))
    cti_assessment(case_id, targets, payload, models)
    with database() as conn:
        errors = conn.execute("""
            SELECT 1 FROM cti_events WHERE case_id=? AND status='error' AND id IN (
                SELECT max(id) FROM cti_events WHERE case_id=? GROUP BY source
            ) LIMIT 1
        """, (case_id, case_id)).fetchone()
        conn.execute("UPDATE cti_cases SET status=? WHERE id=?", ("partial" if errors else "done", case_id))


def reserve_cti(conn, case_id):
    active = conn.execute("SELECT count(*) FROM cti_cases WHERE status IN ('running','queued')").fetchone()[0]
    if active >= 3:
        raise ValueError("Wait for an investigation to finish.")
    conn.execute("UPDATE cti_cases SET status='queued' WHERE id=?", (case_id,))


def collect_source(search_id, query, name, collector, identity, primary=False, institutional_urls=None,
                   web_outage=None):
    with database() as conn:
        event(conn, search_id, "running", f"Consultando: {query}", name)
    name_differs = False
    links = []
    lead_source = collectors.is_lead_source(collector)
    try:
        if primary:
            item = public_pages.collect(identity, links=links, institutional_page=institutional_urls)
            # A company controls the supplied site. Preserve the name it publishes as page data,
            # without adding it as an alias. Public profiles must still match the person's name.
            matches = collectors.identity_match(*item, identity)
            name_differs = not matches
            found = [item] if identity["target_type"] == "organization" or matches else []
        elif lead_source:
            found = list(collectors.items(collector, query))
            if collector is collectors.web_search:
                anchor = (identity["reference"] if identity["target_type"] == "organization"
                          else public_pages.linked_profile(identity["reference"]))
                terms = [identity["target"], query.strip('"')]
                if anchor:
                    terms.append(anchor)
                found = [item for item in found if any(collectors.name_match(
                    item[0] + " " + item[2].partition(" · ")[2], term,
                ) for term in terms)]
        else:
            candidates = collectors.items(collector, query)
            found = [
                item for item in candidates
                if (collectors.name_match(item[0], query) or collectors.name_match(item[2], query))
                and collectors.identity_match(*item, identity)
            ]
    except Exception as exc:
        if web_outage is not None and isinstance(exc, collectors.SearchEnginesUnavailable):
            web_outage.append(exc)
        with database() as conn:
            event(conn, search_id, "error", f"Consulta indisponível ({source_error(exc)}).", name)
        return None
    with database() as conn:
        rows = [(search_id, name, *item, now(), int(lead_source)) for item in found]
        if primary and found:
            rows.extend((search_id, label, title, url, excerpt, now(), int(label == "CNPJ a conferir"))
                        for label, title, url, excerpt in links
                        if identity["target_type"] == "organization" or not name_differs)
        inserted = conn.executemany(
            "INSERT OR IGNORE INTO results (search_id, source, title, url, excerpt, collected_at, is_lead) VALUES (?, ?, ?, ?, ?, ?, ?)",
            rows,
        ).rowcount
        if inserted and primary:
            message = ("O domínio confirmado publica um título diferente do nome informado. Confira a página."
                       if name_differs else f"Referência coletada. {inserted - 1} vínculo(s) publicado(s) na própria fonte.")
        elif primary:
            message = "A página respondeu, mas não confirmou o nome informado."
        elif lead_source:
            message = f"{inserted} pista(s) para conferência." if inserted else "Nenhuma pista nesta fonte."
        elif inserted:
            message = f"{inserted} resultado(s) compatível(is) com o alvo."
        else:
            message = "Nenhum resultado com o nome e a referência do alvo."
        event(conn, search_id, "done", message, name)
    return inserted


def collect_institutional_page(search_id, url, identity):
    source = "Site institucional"
    with database() as conn:
        event(conn, search_id, "running", f"Abrindo {url}", source)
    try:
        page, title, address, excerpt, body = public_pages.secondary_page(url, identity["reference"])
        details = [*public_pages.institution_details(page, address, identity, body),
                   *public_pages.public_channels(page, address, identity["reference"]),
                   *public_pages.published_links(page, address, identity)]
    except Exception as error:
        with database() as conn:
            event(conn, search_id, "error", f"{url} · {source_error(error)}", source)
        return None
    with database() as conn:
        rows = [(search_id, source, title, address, excerpt, now(), 0)]
        rows.extend((search_id, label, name, link, context, now(), int(label == "CNPJ a conferir"))
                    for label, name, link, context in details)
        inserted = conn.executemany(
            "INSERT OR IGNORE INTO results (search_id, source, title, url, excerpt, collected_at, is_lead) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)", rows,
        ).rowcount
        event(conn, search_id, "done", f"{inserted} registro(s) em {address}", source)
    return inserted


def collect_web_round(search_id, query, identity, root, expansion=False):
    found = 0
    failed = False
    outage = []
    terms = collectors.web_queries(query, identity, root)
    if terms and expansion and query.casefold() != identity["target"].casefold() and not public_pages.cnpj_value(query):
        target = " ".join(identity["target"].replace('"', " ").split())
        terms.append(f'{terms[0]} "{target}"')
    for index, term in enumerate(terms):
        count = collect_source(search_id, term, "Busca web", collectors.web_search, identity, web_outage=outage)
        if count is None:
            failed = True
        else:
            found += count
        if outage and index + 1 < len(terms):
            with database() as conn:
                event(conn, search_id, "done", f"{len(terms) - index - 1} consulta(s) web adiada(s). "
                      "As demais fontes continuam e as pistas já encontradas são preservadas.", "Busca web")
            break
    return None if failed else found


def corporate_web_identifiers(conn, search_id, target):
    directories = ("casadosdados.com.br", "cnpj.biz", "econodata.com.br", "transparencia.cc")
    origins = {}
    rows = conn.execute("SELECT title, url, excerpt FROM results WHERE search_id=? AND source='Busca web'",
                        (search_id,)).fetchall()
    for row in rows:
        url = urlsplit(row["url"])
        publisher = next((domain for domain in directories if public_pages.is_official_host(url.hostname, domain)), None)
        excerpt = row["excerpt"].partition(" · ")[2]
        if not publisher or not collectors.name_match(row["title"] + " " + excerpt, target):
            continue
        for identifier in public_pages.published_cnpjs(row["title"] + " " + excerpt):
            origins.setdefault(identifier, set()).add(publisher)
            address = url._replace(fragment="cnpj-" + identifier).geturl()
            conn.execute(
                "INSERT OR IGNORE INTO results (search_id, source, title, url, excerpt, collected_at, is_lead) "
                "VALUES (?, 'CNPJ a conferir', ?, ?, ?, ?, 1)",
                (search_id, f"CNPJ {identifier}", address, f"Diretório: {publisher} · {excerpt}"[:900], now()),
            )
    if len(origins) == 1:
        identifier, publishers = next(iter(origins.items()))
        event(conn, search_id, "done", f"Um CNPJ candidato em {len(publishers)} diretório(s). "
              "Consultando o cadastro para conferência.")
        return identifier
    return ""


def collect(search_id, query, identity, root, expansion=False):
    with database() as conn:
        if expansion and not conn.execute(
            "SELECT 1 FROM searches s JOIN results r ON r.id=s.parent_id "
            "WHERE s.id=? AND r.verified_at!='' AND r.rejected_at=''", (search_id,),
        ).fetchone():
            set_status(conn, search_id, "interrupted", "A evidência de origem deixou de estar confirmada.")
            return
        set_status(conn, search_id, "running", "Busca iniciada.")
    counts = []
    corporate = root and identity["target_type"] == "organization"
    institutional_urls = [] if corporate else None
    if root and os.getenv("OSINT_WEB", "1") == "1":
        counts.append(collect_source(search_id, query, "Referência confirmada", None, identity, primary=True,
                                     institutional_urls=institutional_urls))
    tasks = [COLLECTORS.submit(collect_institutional_page, search_id, url, identity)
             for url in (institutional_urls or [])[:5]]
    registries = {}
    for name, collector in SOURCE_MAP.items():
        if corporate and collector in (collectors.minha_receita, collectors.cvm):
            registries[name] = collector
        elif collector is collectors.web_search:
            tasks.append(COLLECTORS.submit(collect_web_round, search_id, query, identity, root, expansion))
        elif collectors.applies(collector, identity, query):
            tasks.append(COLLECTORS.submit(collect_source, search_id, query, name, collector, identity))
    counts.extend(task.result() for task in as_completed(tasks))
    registration = ""
    if corporate:
        with database() as conn:
            rows = conn.execute(
                "SELECT DISTINCT title FROM results WHERE search_id=? AND source IN ('CNPJ declarado', 'CNPJ a conferir')",
                (search_id,),
            ).fetchall()
            if len(rows) > 1:
                conn.execute("UPDATE results SET is_lead=1 WHERE search_id=? AND source='CNPJ declarado'", (search_id,))
                event(conn, search_id, "done", "Mais de um CNPJ publicado. A consulta cadastral requer um pivô explícito.")
            web_registration = corporate_web_identifiers(conn, search_id, identity["target"])
        if len(rows) == 1:
            registration = public_pages.cnpj_value(rows[0]["title"].removeprefix("CNPJ "))
        elif not rows:
            registration = web_registration
        term = registration or query
        for name, collector in registries.items():
            if collectors.applies(collector, identity, term):
                counts.append(collect_source(search_id, term, name, collector, identity))
        if not registration:
            with database() as conn:
                event(conn, search_id, "done", "CNPJ sem confirmação. Use as consultas corporativas para ampliar a busca.")
    failures = counts.count(None)
    with database() as conn:
        matched, leads = conn.execute(
            "SELECT count(CASE WHEN is_lead=0 THEN 1 END), count(CASE WHEN is_lead=1 THEN 1 END) "
            "FROM results WHERE search_id=?", (search_id,),
        ).fetchone()
        if counts and failures == len(counts):
            set_status(conn, search_id, "error", "Todas as fontes falharam.")
        elif failures:
            message = f"{matched} achado(s) e {leads} pista(s). Parte das fontes falhou."
            set_status(conn, search_id, "partial", message)
        elif not matched and leads:
            set_status(conn, search_id, "leads", "Pistas encontradas. A atribuição requer revisão.")
        elif not matched:
            set_status(conn, search_id, "no_match", "Nenhuma correspondência para o alvo confirmado.")
        else:
            set_status(conn, search_id, "done", "Busca concluída.")


def enqueue(conn, case_id, parent, query):
    active = conn.execute(
        "SELECT count(*) FROM searches WHERE status IN ('queued','running')"
    ).fetchone()[0]
    if active >= 12:
        raise ValueError("Fila cheia. Aguarde uma busca terminar.")
    search_id = conn.execute(
        "INSERT INTO searches (case_id, parent_id, query, status, created_at, identity_scoped) "
        "VALUES (?, ?, ?, 'queued', ?, 1)",
        (case_id, parent, query, now()),
    ).lastrowid
    event(conn, search_id, "queued", "Busca na fila.")
    return search_id


def expansion_queries(result):
    title = result["title"]
    if result["source"] == "Minha Receita" and title.startswith("QSA · "):
        return [entry.split(" · ", 1)[0].strip()[:200] for entry in result["excerpt"].split(" | ")
                if entry.strip()]
    registration = re.match(r"(?:CNPJ |Endereço cadastral · )([A-Z0-9]{12}[0-9]{2})(?:$| · )", title)
    if registration:
        return [registration[1]]
    return [title[:200]] if title else []


def queue_expansion(conn, case_id, identity):
    results = conn.execute(
        "SELECT r.* FROM results r JOIN searches s ON s.id=r.search_id "
        "WHERE s.case_id=? AND r.verified_at!='' AND r.rejected_at='' ORDER BY r.id DESC", (case_id,),
    ).fetchall()
    active = conn.execute("SELECT count(*) FROM searches WHERE status IN ('queued','running')").fetchone()[0]
    if active >= 12:
        raise ValueError("Fila cheia. Aguarde uma busca terminar.")
    previous = {(row["parent_id"], row["query"].casefold()) for row in conn.execute(
        "SELECT parent_id, query FROM searches WHERE case_id=? AND parent_id IS NOT NULL "
        "AND status NOT IN ('manual','error','interrupted')", (case_id,),
    )}
    jobs = []
    limit = min(4, 12 - active)
    for result in results:
        for query in expansion_queries(result):
            key = result["id"], query.casefold()
            if not query or key in previous:
                continue
            search_id = enqueue(conn, case_id, result["id"], query)
            event(conn, search_id, "queued", f"Expansão de evidência confirmada E-{result['id']}.")
            jobs.append((search_id, query, identity, False, True))
            previous.add(key)
            if len(jobs) == limit:
                return jobs
    return jobs


def snapshot(conn, case_id):
    case = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    if case is None:
        raise LookupError("Case not found.")
    data = {"case": dict(case)}
    for table in ("searches", "results", "events"):
        if table == "searches":
            sql = "SELECT * FROM searches WHERE case_id=? ORDER BY id"
        else:
            sql = f"SELECT * FROM {table} WHERE search_id IN (SELECT id FROM searches WHERE case_id=?) ORDER BY id"
        data[table] = [dict(row) for row in conn.execute(sql, (case_id,))]
    data["reviews"] = [dict(row) for row in conn.execute(
        "SELECT * FROM reviews WHERE case_id=? ORDER BY id", (case_id,)
    )]
    for review in data["reviews"]:
        review["evidence"] = json.loads(review["evidence"])
    return data


def report_markdown(data):
    framework = Path(os.getenv("OSINT_FRAMEWORK", "../OSINT-Agentic-Framework"))
    exporter = framework / "scripts" / "export-case-report.py"
    if not exporter.is_file():
        raise ValueError("Configure o diretório do OSINT Agentic Framework para exportar Markdown.")
    render = runpy.run_path(str(exporter))["render_report"]
    results = [item for item in data["results"] if not item["rejected_at"] and
               (not item["is_lead"] or item["verified_at"])]
    leads = [item for item in data["results"] if not item["rejected_at"] and item["is_lead"] and not item["verified_at"]]
    reviews = []
    rejected = {item["id"] for item in data["results"] if item["rejected_at"]}
    for review in data["reviews"]:
        links = [link for link in review["evidence"] if link["id"] not in rejected]
        reviews.append({
            "claim": review["claim"],
            "supports": [f"E-{x['id']}" for x in links if x["stance"] == "supports"],
            "contradicts": [f"E-{x['id']}" for x in links if x["stance"] == "contradicts"],
            "evidências de contexto": [f"E-{x['id']}" for x in links if x["stance"] == "context"],
            "confidence_rationale": review["rationale"],
        })
    return render(f"LOCAL-{data['case']['id']}", {
        "executive_summary": f"Alvo: {data['case']['target']}. Objetivo: {data['case']['goal'] or 'Não registrado'}. "
                             f"{len(results)} evidência(s) coletada(s) em {len(data['searches'])} busca(s). "
                             f"Referência declarada: {data['case']['reference'] or 'caso anterior à confirmação de alvo'}.",
        "confidence": "low",
        "key_findings": [{"description": item["title"], "id": f"E-{item['id']}",
                          "source": item["source"], "url": item["url"],
                          "collected_at": item["collected_at"], "published_at": item["published_at"],
                          "excerpt": item["excerpt"], **({"validação": item["verification_note"],
                              "data da validação": item["verified_at"]} if item["verified_at"] else {})}
                         for item in results],
        "hypotheses": reviews,
        "gaps": ["A independência das origens exige avaliação humana."] + [
            {"description": item["title"], "source": item["source"], "url": item["url"],
             "status": "Pista sem atribuição confirmada"} for item in leads
        ],
        "risks": [],
        "next_steps": [],
    })


def field(data, name, limit, required=True):
    value = data.get(name, "")
    if not isinstance(value, str) or len(value.strip()) > limit or (required and not value.strip()):
        raise ValueError(f"Campo inválido: {name}. Limite de {limit} caracteres.")
    return value.strip()


def confirmed_identity(data, target):
    kind = field(data, "target_type", 20)
    reference = field(data, "reference", 300)
    if data.get("confirmed") is not True:
        raise ValueError("Confira o nome e a referência e confirme o alvo antes da coleta.")
    if not re.search(r"[^\W_]", target):
        raise ValueError("Informe o nome do alvo.")
    if kind == "organization":
        reference = reference.lower().rstrip(".")
        host = reference
    elif kind == "individual":
        if "://" not in reference:
            reference = "https://" + reference
        page = urlsplit(reference)
        if (page.scheme != "https" or page.username is not None
                or page.port is not None or (page.path in ("", "/") and not page.query)):
            raise ValueError("Informe a URL completa de um perfil, currículo ou página pública.")
        host = page.hostname or ""
    else:
        raise ValueError("Selecione organização ou pessoa.")
    if not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}", host):
        raise ValueError("Informe um domínio público, como exemplo.com.br.")
    if host.endswith((".local", ".localhost", ".internal")):
        raise ValueError("Use uma referência pública.")
    return {"target": target, "target_type": kind, "reference": reference}


def require_identity(conn, case_id):
    case = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    if case is None:
        raise LookupError("Case not found.")
    if not case["reference"]:
        raise ValueError("Este caso é anterior à confirmação de alvo. Abra um novo caso com nome e referência.")
    return dict(case)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def send_data(self, status, body, mime):
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, data, status=200):
        self.send_data(status, json.dumps(data, ensure_ascii=False).encode(), "application/json; charset=utf-8")

    def valid_host(self):
        try:
            host = urlsplit("//" + self.headers.get("Host", "")).hostname
        except ValueError:
            return False
        return host in ("localhost", "127.0.0.1", "::1")

    def route(self):
        return urlsplit(self.path).path.strip("/").split("/")

    def do_GET(self):
        if not self.valid_host():
            return self.send_json({"error": "Use the local address."}, 403)
        try:
            self.get_route()
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            return
        except (ValueError, LookupError):
            self.send_json({"error": "Case not found."}, 404)

    def get_route(self):
        parts = self.route()
        static = {
            "": ("cti.html", "text/html"),
            "cti": ("cti.html", "text/html"),
            "cti.js": ("cti.js", "text/javascript"),
            "osint": ("cti.html", "text/html"),
            "app.js": ("app.js", "text/javascript"),
            "style.css": ("style.css", "text/css"),
        }
        if len(parts) == 1 and parts[0] in static:
            file, mime = static[parts[0]]
            return self.send_data(200, (STATIC / file).read_bytes(), mime + "; charset=utf-8")
        if parts == ["api", "health"]:
            return self.send_json({"ok": True})
        if parts == ["api", "diagnostics"]:
            return self.send_json(diagnostic_results())
        if parts == ["api", "cti"]:
            with database() as conn:
                cases = [dict(row) for row in conn.execute(
                    "SELECT id,title,status FROM cti_cases ORDER BY id DESC")]
                imported = conn.execute("SELECT count(*) FROM cti_misp").fetchone()[0]
            return self.send_json({"cases": cases, "sources": cti.configured_sources(),
                                   "imported": imported, "session": SESSION})
        if parts[:2] == ["api", "cti"] and len(parts) == 4 and parts[3] == "stix":
            with database() as conn:
                return self.send_json(cti.stix_bundle(cti.snapshot(conn, int(parts[2]))))
        if parts[:2] == ["api", "cti"] and len(parts) == 3:
            with database() as conn:
                case = cti.snapshot(conn, int(parts[2]))
                cti.case_intelligence(conn, case)
                return self.send_json(case)
        if parts == ["api", "cases"]:
            with database() as conn:
                cases = [dict(row) for row in conn.execute("SELECT * FROM cases ORDER BY id DESC")]
            sources = list(SOURCE_MAP)
            if os.getenv("OSINT_WEB", "1") == "1":
                sources.insert(0, "Referência confirmada")
            return self.send_json({"cases": cases, "sources": sources, "session": SESSION})
        if parts[:2] == ["api", "cases"] and len(parts) in (3, 4):
            case_id = int(parts[2])
            if parts[3:] == ["stream"]:
                return self.stream(case_id)
            with database() as conn:
                conn.execute("BEGIN")
                data = snapshot(conn, case_id)
            if len(parts) == 3:
                return self.send_json(data)
            if parts[3] == "report.md":
                try:
                    report = report_markdown(data)
                except ValueError as exc:
                    return self.send_json({"error": str(exc)}, 503)
                return self.send_data(200, report.encode(), "text/plain; charset=utf-8")
        self.send_json({"error": "Route not found."}, 404)

    def stream(self, case_id):
        with database() as conn:
            snapshot(conn, case_id)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        previous = (None, None)
        deadline = time.monotonic() + 15
        self.connection.settimeout(5)
        while time.monotonic() < deadline:
            with database() as conn:
                conn.execute("BEGIN")
                revision = conn.execute(
                    "SELECT max(events.id) FROM events JOIN searches ON searches.id=events.search_id WHERE case_id=?",
                    (case_id,),
                ).fetchone()[0]
                review_revision = conn.execute(
                    "SELECT max(id) FROM reviews WHERE case_id=?", (case_id,)
                ).fetchone()[0]
                version = (revision, review_revision)
                data = snapshot(conn, case_id) if version != previous else None
            if data is not None:
                self.wfile.write(b"data: " + json.dumps(data, ensure_ascii=False).encode() + b"\n\n")
                previous = version
            time.sleep(0.5)

    def do_POST(self):
        if (not self.valid_host() or self.headers.get("X-OSINT-Session") != SESSION
                or self.headers.get_content_type() != "application/json"):
            self.close_connection = True
            return self.send_json({"error": "Invalid local session. Refresh the page."}, 403)
        try:
            size = int(self.headers.get("Content-Length", "0"))
            parts = self.route()
            limit = 5_000_000 if parts == ["api", "cti", "misp"] else 8192
            if not 0 < size <= limit:
                self.close_connection = True
                raise ValueError("Invalid request size.")
            data = json.loads(self.rfile.read(size))
            if not isinstance(data, dict):
                raise ValueError("Send a JSON object.")
            parts = self.route()
            if parts == ["api", "diagnostics"]:
                return self.send_json(start_diagnostics(), 202)
            if parts[:2] == ["api", "cti"]:
                return self.post_cti(parts[2:], data)
            jobs = []
            with database() as conn:
                conn.execute("BEGIN IMMEDIATE")
                if parts == ["api", "cases"]:
                    query = field(data, "target", 200)
                    goal = field(data, "goal", 500, required=False)
                    identity = confirmed_identity(data, query)
                    case_id = conn.execute(
                        "INSERT INTO cases (target, goal, created_at, target_type, reference) VALUES (?, ?, ?, ?, ?)",
                        (query, goal, now(), identity["target_type"], identity["reference"]),
                    ).lastrowid
                    search_id = enqueue(conn, case_id, None, query)
                    jobs.append((search_id, query, identity, True))
                    response = {"case_id": case_id, "search_id": search_id}
                elif parts[:2] == ["api", "cases"] and parts[3:] == ["rerun"]:
                    case_id = int(parts[2])
                    identity = require_identity(conn, case_id)
                    active = conn.execute(
                        "SELECT 1 FROM searches WHERE case_id=? AND parent_id IS NULL AND status IN ('queued','running')",
                        (case_id,),
                    ).fetchone()
                    if active:
                        raise ValueError("Já há uma coleta principal em andamento neste caso.")
                    query = identity["target"]
                    search_id = enqueue(conn, case_id, None, query)
                    jobs.append((search_id, query, identity, True))
                    response = {"case_id": case_id, "search_id": search_id}
                elif parts[:2] == ["api", "cases"] and parts[3:] == ["expand"]:
                    case_id = int(parts[2])
                    identity = require_identity(conn, case_id)
                    jobs = queue_expansion(conn, case_id, identity)
                    response = {"case_id": case_id, "search_ids": [job[0] for job in jobs]}
                elif parts[:2] == ["api", "cases"] and parts[3:] == ["searches"]:
                    case_id = int(parts[2])
                    identity = require_identity(conn, case_id)
                    query = field(data, "query", 200)
                    parent = data.get("parent_id")
                    found = type(parent) is int and conn.execute(
                        "SELECT 1 FROM results JOIN searches ON searches.id=results.search_id "
                        "WHERE results.id=? AND searches.case_id=? AND rejected_at=''", (parent, case_id),
                    ).fetchone()
                    if not found:
                        raise LookupError("Resultado não encontrado neste caso.")
                    search_id = enqueue(conn, case_id, parent, query)
                    jobs.append((search_id, query, identity, False))
                    response = {"case_id": case_id, "search_id": search_id}
                elif parts[:2] == ["api", "cases"] and parts[3:] == ["manual"]:
                    case_id = int(parts[2])
                    query = field(data, "query", 400)
                    require_identity(conn, case_id)
                    parent = data.get("parent_id")
                    if parent is not None and (type(parent) is not int or not conn.execute(
                        "SELECT 1 FROM results JOIN searches ON searches.id=results.search_id "
                        "WHERE results.id=? AND searches.case_id=? AND rejected_at=''", (parent, case_id),
                    ).fetchone()):
                        raise LookupError("Resultado não encontrado neste caso.")
                    search_id = conn.execute(
                        "INSERT INTO searches (case_id, parent_id, query, status, created_at) VALUES (?, ?, ?, 'manual', ?)",
                        (case_id, parent, query, now()),
                    ).lastrowid
                    event(conn, search_id, "manual", "Consulta registrada para abertura no navegador.")
                    response = {"search_id": search_id}
                elif parts[:2] == ["api", "cases"] and parts[3:] == ["capture"]:
                    case_id = int(parts[2])
                    search_id = data.get("search_id")
                    if type(search_id) is not int or not conn.execute(
                        "SELECT 1 FROM searches WHERE id=? AND case_id=? AND status='manual'", (search_id, case_id)
                    ).fetchone():
                        raise LookupError("Consulta manual não encontrada neste caso.")
                    title = field(data, "title", 300)
                    source = field(data, "source", 100)
                    url = field(data, "url", 2000)
                    parsed = urlsplit(url)
                    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username is not None:
                        raise ValueError("Use uma URL HTTP ou HTTPS sem credenciais.")
                    excerpt = field(data, "excerpt", 1000)
                    published = field(data, "published_at", 10, required=False)
                    if published:
                        datetime.strptime(published, "%Y-%m-%d")
                    inserted = conn.execute(
                        "INSERT OR IGNORE INTO results "
                        "(search_id, source, title, url, excerpt, collected_at, published_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (search_id, source, title, url, excerpt, now(), published),
                    )
                    if not inserted.rowcount:
                        raise ValueError("Essa URL já foi capturada para essa fonte e consulta.")
                    event(conn, search_id, "done", "Evidência registrada manualmente.", source)
                    response = {"result_id": inserted.lastrowid}
                elif parts[:2] == ["api", "cases"] and parts[3:] in (["verify"], ["reject"]):
                    case_id = int(parts[2])
                    require_identity(conn, case_id)
                    result_id = data.get("result_id")
                    note = field(data, "note", 1000, required=False)
                    reject = parts[3] == "reject"
                    row = type(result_id) is int and conn.execute(
                        "SELECT results.search_id, verified_at, rejected_at FROM results JOIN searches "
                        "ON searches.id=results.search_id WHERE results.id=? AND searches.case_id=?",
                        (result_id, case_id),
                    ).fetchone()
                    if not row:
                        raise LookupError("Resultado não encontrado neste caso.")
                    if reject and not row["rejected_at"]:
                        conn.execute("UPDATE results SET rejected_at=?, verified_at='', verification_note=? WHERE id=?",
                                     (now(), note, result_id))
                        event(conn, row["search_id"], "done", f"E-{result_id} invalidada pelo investigador.")
                    elif not reject and not row["verified_at"]:
                        conn.execute("UPDATE results SET verified_at=?, rejected_at='', verification_note=? WHERE id=?",
                                     (now(), note, result_id))
                        event(conn, row["search_id"], "done", f"E-{result_id} validada pelo investigador.")
                    response = {"result_id": result_id}
                elif parts[:2] == ["api", "cases"] and parts[3:] == ["reviews"]:
                    case_id = int(parts[2])
                    case = snapshot(conn, case_id)
                    claim = field(data, "claim", 500)
                    rationale = field(data, "rationale", 1500)
                    evidence = data.get("evidence")
                    if not isinstance(evidence, list) or not 1 <= len(evidence) <= 20:
                        raise ValueError("Selecione de 1 a 20 evidências.")
                    valid_ids = {item["id"] for item in case["results"] if not item["rejected_at"] and
                                 (not item["is_lead"] or item["verified_at"])}
                    selected = set()
                    for link in evidence:
                        if (not isinstance(link, dict) or type(link.get("id")) is not int
                                or link["id"] not in valid_ids or link["id"] in selected
                                or link.get("stance") not in ("supports", "contradicts", "context")):
                            raise ValueError("Vínculo de evidência inválido.")
                        selected.add(link["id"])
                    review_id = conn.execute("INSERT INTO reviews VALUES (NULL, ?, ?, ?, ?, ?)",
                                             (case_id, claim, rationale, json.dumps(evidence), now())).lastrowid
                    response = {"review_id": review_id}
                else:
                    raise LookupError("Route not found.")
            for job in jobs:
                WORKERS.submit(collect, *job)
            self.send_json(response, 201)
        except (ValueError, OverflowError) as exc:
            self.send_json({"error": str(exc)}, 400)
        except LookupError as exc:
            self.send_json({"error": str(exc)}, 404)


    def post_cti(self, parts, data):
        job = None
        worker = run_cti
        with database() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if not parts:
                seeds = cti.parse_seeds(data.get("seeds"))
                title = field(data, "title", 150, required=False) or seeds[0]["value"][:150]
                case_id = conn.execute("INSERT INTO cti_cases VALUES (NULL, ?, ?, 'idle', ?)",
                                       (title, json.dumps(seeds), now())).lastrowid
                reserve_cti(conn, case_id)
                job = case_id, seeds
                response = {"id": case_id}
            elif parts == ["misp"]:
                raw = data.get("events")
                if not isinstance(raw, list) or not 1 <= len(raw) <= 100:
                    raise ValueError("Import between 1 and 100 MISP events per file.")
                records = [cti.misp_event(entry) for entry in raw]
                conn.executemany("INSERT INTO cti_misp VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",
                                 [(entry["id"], json.dumps(entry)) for entry in records])
                response = {"imported": len(records)}
            elif len(parts) == 2:
                case_id = int(parts[0])
                case = cti.snapshot(conn, case_id)
                if parts[1] == "expand":
                    if case["status"] in ("queued", "running"):
                        raise ValueError("An investigation is already running.")
                    chosen = [item for item in case["relations"] if item["review"] == "confirmed" and
                              item["kind"] in ("IP", "Domínio", "URL", "Hash", "User-Agent", "Grupo", "Malware", "Campanha", "Ferramenta")]
                    seeds = list({cti.match_key(item["kind"], item["target"]): {
                        "kind": item["kind"], "value": item["target"]} for item in chosen}.values())[:12]
                    reserve_cti(conn, case_id)
                    original_terms = [seed for seed in case["seeds"] if seed["kind"] in ("Termo", "Grupo")]
                    combined = {cti.match_key(seed["kind"], seed["value"]): seed for seed in original_terms + seeds}
                    job = case_id, list(combined.values()) if seeds else case["seeds"]
                    response = {"id": case_id, "pivots": len(seeds)}
                elif parts[1] == "assessment":
                    if case["status"] in ("queued", "running"):
                        raise ValueError("Wait for the current investigation to finish.")
                    models = cti.assessment_models()
                    if not models:
                        raise ValueError("OpenCode assessments are disabled in local configuration.")
                    targets = case["seeds"]
                    payload = cti.assessment_payload(targets, assessment_observations(case))
                    if not payload:
                        raise ValueError("This case has no public evidence to assess yet.")
                    reserve_cti(conn, case_id)
                    worker = retry_cti_assessment
                    job = case_id, targets, payload, models
                    response = {"id": case_id}
                elif parts[1] == "review":
                    state = field(data, "review", 15)
                    if state not in ("confirmed", "rejected"):
                        raise ValueError("Invalid review decision.")
                    result_id = data.get("result_id")
                    if type(result_id) is not int or not conn.execute(
                        "UPDATE cti_relations SET review=? WHERE case_id=? AND id=?", (state, case_id, result_id),
                    ).rowcount:
                        raise LookupError("Relationship not found.")
                    decision = "confirmed" if state == "confirmed" else "rejected"
                    cti.event(conn, case_id, "Revisão", state, f"Evidence #{result_id} {decision}.", now())
                    response = {"id": result_id}
                elif parts[1] == "reference":
                    category = field(data, "category", 30)
                    labels = {"forum": "Menção em fórum", "group_handle": "Handle publicado do grupo",
                              "attribution": "Atribuição documentada"}
                    if category not in labels:
                        raise ValueError("Invalid reference category.")
                    origin = field(data, "origin", 200)
                    title = field(data, "title", 250)
                    url = cti.clean_url(field(data, "url", 1500))
                    if not url or not url.startswith("https://"):
                        raise ValueError("Enter a public HTTPS URL.")
                    note = field(data, "detail", 1000)
                    rows = [cti.relation({"kind": "Grupo", "value": origin}, "Referência", title,
                                         labels[category], "Registro manual", reference=url, detail=note,
                                         confidence="Documentada pela fonte" if category == "attribution" else "A conferir")]
                    response = {"added": cti.save(conn, case_id, rows)}
                else:
                    raise LookupError("CTI route not found.")
            else:
                raise LookupError("CTI route not found.")
        if job:
            WORKERS.submit(worker, *job)
        return self.send_json(response, 201)


if __name__ == "__main__":
    initialize()
    host = os.getenv("OSINT_HOST", "127.0.0.1")
    port = int(os.getenv("OSINT_PORT", "8080"))
    with ThreadingHTTPServer((host, port), Handler) as server:
        print(f"OpenInvestigation at http://{host}:{port}", flush=True)
        server.serve_forever()
