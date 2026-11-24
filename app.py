"""Local CTI case storage, collection workers, and HTTP interface."""
import json
import re
import os
import secrets
import socket
import sqlite3
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit

import collectors
import cti
import policy

STATIC = Path(__file__).parent / "static"
DB = Path(os.getenv("OSINT_DATA_DIR", "./data")) / "cases.sqlite3"
WORKERS = ThreadPoolExecutor(max_workers=3)
COLLECTORS = ThreadPoolExecutor(max_workers=6)
SESSION = secrets.token_urlsafe(24)
STAGE_ROW_LIMIT = 1200      # rows kept from one source stage before it is marked truncated
ENTITY_CONTEXT_LIMIT = 25   # entities carried into the ATT&CK lookup


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def database():
    with closing(sqlite3.connect(DB, timeout=10)) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        with conn:
            yield conn


LEGACY_TABLES = ("cases", "searches", "results", "events", "reviews")


def initialize():
    DB.parent.mkdir(parents=True, exist_ok=True)
    with database() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        cti.initialize(conn)
        # Threat-only builds no longer use the legacy tables. Preserve existing data
        # instead of dropping it, and point the operator at the migration notes.
        present = [row["name"] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN (%s)"
            % ",".join("?" * len(LEGACY_TABLES)), LEGACY_TABLES)]
        if present:
            print("WARNING: legacy investigation tables found and left untouched: "
                  + ", ".join(sorted(present))
                  + ". See README (Migrating from the legacy flow) to export and discard them.",
                  flush=True)


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


def cti_stage(case_id, source, callback, terms=None):
    with database() as conn:
        cti.event(conn, case_id, source, "running", "Query started.", now())
    rows = []
    saved = inserted = 0
    error = None
    truncated = False
    incremental = source in (*cti.WEB_MENTION_SOURCES, "Verificação web")
    try:
        for row in callback():
            rows.append(row)
            if incremental and len(rows) - saved >= 4:
                with database() as conn:
                    inserted += cti.save(conn, case_id, rows[saved:])
                saved = len(rows)
            if len(rows) == STAGE_ROW_LIMIT:
                truncated = True
                break
    except Exception as exc:
        error = source_error(exc)
    with database() as conn:
        inserted += cti.save(conn, case_id, rows[saved:])
        message = f"{inserted} new relationship(s) · {len(rows)} found."
        if truncated:
            message += f" Truncated at {STAGE_ROW_LIMIT} (partial)."
        if error:
            message += " Source unavailable: " + error
        cti.event(conn, case_id, source, "error" if error else "done", message, now(), found=len(rows))
        if terms is not None:
            cti.log_query(conn, case_id, source, terms, len(rows), now())
    return rows, bool(error)


def submit_cti_iocs(case_id, seeds, entries, sources):
    values = [seed["value"] for seed in seeds]
    tasks = [COLLECTORS.submit(cti_stage, case_id, "MISP local", lambda: cti.misp_matches(seeds, entries), values)]
    has_iocs = any(seed["kind"] in ("IP", "URL", "Domínio", "Hash") for seed in seeds)
    if "Histórico local" in sources and has_iocs:
        tasks.append(COLLECTORS.submit(cti_stage, case_id, "Histórico local", lambda: cti.local_history_matches(seeds), values))
    if "Relatórios históricos na web" in sources and has_iocs:
        tasks.append(COLLECTORS.submit(cti_stage, case_id, "Relatórios históricos na web",
                                       lambda: cti.historical_web_matches(seeds), values))
    if "CIRCL OSINT" in sources and has_iocs:
        tasks.append(COLLECTORS.submit(cti_stage, case_id, "CIRCL OSINT", lambda: cti.circl_matches(seeds), values))
    if "ThreatDefence" in sources and (has_iocs or any(seed["kind"] == "User-Agent" for seed in seeds)):
        tasks.append(COLLECTORS.submit(cti_stage, case_id, "ThreatDefence", lambda: cti.threatdefence_matches(seeds), values))
    if "CISA KEV" in sources and any(seed["kind"] == "CVE" for seed in seeds):
        tasks.append(COLLECTORS.submit(cti_stage, case_id, "CISA KEV", lambda: cti.cisa_kev_matches(seeds), values))
    if "Feodo Tracker" in sources and any(seed["kind"] == "IP" for seed in seeds):
        tasks.append(COLLECTORS.submit(cti_stage, case_id, "Feodo Tracker", lambda: cti.feodo_matches(seeds), values))
    if "URLhaus" in sources and any(seed["kind"] in ("IP", "URL", "Domínio") for seed in seeds):
        tasks.append(COLLECTORS.submit(cti_stage, case_id, "URLhaus", lambda: cti.urlhaus_matches(seeds), values))
    if "MalwareBazaar" in sources and any(seed["kind"] == "Hash" for seed in seeds):
        tasks.append(COLLECTORS.submit(cti_stage, case_id, "MalwareBazaar", lambda: cti.malwarebazaar_matches(seeds), values))
    if "RDAP" in sources and any(seed["kind"] in ("IP", "Domínio", "ASN") for seed in seeds):
        tasks.append(COLLECTORS.submit(cti_stage, case_id, "RDAP", lambda: cti.rdap_matches(seeds), values))
    if "crt.sh" in sources and any(seed["kind"] == "Domínio" for seed in seeds):
        tasks.append(COLLECTORS.submit(cti_stage, case_id, "crt.sh", lambda: cti.crtsh_matches(seeds), values))
    if "RIPEstat" in sources and any(seed["kind"] in ("IP", "ASN") for seed in seeds):
        tasks.append(COLLECTORS.submit(cti_stage, case_id, "RIPEstat", lambda: cti.ripestat_matches(seeds), values))
    if has_iocs:
        for source, (variable, collector) in cti.authenticated_sources().items():
            if source in sources:
                tasks.append(COLLECTORS.submit(cti_stage, case_id, source,
                                               lambda collector=collector, key=os.environ[variable]: collector(seeds, key), values))
    return tasks


def submit_cti_mentions(case_id, terms, sources):
    values = [seed["value"] for seed in terms]
    collectors_by_source = {"Busca web": cti.keyword_matches, "GitHub público": cti.github_mentions,
                            "MISP Galaxy": cti.galaxy_matches,
                            "Official cybercrime publications": cti.official_cybercrime_mentions}
    tasks = [COLLECTORS.submit(cti_stage, case_id, source, lambda collect=collect: collect(terms), values)
             for source, collect in collectors_by_source.items() if source in sources]
    tasks.extend(COLLECTORS.submit(cti_stage, case_id, source,
                                  lambda source=source: cti.open_index_mentions(terms, source), values)
                 for source in ("Mwmbl", "Arquivo.pt") if source in sources)
    if "Ransomware.live" in sources:
        key = os.environ["RANSOMWARE_LIVE_API_KEY"].strip()
        tasks.append(COLLECTORS.submit(cti_stage, case_id, "Ransomware.live",
                                       lambda: cti.ransomware_live_matches(terms, key), values))
    return tasks


def cti_assessment(case_id, targets, payload, models):
    def attempt(model, status, message):
        with database() as conn:
            cti.event(conn, case_id, "OpenCode · " + model, status, message, now())
    return cti_stage(case_id, "OpenCode", lambda: cti.enrich_case(targets, payload, models, attempt),
                     [seed["value"] for seed in targets])


def case_policy(conn, case_id):
    row = conn.execute("SELECT tlp, source_prefs FROM cti_cases WHERE id=?", (case_id,)).fetchone()
    tlp = policy.normalize_tlp(row["tlp"] if row else "")
    try:
        prefs = json.loads(row["source_prefs"]) if row and row["source_prefs"] else {}
    except ValueError:
        prefs = {}
    passive = bool(prefs.get("passive"))
    overrides = prefs.get("overrides") if isinstance(prefs.get("overrides"), dict) else {}
    return tlp, passive, overrides


def run_cti(case_id, seeds):
    with database() as conn:
        conn.execute("UPDATE cti_cases SET status='running' WHERE id=?", (case_id,))
        entries = [json.loads(row["payload"]) for row in conn.execute("SELECT payload FROM cti_misp")]
        round_id = cti.begin_round(conn, case_id, now())
        tlp, passive, overrides = case_policy(conn, case_id)
    available = cti.configured_sources()
    sources = policy.effective_sources(available, tlp, passive, overrides)
    tasks = submit_cti_iocs(case_id, seeds, entries, sources)
    terms = [seed for seed in seeds if seed["kind"] in ("Termo", "Grupo")]
    missing_search = (bool(terms) and os.getenv("OSINT_WEB", "1") == "1"
                      and policy.permits_source("Busca web", tlp, passive, overrides)
                      and "Busca web" not in available)
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
        verified, error = cti_stage(case_id, "Verificação web", lambda: cti.verified_mentions(observations),
                                    sorted({row["origin"] for row in observations if row["source"] in cti.WEB_MENTION_SOURCES}))
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
                checked, error = cti_stage(case_id, "Verificação web", lambda: cti.verified_mentions(new_rows),
                                           sorted({row["origin"] for row in new_rows if row["source"] in cti.WEB_MENTION_SOURCES}))
                observations.extend(checked)
                failed += error
            observations.extend(new_rows)
            with database() as conn:
                cti.event(conn, case_id, "Expansão automática", "done", "Expansion completed.", now())
    if "MITRE ATT&CK" in sources:
        context = [*seeds, *({"kind": row["kind"], "value": row["target"]} for row in observations
                             if row["kind"] in ("Grupo", "Campanha", "Malware", "Alias"))]
        entities = list({(seed["kind"], seed["value"].casefold()): seed for seed in context
                         if seed["kind"] in ("Termo", "Grupo", "Campanha", "Malware", "Ferramenta", "Alias")}.values())[:ENTITY_CONTEXT_LIMIT]
        if entities:
            rows, error = cti_stage(case_id, "MITRE ATT&CK", lambda: cti.attack_matches(entities, cti.attack_bundle()),
                                    [entity["value"] for entity in entities])
            failed += error
            observations.extend(rows)
            groups = list({row["target"]: {"kind": "Grupo", "value": row["target"]} for row in rows
                           if row["kind"] == "Grupo" and row["relationship"] == "Identificado no catálogo"}.values())
            if groups and "Menções públicas" in sources:
                mentions, error = cti_stage(case_id, "Menções públicas", lambda: cti.public_mentions(groups),
                                            [group["value"] for group in groups])
                observations.extend(mentions)
                failed += error
    models = cti.assessment_models()
    with database() as conn:
        case = cti.snapshot(conn, case_id)
    targets = case["seeds"]
    payload, sanitized = cti.assessment_payload(targets, assessment_observations(case))
    use_llm = "OpenCode" in sources and bool(models)
    if payload:
        graded = [row for row in case["relations"] if row["source"] != "OpenCode" and row["review"] != "rejected"]
        cti.cluster_evidence(graded)
        score_result = cti.score(graded)
        assessed = False
        if use_llm:
            if sanitized:
                with database() as conn:
                    cti.event(conn, case_id, "OpenCode", "warning",
                              f"Sanitized {sanitized} excerpt(s) before sending them to the model.", now())
            _, error = cti_assessment(case_id, targets, payload, models)
            failed += error
            assessed = not error
        if not assessed:
            # No hosted model, or the model failed: fall back to the code-generated assessment so the
            # case always has a written conclusion.
            with database() as conn:
                cti.save(conn, case_id, list(cti.code_assessment(targets, payload, score_result)))
                cti.event(conn, case_id, "Parecer", "done",
                          f"Code-generated assessment · confidence {score_result['score']}/5.", now())
    elif use_llm:
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


def field(data, name, limit, required=True):
    value = data.get(name, "")
    if not isinstance(value, str) or len(value.strip()) > limit or (required and not value.strip()):
        raise ValueError(f"Campo inválido: {name}. Limite de {limit} caracteres.")
    return value.strip()


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
            "style.css": ("style.css", "text/css"),
        }
        if len(parts) == 1 and parts[0] in static:
            file, mime = static[parts[0]]
            return self.send_data(200, (STATIC / file).read_bytes(), mime + "; charset=utf-8")
        if parts == ["api", "health"]:
            return self.send_json({"ok": True})
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
        self.send_json({"error": "Route not found."}, 404)

    def do_POST(self):
        if (not self.valid_host() or self.headers.get("X-OSINT-Session") != SESSION
                or self.headers.get_content_type() != "application/json"):
            self.close_connection = True
            return self.send_json({"error": "Invalid local session. Refresh the page."}, 403)
        try:
            parts = self.route()
            size = int(self.headers.get("Content-Length", "0"))
            limit = 5_000_000 if parts == ["api", "cti", "misp"] else 8192
            if not 0 < size <= limit:
                self.close_connection = True
                raise ValueError("Invalid request size.")
            data = json.loads(self.rfile.read(size))
            if not isinstance(data, dict):
                raise ValueError("Send a JSON object.")
            if parts[:2] == ["api", "cti"]:
                return self.post_cti(parts[2:], data)
            self.send_json({"error": "Route not found."}, 404)
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
                tlp = data.get("tlp")
                if tlp not in policy.TLP_LEVELS:
                    raise ValueError("Select a TLP level (CLEAR, GREEN, AMBER, or RED) before starting.")
                raw_overrides = data.get("sources") if isinstance(data.get("sources"), dict) else {}
                overrides = {key: bool(value) for key, value in raw_overrides.items() if key in policy.ALL_SOURCES}
                prefs = {"passive": bool(data.get("passive")), "overrides": overrides}
                case_id = conn.execute(
                    "INSERT INTO cti_cases (title, seeds, status, created_at, tlp, source_prefs) "
                    "VALUES (?, ?, 'idle', ?, ?, ?)",
                    (title, json.dumps(seeds), now(), tlp, json.dumps(prefs, ensure_ascii=False))).lastrowid
                reserve_cti(conn, case_id)
                job = case_id, seeds
                response = {"id": case_id, "tlp": tlp}
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
                    prefs = case.get("source_prefs") or {}
                    if not policy.permits_hosted_llm(case.get("tlp"), bool(prefs.get("passive")),
                                                     prefs.get("overrides") if isinstance(prefs.get("overrides"), dict) else {}):
                        raise ValueError("Hosted model assessments are not allowed at this case's TLP.")
                    models = cti.assessment_models()
                    if not models:
                        raise ValueError("Model assessments are disabled in local configuration.")
                    targets = case["seeds"]
                    payload, sanitized = cti.assessment_payload(targets, assessment_observations(case))
                    if not payload:
                        raise ValueError("This case has no public evidence to assess yet.")
                    if sanitized:
                        cti.event(conn, case_id, "OpenCode", "warning",
                                  f"Sanitized {sanitized} excerpt(s) before sending them to the model.", now())
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
