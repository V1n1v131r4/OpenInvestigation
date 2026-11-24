# OpenInvestigation

OpenInvestigation is a self-hosted threat investigation workspace. It collects and correlates public evidence, maps relationships, and produces a case assessment whose citations lead back to the original evidence.

Docker Compose runs the application and a local SearXNG instance. The application keeps cases, evidence, and imported **MISP event JSON** in a local SQLite volume. The MISP import and correlation workflow is built in and works without a separate MISP server.

**OpenCode runs inside the application container** and invokes the configured model to generate an assessment. With the default free OpenCode models or configured OpenAI and Anthropic keys, inference runs at the hosted provider. SearXNG and the source connectors also make external requests when enabled.

## Run locally

Install Docker with Docker Compose, then run from the project directory:

```sh
docker compose up --build -d
```

Open [http://127.0.0.1:8080](http://127.0.0.1:8080). Use `docker compose logs -f osint` to follow the service and `docker compose down` to stop it. SQLite data lives in the Compose volume. Set `OSINT_PORT` in `.env` to change the HTTP port.

## Migrating from the legacy flow

OpenInvestigation now investigates threats only. The earlier people-and-organization workflow and its `cases`, `searches`, `results`, `events`, and `reviews` tables are gone. If you upgraded an existing database, keep using the same project directory and Compose project name so Docker attaches the existing volume. The application **does not delete** those legacy tables; it logs a startup warning and leaves them in place so you can export and discard them on your own schedule.

Export the legacy tables to the data volume as JSON:

```sh
docker compose run --rm --no-deps osint python3 - <<'PY'
import json, sqlite3
db = sqlite3.connect("/data/cases.sqlite3"); db.row_factory = sqlite3.Row
tables = ("cases", "searches", "results", "events", "reviews")
have = {r["name"] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
dump = {t: [dict(r) for r in db.execute(f"SELECT * FROM {t}")] for t in tables if t in have}
open("/data/legacy-export.json", "w", encoding="utf-8").write(json.dumps(dump, ensure_ascii=False, indent=2))
print("exported", {t: len(v) for t, v in dump.items()})
PY
```

The file is written to `/data/legacy-export.json` inside the `cases` volume; copy it out with `docker compose cp osint:/data/legacy-export.json ./legacy-export.json`. Once you have the export, discard the legacy tables:

```sh
docker compose run --rm --no-deps osint python3 - <<'PY'
import sqlite3
db = sqlite3.connect("/data/cases.sqlite3")
for t in ("reviews", "events", "results", "searches", "cases"):
    db.execute(f"DROP TABLE IF EXISTS {t}")
db.commit(); db.execute("VACUUM")
print("legacy tables dropped")
PY
```

## Configure API keys

Create a `.env` file next to `compose.yaml`. If you already have one, keep it and add any missing variables from the template.

```sh
test -f .env || cp .env.example .env
```

Open `.env` in a text editor and fill in only the integrations you want to use. All keys are optional. Leave unused values blank.

```dotenv
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
OPENCODE_API_KEY=
MWMBL_API_KEY=
VIRUSTOTAL_API_KEY=
THREATFOX_AUTH_KEY=
SHODAN_API_KEY=
RANSOMWARE_LIVE_API_KEY=
```

Keep your actual keys in the local `.env`. Git ignores this file. After adding or changing keys, recreate the app container so Docker Compose loads them.

```sh
docker compose up -d osint
```

## Investigate a case

1. Enter up to 20 inputs, one per line. Supported inputs include IPv4, IPv6, CIDR ranges, domains, URLs, hashes, emails, CVEs, ASNs, crypto wallets (BTC/ETH), APT group names and aliases, and free-text search terms. Defanged input (`hxxp`, `[.]`, `[at]`) is normalized automatically, keeping the original. Prefix ambiguous types: `ua:`, `ja3:`, `jarm:`, `imphash:`, `ssdeep:`, `file:`, `mutex:`.
2. Follow **Live activity** or browse the **Relationship graph**. Select a node to open the evidence panel. Drag the background to pan, and use the zoom controls or **Fit graph** to navigate.
3. Use **Case assessment** below the graph to review the conclusion, claims, hypotheses, and cited evidence. The orange confidence badge explains the score on a 0–5 scale. Each evidence item carries an Admiralty code (e.g. `B2`): a source-reliability letter from `reliability.json` and an information-credibility number. A text match confirms the term is present, not that the claim is true.
4. Confirm or reject individual evidence items. If you reject a cited item, the assessment and its confidence become out of date. **Reassess case** uses the stored evidence. **Run investigation again** searches confirmed entities when available and otherwise uses the original targets.
5. Open **Coverage and run history**, **Timeline**, or **Related cases** to compare collection runs, distinguish activity and publication dates, and open earlier evidence. Export the case as JSON or export supported observables and source notes as STIX 2.1.

## Sources

| Source | What it adds |
|---|---|
| Local MISP event index | Imported MISP event JSON stored in SQLite, exact matches, and co-occurrences |
| CIRCL OSINT | Public feed entries for matching indicators |
| ThreatDefence | Published indicators, reported confidence, review dates, and detection references |
| MITRE ATT&CK | Group aliases, campaigns, malware, techniques, and references |
| MISP Galaxy | Public actor and ransomware catalogs with exact name and alias matches |
| Official cybercrime publications | CISA, FBI IC3, DOJ, and Europol references found via SearXNG, with indexed and verified records distinguished |
| Ransomware.live | Optional tracker profiles and aggregate claim counts, with `RANSOMWARE_LIVE_API_KEY` |
| SearXNG | Exact-phrase and site-specific searches across public forums, blogs, and repositories |
| Mwmbl | Independent web search, with an optional `MWMBL_API_KEY` |
| Arquivo.pt | Archived web mentions and capture dates |
| Public GitHub | Public repositories that match a term |
| Historical web reports | Exact and defanged IOC matches in selected public publishers |
| VirusTotal | Existing analyses, with an optional `VIRUSTOTAL_API_KEY` |
| Shodan | Observed public IP services, with an optional `SHODAN_API_KEY` |
| ThreatFox | Public IOC associations, with an optional `THREATFOX_AUTH_KEY` |
| CISA KEV | Known exploited vulnerabilities for CVE seeds (downloaded catalog) |
| Feodo Tracker | Botnet C2 IPs (downloaded blocklist) |
| URLhaus | Malicious URLs hosted on a domain or IP |
| MalwareBazaar | Known malware samples for a hash |
| RDAP | Registration records for an IP, domain, or ASN |
| crt.sh | Certificate-transparency subdomains for a domain |
| RIPEstat | Announcing AS for an IP and the AS holder |

The default SearXNG configuration excludes DuckDuckGo because of recurring CAPTCHAs. Independent sources continue when a web engine is unavailable. OpenInvestigation checks accessible public HTTPS pages for textual matches and keeps unavailable pages as indexed evidence. An automatic expansion round can look up up to six indicators and two names extracted from verified pages. IOC lookups query passive data providers, and linked detection rules remain references.

Set `OSINT_WEB=0` to disable external collection. When running outside Compose, set `OSINT_SEARCH_URL` to your SearXNG search endpoint. A bundled CYFIRMA reference provides an offline regression case for `143.198.64.151`. Its publication date does not establish current use of the IP. [Historical report](https://www.cyfirma.com/research/osint-investigation-hunting-malicious-infrastructure-linked-to-transparent-tribe/)

## OPSEC and egress

Each case carries a **TLP** that controls what may leave your machine. You choose it when you start an investigation; there is no default, so the choice is deliberate.

| TLP | Sources that run |
|---|---|
| `RED` | Local only — imported MISP events and local history. No external request, no model. |
| `AMBER` | Local plus public catalogs (ATT&CK, MISP Galaxy, CIRCL, ThreatDefence). No web search, no hosted model. Reputation providers only if you opt in per case. |
| `GREEN` / `CLEAR` | Every enabled source. |

**Passive mode** (any TLP) restricts a case to local data and catalogs that are downloaded in full and matched locally, so the seed itself is never sent. Per-source toggles let you enable or disable individual sources within what the TLP allows, and the form previews exactly which sources will receive the seeds before you start. A per-case **query log** records what each source was sent and how many results it returned.

Outbound requests are configurable:

- `OSINT_HTTP_PROXY` — route all outbound traffic through an `http://` (recommended) or `https://` proxy. When set it is the only proxy used. SOCKS is not supported (standard-library limitation).
- `OSINT_USER_AGENT` — override the outbound User-Agent (neutral default).
- `OSINT_FETCH_ALLOW` / `OSINT_FETCH_DENY` — comma-separated host suffixes that allow or deny which pages the reader may fetch.

Source text sent to a model is treated as untrusted: excerpts are stripped of obvious prompt-injection patterns and output delimiters and capped per excerpt, and the case records how many were sanitized.

## Investigating cybercrime groups

Enter a group name or alias, for example `LockBit`. MISP Galaxy distinguishes actor records from ransomware families. Official publications add advisories and law-enforcement references. A charging announcement is labeled as an allegation. Ransomware.live totals reflect claims recorded by the tracker and require independent corroboration.

MISP Galaxy and official publications do not require an API token. To enable the optional tracker, register at [Ransomware.live](https://my.ransomware.live/), generate your API Pro key and add `RANSOMWARE_LIVE_API_KEY` to your local `.env`. Recreate the app container with `docker compose up -d --build osint`. The key is sent only to the Ransomware.live Pro API. [API documentation](https://api-pro.ransomware.live/docs)

## Assessment models

After [configuring your API keys](#configure-api-keys), OpenInvestigation tries models in this order:

1. **GPT-5 Mini** when `OPENAI_API_KEY` is set. Override it with `OSINT_OPENAI_MODEL`.
2. **Claude Sonnet 4.6** when `ANTHROPIC_API_KEY` is set. Override it with `OSINT_ANTHROPIC_MODEL`.
3. **OpenCode free models**. Compose defaults to `opencode/big-pickle`, then `opencode/deepseek-v4.1-flash-free`. Use `OSINT_OPENCODE_MODEL` and the comma-separated `OSINT_OPENCODE_FALLBACK_MODELS` to configure this sequence. Set `OPENCODE_API_KEY` if the console requires authentication.

Free-model availability and quotas can change. For frequent use, configure your own provider key. Providers can charge for requests and receive the public evidence excerpts used for the assessment. Each fallback uses the same evidence, and a failed assessment preserves the collection for retry. Set `OSINT_LLM=0` to disable assessments. [OpenCode model catalog](https://opencode.ai/docs/console/models/) · [Providers](https://opencode.ai/docs/providers/)

## Test

Run the controlled tests with `python3 -I -m unittest -q`. They use only the standard library and make no network requests. The HTTP/Docker workflow test is opt-in: run it explicitly with `python3 test_docker_workflow.py`. Older cases and original source passages retain their stored language. New model assessments are requested in English.

<img width="1184" height="633" alt="Screenshot 2026-11-23 at 11 56 48" src="https://github.com/user-attachments/assets/9a032e37-d102-4955-adcd-ae4bb6f8951b" />

<img width="1184" height="799" alt="Screenshot 2026-11-23 at 11 57 06" src="https://github.com/user-attachments/assets/8ce330b6-8322-4a59-8edf-292090b26202" />

<img width="1184" height="741" alt="Screenshot 2026-11-23 at 11 57 20" src="https://github.com/user-attachments/assets/52b4d744-b65b-4fed-ad32-e4762b09a299" />



