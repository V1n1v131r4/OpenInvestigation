# OpenInvestigation

OpenInvestigation is a self-hosted threat investigation workspace. It collects and correlates public evidence, maps relationships, and produces a case assessment whose citations lead back to the original evidence.

Docker Compose runs the application and a local SearXNG instance. The application keeps cases, evidence, and imported **MISP event JSON** in a local SQLite volume. The MISP import and correlation workflow is built in and works without a separate MISP server.

The application calls a configured model **directly over HTTP** (OpenAI or Anthropic) to write the assessment prose; the confidence score itself is computed in code. Inference runs at the hosted provider you configure. SearXNG and the source connectors also make external requests when enabled. There is no bundled model and no Node runtime in the image.

## Run locally

Install Docker with Docker Compose, then run from the project directory:

```sh
docker compose up --build -d
```

Open [http://127.0.0.1:8080](http://127.0.0.1:8080). Use `docker compose logs -f osint` to follow the service and `docker compose down` to stop it. SQLite data lives in the Compose volume. Set `OSINT_PORT` in `.env` to change the HTTP port.


## Configure API keys

Create a `.env` file next to `compose.yaml`. If you already have one, keep it and add any missing variables from the template.

```sh
test -f .env || cp .env.example .env
```

Open `.env` in a text editor and fill in only the integrations you want to use. All keys are optional. Leave unused values blank.

```dotenv
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
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

1. Enter up to 20 inputs, one per line. Supported inputs include IPv4, IPv6, CIDR ranges, domains, URLs, hashes, emails, CVEs, ASNs, crypto wallets (BTC/ETH/Monero/Tron), Brazilian PIX keys, IBANs, bank accounts, APT group names and aliases, and free-text search terms. Defanged input (`hxxp`, `[.]`, `[at]`) is normalized automatically, keeping the original. Prefix ambiguous types: `ua:`, `ja3:`, `jarm:`, `imphash:`, `ssdeep:`, `file:`, `mutex:`, `wallet:`, `pix:`, `iban:`, `conta:`.
2. Follow **Live activity** or browse the **Relationship graph**. Select a node to open the evidence panel. Drag the background to pan, and use the zoom controls or **Fit graph** to navigate.
3. Use **Case assessment** below the graph to review the conclusion, claims, hypotheses, and cited evidence. The orange confidence badge explains the score on a 0–5 scale. Each evidence item carries an Admiralty code (e.g. `B2`): a source-reliability letter from `reliability.json` and an information-credibility number. A text match confirms the term is present, not that the claim is true.
4. Confirm or reject individual evidence items. If you reject a cited item, the assessment and its confidence become out of date. **Reassess case** uses the stored evidence. **Run investigation again** searches confirmed entities when available and otherwise uses the original targets.
5. Open **Coverage and run history**, **Timeline**, or **Related cases** to compare collection runs, distinguish activity and publication dates, and open earlier evidence. Export the case as JSON or export supported observables and source notes as STIX 2.1.
6. Under **Case details**, record an owner, tags, and notes. Use **Archive** to keep a finished case out of the way, or **Delete** to remove a case and all its evidence (you are asked to confirm). When a web mention is verified, its page text is captured locally with a SHA-256 hash; **Open local copy** in the evidence panel shows that capture even if the page later changes or disappears.

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
| OFAC SDN | Sanctioned crypto wallets, matched locally against the Treasury SDN list (GitHub extract fallback) |
| Chainabuse | Community scam reports for a wallet, aggregated by category, with `CHAINABUSE_API_KEY` |
| Ransomwhere | Ransom-payment wallets (family and USD received), matched against the downloaded dataset |
| mempool.space | On-chain balance and transaction count for a BTC wallet (no key) |
| Etherscan | On-chain balance and first-seen for an ETH wallet, with `ETHERSCAN_API_KEY` |
| Validação local | Offline validation of PIX keys (CPF/CNPJ/email/phone/EVP) and IBAN (mod-97); nothing leaves the machine |
| Denúncias BR | Scam-report mentions of a PIX key or account on Brazilian complaint portals (low reliability) |
| Dorks de fraude | Curated dork pack (paste sites, Telegram, filetype dumps, scam context) for a fraud indicator |
| Ahmia | Full-text mentions of a fraud indicator on Tor hidden services, over clearnet (CSAM-filtered) |
| RansomLook | Leak-site / ransomware-ecosystem matches for a wallet or actor name (clearnet API) |
| IntelX | Paste/leak/darknet index, with `INTELX_API_KEY` (optional; free tier is very limited) |
| Feodo Tracker | Botnet C2 IPs (downloaded blocklist) |
| URLhaus | Malicious URLs hosted on a domain or IP, with `ABUSECH_API_KEY` (abuse.ch now requires auth) |
| MalwareBazaar | Known malware samples for a hash, with `ABUSECH_API_KEY` (abuse.ch now requires auth) |
| RDAP | Registration records for an IP, domain, or ASN |
| crt.sh | Certificate-transparency subdomains for a domain |
| RIPEstat | Announcing AS for an IP and the AS holder |
| OTX | AlienVault OTX pulses, with `OTX_API_KEY` |
| GreyNoise | Internet-scanner classification for an IP, with `GREYNOISE_API_KEY` |
| urlscan | Submitted scans for a domain, URL, or IP, with `URLSCAN_API_KEY` |
| Censys | Observed services for an IP, with `CENSYS_API_ID` and `CENSYS_API_SECRET` |
| CIRCL pDNS | Passive DNS records, with `CIRCL_PDNS_USER` and `CIRCL_PDNS_PASSWORD` |

### Financial-fraud indicators

Crypto wallets have strong open attribution: OFAC sanctions (authoritative), Chainabuse reports, the
Ransomwhere dataset, and on-chain explorers. Fiat indicators are weaker on purpose. There is **no open
bulk feed of fraudulent PIX keys or bank accounts** — Brazil's Central Bank fraud-marking is a per-key,
access-controlled DICT lookup, not an open API. For PIX and accounts OpenInvestigation therefore offers
deterministic offline validation (CPF/CNPJ/IBAN) plus low-reliability scam-report mentions, not a
definitive "this account is fraud" verdict. PIX keys can be personal data (CPF, phone, email); handle and
export accordingly.

Beyond the open clearnet, a dork pack (`Dorks de fraude`) targets indexed pastes, Telegram, and dumps,
and dark-web mentions are reached **over clearnet** via Ahmia (Tor hidden-service search), RansomLook
(ransomware leak sites), and optionally IntelX. Fetching `.onion` directly is out of scope: the egress
layer rejects SOCKS by design, so Tor would need a deliberate proxy redesign, opsec, and authorization.
These sources surface where an indicator appears — they never download or redistribute leaked data.

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

After [configuring your API keys](#configure-api-keys), OpenInvestigation calls the providers directly over HTTP, in this order:

1. **GPT-5 Mini** (OpenAI) when `OPENAI_API_KEY` is set. Override it with `OSINT_OPENAI_MODEL`.
2. **Claude Sonnet 4.6** (Anthropic) when `ANTHROPIC_API_KEY` is set. Override it with `OSINT_ANTHROPIC_MODEL`.

The model only writes the prose; the confidence score is computed in code and prevails. If a model fails or returns nothing usable, the next one is tried, and if none succeed the case still gets a code-generated assessment. Providers can charge for requests and receive the public evidence excerpts used for the assessment. Set `OSINT_LLM=0` to disable model assessments entirely (the code assessment still runs). [OpenAI API](https://platform.openai.com/docs/api-reference) · [Anthropic API](https://docs.anthropic.com/en/api)

## Test

Run the controlled tests with `python3 -I -m unittest -q`. They use only the standard library and make no network requests. The HTTP/Docker workflow test is opt-in: run it explicitly with `python3 test_docker_workflow.py`. Older cases and original source passages retain their stored language. New model assessments are requested in English.

<img width="1184" height="633" alt="Screenshot 2026-11-23 at 11 56 48" src="https://github.com/user-attachments/assets/9a032e37-d102-4955-adcd-ae4bb6f8951b" />

<img width="1184" height="799" alt="Screenshot 2026-11-23 at 11 57 06" src="https://github.com/user-attachments/assets/8ce330b6-8322-4a59-8edf-292090b26202" />

<img width="1184" height="741" alt="Screenshot 2026-11-23 at 11 57 20" src="https://github.com/user-attachments/assets/52b4d744-b65b-4fed-ad32-e4762b09a299" />



