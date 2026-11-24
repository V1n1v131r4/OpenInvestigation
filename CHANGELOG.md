# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
semantic versioning once releases are tagged.

## [Unreleased]

### Changed

- Refocused the tool on threat intelligence only (IOCs, actors, malware, campaigns) and removed
  the legacy people-and-organization investigation flow.
- Trimmed `collectors.py` to the CTI web-search surface (`download`, `fetch`, `clean`,
  `phrase_match`, `NoRedirects`, `SearchEnginesUnavailable`, `web_search`).
- Trimmed `public_pages.py` to the page-reading surface (`request`, `public_address`, `Page`,
  `secondary_page`, `is_official_host`).
- Rewrote `test_docker_workflow.py` as an opt-in, offline CTI HTTP smoke test and extracted the
  in-process test client into `test_support.py`.

### Added

- New no-key CTI sources, each with a size limit, timeout, typed errors, and a fixture test, slotted
  into the TLP policy: CISA KEV and Feodo Tracker (downloaded catalogs matched locally, so they run
  under AMBER) and URLhaus, MalwareBazaar, RDAP, crt.sh, and RIPEstat (seed lookups, reputation —
  opt-in under AMBER). RDAP follows registry bootstrap redirects; crt.sh adds certificate-transparency
  subdomains; RIPEstat adds the announcing AS and the AS holder.
- Optional keyed CTI sources, each opt-in under AMBER and gated by its own key: OTX (`OTX_API_KEY`),
  GreyNoise (`GREYNOISE_API_KEY`), urlscan (`URLSCAN_API_KEY`), Censys (`CENSYS_API_ID` +
  `CENSYS_API_SECRET`), and CIRCL pDNS (`CIRCL_PDNS_USER` + `CIRCL_PDNS_PASSWORD`).
- New seed types with validators: email, CVE, ASN, CIDR, JA3, JARM, crypto wallet (BTC/ETH),
  imphash, ssdeep, filename, and mutex, the ambiguous ones taking a prefix (`ja3:`, `jarm:`,
  `imphash:`, `ssdeep:`, `file:`, `mutex:`). Defanged input (`hxxp`, `[.]`, `(.)`, `[:]`, `[at]`) is
  normalized to a recognized indicator while the original form is kept.
- Per-case OPSEC controls: a required TLP level (CLEAR/GREEN/AMBER/RED, no default), passive mode, and
  per-source overrides, enforced by a new `policy.py` so a case only queries the sources its level
  allows (RED = local only; AMBER = local + catalogs, reputation opt-in, no web search or hosted
  model). A per-case query log records what each source was sent and how many results it returned.
- Configurable egress: `OSINT_HTTP_PROXY` (http/https) routes all outbound traffic through a proxy,
  `OSINT_USER_AGENT` overrides the outbound User-Agent, and `OSINT_FETCH_ALLOW`/`OSINT_FETCH_DENY`
  allow or deny which hosts the page reader may fetch. The page reader keeps its public-IP pinning
  when no proxy is set and tunnels via CONNECT when one is.
- LLM input sanitization: source excerpts are stripped of obvious prompt-injection patterns and
  output delimiters and capped per excerpt before being sent to the model, and the case logs how
  many excerpts were sanitized.
- Confidence computed in code: a pure `cti.score` derives the 0–5 confidence from the evidence —
  0 without evidence, ceiling 2 with a single cluster, ceiling 3 without high-credibility
  corroboration, 4–5 with two or more independent clusters at credibility 1–2. The model no longer
  sets the score: it is shown the code score and writes only the prose, and the code score prevails
  in the UI if the model diverges. A case always carries `score` even when no model runs. When no
  hosted model is allowed (RED/AMBER or the model disabled) the application writes a deterministic,
  code-generated assessment from the score, reasons, and cited evidence, so every case has a written
  conclusion; under GREEN/CLEAR a model rewrites the prose instead.
- Temporal decay for IP and domain IOCs: each such evidence gets an age in days and a weight that
  declines once the sighting is older than `OSINT_IOC_DECAY_DAYS` (default 90), shown in the evidence
  panel and noted in the assessment, since infrastructure is reassigned over time.
- Shared-infrastructure noise filter (`noise.py`, editable `noise.json`, override via
  `OSINT_NOISE_FILE`): seeds and evidence on public DNS, cloud/CDN, or hosting infrastructure are
  marked `shared_infrastructure` and their Admiralty credibility is lowered so they cannot drive the
  score up.
- Entity resolution (`entities.py`): a canonical identity and alias graph from ATT&CK and MISP
  Galaxy, with per-alias sources, cross-catalog overlaps, and intra-catalog conflicts flagged.
- Model-claim validation: each assessment claim must cite evidence whose excerpt shares a term with
  the claim; unsupported claims are dropped and counted.
- Explicit truncation: collection caps are named constants instead of silent slices, a stage that
  hits its row limit is marked truncated (partial) in the run history, and a test guards against new
  silent cuts.
- Independence clustering: evidence is grouped into independent-origin clusters using a simhash of
  the page text (near-duplicate republications collapse together, configurable via
  `OSINT_SIMHASH_DISTANCE`), shared reference URLs, and citation links (one page citing another's
  URL). Each evidence gets a `cluster_id` and the case reports the number of independent clusters.
  This replaces the previous whole-body hash.
- Admiralty grading per evidence: a source-reliability letter (A–F) from a versioned, editable
  `reliability.json` plus an information-credibility number (1–6) derived from the evidence's
  confidence, shown as a code (e.g. B2) in the evidence panel; unknown sources default to F/6.
  The "verified mention" qualifier is renamed "Text match confirmed" to make clear it confirms the
  term is present, not that the claim is true.
- `LICENSE` (MIT), `SECURITY.md`, `CONTRIBUTING.md`, and a `CHANGELOG.md`.
- GitHub Actions CI running `python3 -I -m unittest -q` on Python 3.12, offline.
- Dependabot configuration for Docker base images and GitHub Actions.
- A test-time network guard (`netblock.py`) that blocks non-loopback access so the suite cannot
  reach the internet.
- Startup migration notice: legacy tables are detected and preserved, not dropped, with export and
  discard instructions in the README.

### Removed

- Legacy `/api/cases*` routes and the `cases`/`searches`/`results`/`events`/`reviews` schema code.
- Wikipedia, Crossref, GDELT, CVM, Querido Diário, Câmara, and Minha Receita source adapters, the
  local corpus reader, and the identity-matching helpers.
- CNPJ, LinkedIn, QSA, and institutional-page helpers in `public_pages.py`.
- Legacy static assets (`static/app.js`, `static/index.html`), the `corpus/` directory, the
  `OSINT_CORPUS_DIR` and `OSINT_FRAMEWORK` settings and mounts, the `runpy` dependency, and the
  `review_with_opencode.py` helper.
