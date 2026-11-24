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

- Per-case OPSEC controls: a required TLP level (CLEAR/GREEN/AMBER/RED, no default), passive mode, and
  per-source overrides, enforced by a new `policy.py` so a case only queries the sources its level
  allows (RED = local only; AMBER = local + catalogs, reputation opt-in, no web search or hosted
  model). A per-case query log records what each source was sent and how many results it returned.
- Configurable egress: `OSINT_HTTP_PROXY` (http/https) routes all outbound traffic through a proxy,
  `OSINT_USER_AGENT` overrides the outbound User-Agent, and `OSINT_FETCH_ALLOW`/`OSINT_FETCH_DENY`
  allow or deny which hosts the page reader may fetch. The page reader keeps its public-IP pinning
  when no proxy is set and tunnels via CONNECT when one is.
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
