# Contributing to OpenInvestigation

Thanks for helping improve OpenInvestigation. It is a threat-investigation workspace that collects
and correlates public threat intelligence (IOCs, actors, malware, campaigns). Contributions should
keep it simple, auditable, and runnable offline for tests.

## Ground rules

- **Standard library only.** The runtime and the tests depend on nothing beyond the Python
  standard library. A new third-party dependency must be justified in the pull request and is the
  exception, not the default.
- **Python 3.12+.** CI runs on 3.12.
- **English internal labels.** Enum values and stored data use English identifiers. Translation
  belongs in the UI. Do not store Portuguese text in new data.
- **No case data to third parties in tests.** Use fixtures and mocks. Tests must not make network
  requests; the suite blocks non-loopback sockets to enforce this.
- **Match the surrounding style.** 4-space indentation, no reformatting of untouched code, comment
  density and naming consistent with the file you are editing.

## Run it locally

With Docker (full stack, including SearXNG):

```sh
docker compose up --build -d
# http://127.0.0.1:8080  ·  logs: docker compose logs -f osint  ·  stop: docker compose down
```

Without Docker (app only, standard library):

```sh
OSINT_WEB=0 python3 app.py   # serves on http://127.0.0.1:8080
```

## Test

```sh
python3 -I -m unittest -q
```

The suite uses only the standard library, runs offline, and blocks non-loopback network access.
The HTTP/Docker workflow check is opt-in and boots a real server:

```sh
python3 test_docker_workflow.py
```

Every change must leave `python3 -I -m unittest -q` green. Add tests for new behavior.

## Proposing a new source

Sources are collectors: small functions that query one public dataset and yield normalized rows.
A new source should:

1. **Have a narrow, typed interface.** Take the seeds/terms it needs and yield relationship rows
   in the shape the existing collectors use. Raise typed errors (e.g. a specific exception or the
   shared `SearchEnginesUnavailable`) rather than returning partial garbage.
2. **Bound every response.** Pass an explicit size `limit` to `collectors.download` (or equivalent)
   and never read an unbounded body.
3. **Set an explicit timeout.** Reuse the shared 10s download timeout; do not block indefinitely.
4. **Ship a fixture-based test.** Patch the HTTP layer with a recorded fixture and assert the
   parsing, the error handling (HTTP 404/429, malformed payloads), and that no real request is
   made. Do not hit the live service in tests.
5. **Respect the case policy.** New sources must slot into the per-case source selection and the
   TLP policy (see `PLAN.md`, Stage 3). A source that sends the seed to a third party must be
   gated accordingly.
6. **Document it.** Add a row to the Sources table in `README.md` describing what it adds and any
   required key.

Keep secrets out of logs and out of requests that should not carry them. Treat all fetched source
text as untrusted input.

## Pull requests

- One focused change per PR, with a clear imperative title.
- Describe what changed and why, and note any new environment variable or dependency.
- Confirm the test suite passes and, when relevant, that `docker compose up --build` still boots
  and `/api/health` responds.
