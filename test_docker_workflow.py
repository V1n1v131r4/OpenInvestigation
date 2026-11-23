"""Exercise a real OSINT Local server over HTTP with an isolated database."""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from test_investigation import TARGETS

EXPECTED_FACTS = {
    "BunQr Labs": ("inteligência", "cybersecurity", "privacidade", "opsec"),
    "Over Security": ("consultoria", "treinamento", "pentest", "cibersegurança"),
    "Vinicius Vieira": ("trustly", "cibersegurança", "cybersecurity", "pesquisador"),
    "Ricardo Longatto": ("fundador", "instrutor", "especialista"),
    "DESEC Security": ("treinamento", "consultoria", "cibersegurança", "pentest"),
}


class Server:
    def __init__(self, directory):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        self.env = dict(os.environ, OSINT_HOST="127.0.0.1", OSINT_PORT=str(self.port),
                        OSINT_DATA_DIR=directory, OSINT_WEB="1")
        self.base = f"http://127.0.0.1:{self.port}"
        self.session = ""

    def open(self, path, payload=None):
        if payload is None:
            return urlopen(self.base + path, timeout=10)
        body = json.dumps(payload).encode()
        return urlopen(Request(self.base + path, data=body, headers={
            "Content-Type": "application/json", "X-OSINT-Session": self.session,
        }), timeout=10)

    def read(self, path, payload=None):
        with self.open(path, payload) as response:
            return json.load(response)

    def __enter__(self):
        self.process = subprocess.Popen([sys.executable, "app.py"], env=self.env)
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise RuntimeError("Servidor terminou antes do teste.")
                try:
                    if self.read("/api/health")["ok"]:
                        self.session = self.read("/api/cases")["session"]
                        return self
                except URLError:
                    time.sleep(.2)
            raise RuntimeError("Servidor não respondeu ao health check.")
        except Exception:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_):
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()


def finished(server, path):
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        case = server.read(path)
        if case["searches"][0]["status"] not in ("queued", "running"):
            return case
        time.sleep(.35)
    raise RuntimeError(f"Coleta ainda em execução: {path}")


def expected_reference(url, kind, reference):
    parsed = urlsplit(url)
    if kind == "organization":
        return parsed.hostname == reference or (parsed.hostname or "").endswith("." + reference)
    if reference == "linkedin.com/in/v1n1v131r4":
        return (parsed.hostname in {"linkedin.com", "www.linkedin.com", "br.linkedin.com"}
                and parsed.path.rstrip("/") in {"/in/v1n1v131r4", "/in/v1n1v131r4/en"})
    return url.rstrip("/") == reference.rstrip("/")


def run():
    targets = (*TARGETS, ("DESEC Security", "organization", "desecsecurity.com"))
    failures = 0
    records = []
    with tempfile.TemporaryDirectory(prefix="osint-docker-test-") as directory:
        server = Server(directory)
        with server:
            assert not server.read("/api/cases")["cases"]
            for name, kind, reference in targets:
                created = server.read("/api/cases", {
                    "target": name, "target_type": kind, "reference": reference, "confirmed": True,
                })
                path = f"/api/cases/{created['case_id']}"
                case = finished(server, path)
                evidence = [
                    row for row in case["results"] if row["source"] == "Referência confirmada"
                    and expected_reference(row["url"], kind, reference)
                    and any(term in row["excerpt"].casefold() for term in EXPECTED_FACTS[name])
                ]
                failures += not evidence
                print(json.dumps({
                    "alvo": name, "referencia": reference, "status": case["searches"][0]["status"],
                    "evidencias_uteis": evidence,
                    "indisponiveis": [e for e in case["events"] if e["state"] == "error"],
                }, ensure_ascii=False), flush=True)
                if not evidence:
                    continue
                root = evidence[0]
                query = '"' + name + '"'
                search = server.read(path + "/manual", {"query": query, "parent_id": root["id"]})
                captured_id = None
                if name == "BunQr Labs":
                    captured = server.read(path + "/capture", {
                        "search_id": search["search_id"], "source": "Site institucional",
                        "title": "Guia Prático de Privacidade Digital",
                        "url": "https://bunqrlabs.com/guia-privacidade-digital/",
                        "excerpt": "Publicação educacional sobre privacidade digital.",
                    })
                    captured_id = captured["result_id"]
                records.append((path, query, search["search_id"], root["id"], captured_id))
                with server.open(path + "/stream") as stream:
                    assert json.loads(stream.readline().removeprefix(b"data: "))["case"]["id"] == created["case_id"]
        with server:
            for path, query, search_id, evidence_id, captured_id in records:
                case = server.read(path)
                assert any(row["id"] == evidence_id for row in case["results"])
                assert any(row["id"] == search_id and row["query"] == query
                           and row["parent_id"] == evidence_id for row in case["searches"])
                if captured_id is not None:
                    assert any(row["id"] == captured_id and row["search_id"] == search_id
                               for row in case["results"])
                with server.open(path + "/report.md") as report:
                    markdown = report.read().decode().replace(r"\-", "-")
                    assert f"E-{evidence_id}" in markdown
    return bool(failures)


if __name__ == "__main__":
    raise SystemExit(run())
