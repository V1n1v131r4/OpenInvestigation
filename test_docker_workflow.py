"""Exercise a real OpenInvestigation server over HTTP with an isolated database.

Opt-in: run explicitly with `python3 test_docker_workflow.py`. It boots app.py as a
subprocess and drives the CTI HTTP surface offline (OSINT_WEB=0), relying only on the
bundled regression data. It makes no external network requests.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from urllib.error import URLError
from urllib.request import Request, urlopen

# Bundled offline regression indicator (CYFIRMA reference shipped in cti_history.json).
REGRESSION_IP = "143.198.64.151"


class Server:
    def __init__(self, directory):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        self.env = dict(os.environ, OSINT_HOST="127.0.0.1", OSINT_PORT=str(self.port),
                        OSINT_DATA_DIR=directory, OSINT_WEB="0")
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
                    raise RuntimeError("Server exited before the test started.")
                try:
                    if self.read("/api/health")["ok"]:
                        self.session = self.read("/api/cti")["session"]
                        return self
                except URLError:
                    time.sleep(.2)
            raise RuntimeError("Server did not answer the health check.")
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
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        case = server.read(path)
        if case["status"] not in ("queued", "running"):
            return case
        time.sleep(.35)
    raise RuntimeError(f"Collection still running: {path}")


def run():
    with tempfile.TemporaryDirectory(prefix="openinvestigation-http-test-") as directory:
        server = Server(directory)
        with server:
            assert not server.read("/api/cti")["cases"]
            created = server.read("/api/cti", {"seeds": REGRESSION_IP, "tlp": "CLEAR"})
            path = f"/api/cti/{created['id']}"
            case = finished(server, path)
            print(json.dumps({
                "seed": REGRESSION_IP, "status": case["status"],
                "relations": len(case["relations"]),
                "events": [e for e in case["events"] if e["status"] == "error"],
            }, ensure_ascii=False), flush=True)
            attributed = any(row["source"] == "CYFIRMA" for row in case["relations"])
            # A reload must preserve the stored case across process restarts.
        with server:
            reloaded = server.read(path)
            assert reloaded["id"] == created["id"]
            bundle = server.read(path + "/stix")
            assert bundle["type"] == "bundle"
    return int(not attributed)


if __name__ == "__main__":
    raise SystemExit(run())
