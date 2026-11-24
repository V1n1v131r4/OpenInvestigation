"""Shared helper to drive the in-process HTTP handler from unit tests."""
import io
import json

import netblock

# Enforce the offline guarantee for the whole suite before anything touches the network.
netblock.install()

import app


class Client(app.Handler):
    def __init__(self, path, payload):
        self.path = path
        body = json.dumps(payload).encode()

        class Headers(dict):
            def get_content_type(self):
                return "application/json"

        self.headers = Headers(Host="localhost:8080")
        self.headers.update({"Content-Length": str(len(body)), "X-OSINT-Session": app.SESSION})
        self.rfile = io.BytesIO(body)

    def send_data(self, status, body, mime):
        self.response = status, json.loads(body) if mime.startswith("application/json") else body.decode()

    @classmethod
    def call(cls, path, payload=None, expected=200):
        instance = cls(path, payload)
        (instance.do_GET if payload is None else instance.do_POST)()
        status, response = instance.response
        if status != expected:
            raise AssertionError((status, response))
        return response
