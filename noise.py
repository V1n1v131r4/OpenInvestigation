"""Shared/noisy infrastructure filter.

Flags IOCs that sit on infrastructure many unrelated parties use — public DNS resolvers, major
cloud/CDN ranges, sinkholes, and high-traffic domains — so a co-occurrence there is weak evidence
of a relationship. The list is local and editable (`noise.json`, or a custom file via
`OSINT_NOISE_FILE`). Remote updates are out of scope here and would be opt-in and TLP-gated.
"""
import ipaddress
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

NOISE_FILE = Path(__file__).with_name("noise.json")
_NOISE = None


def _load():
    global _NOISE
    if _NOISE is None:
        path = os.getenv("OSINT_NOISE_FILE", "").strip() or NOISE_FILE
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        networks = []
        for cidr in data.get("cidrs", []):
            try:
                networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                continue
        domains = tuple(str(d).lower().rstrip(".") for d in data.get("domains", []) if isinstance(d, str) and d)
        labels = data.get("labels", {}) if isinstance(data.get("labels"), dict) else {}
        _NOISE = {"domains": domains, "networks": tuple(networks), "labels": labels}
    return _NOISE


def _host(kind, value):
    if not isinstance(value, str):
        return ""
    if kind == "IP":
        return value
    if kind == "Domínio":
        return value.lower().rstrip(".")
    if kind == "URL":
        try:
            return (urlsplit(value).hostname or "").lower().rstrip(".")
        except ValueError:
            return ""
    return ""


def classify(kind, value):
    """Return a reason string if the IOC is shared/noisy infrastructure, else ''."""
    data = _load()
    host = _host(kind, value)
    if not host:
        return ""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        for network in data["networks"]:
            if address in network:
                return data["labels"].get(str(network), f"IP in shared range {network}")
        return ""
    for domain in data["domains"]:
        if host == domain or host.endswith("." + domain):
            return data["labels"].get(domain, f"host under shared domain {domain}")
    return ""
