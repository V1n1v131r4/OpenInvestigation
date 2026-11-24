"""Search adapters. Requests only go to the configured public web index."""
import json
import os
import re
from html import unescape
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

import egress


WEB_RESULT_LIMIT = 8  # results read from one web-search response


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def download(endpoint, headers=None, limit=2_000_000):
    request = Request(endpoint, headers={
        "User-Agent": egress.user_agent(),
        "Accept": "application/json",
        **(headers or {}),
    })
    with build_opener(NoRedirects(), *egress.proxy_handlers()).open(request, timeout=10) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Resposta acima do limite de tamanho.")
    return data


def fetch(endpoint, params):
    return json.loads(download(endpoint + "?" + urlencode(params)))


def clean(value):
    return unescape(re.sub(r"<[^>]*>", "", str(value))).strip()


def phrase_match(text, phrase):
    terms = phrase.split()
    if not terms:
        return None
    pattern = r"(?<!\w)" + r"\s+".join(map(re.escape, terms)) + r"(?!\w)"
    return re.search(pattern, text, re.IGNORECASE)


class SearchEnginesUnavailable(OSError):
    def __init__(self, records):
        labels = []
        for entry in records[:6]:
            if not isinstance(entry, list) or not entry or not isinstance(entry[0], str):
                continue
            engine = entry[0]
            if not re.fullmatch(r"[\w .-]{1,32}", engine):
                continue
            reason = str(entry[1]).casefold() if len(entry) > 1 else ""
            state = ("CAPTCHA" if "captcha" in reason else "rate limited" if any(
                key in reason for key in ("429", "too many", "rate limit")) else "timeout" if any(
                key in reason for key in ("timeout", "timed out")) else "unavailable")
            labels.append(f"{engine}: {state}")
        super().__init__("No search engine returned results" + (" · " + "; ".join(labels) if labels else ""))


def web_search(query):
    endpoint = os.getenv("OSINT_SEARCH_URL", "").strip()
    if not endpoint:
        return
    data = fetch(endpoint, {"q": query, "format": "json", "language": "all", "categories": "general"})
    rows = data.get("results")
    if not isinstance(rows, list):
        raise ValueError("Unexpected web search response format.")
    unavailable = data.get("unresponsive_engines")
    if not rows and isinstance(unavailable, list) and unavailable:
        raise SearchEnginesUnavailable(unavailable)
    for row in rows[:WEB_RESULT_LIMIT]:
        if not isinstance(row, dict):
            continue
        excerpt = clean(row.get("content") or "")
        yield row.get("title") or "", row.get("url") or "", f"Query: {query} · {excerpt}"
