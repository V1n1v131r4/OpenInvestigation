"""Per-case egress policy: which sources may run for a given TLP, passive flag, and overrides.

Source classes by what leaves the machine:
- local:      read-only local data (imported MISP events, bundled history). Nothing leaves.
- catalog:    download a public catalog/feed in full and match locally. The seed is NOT sent.
- web_search: send the seed or term to a search engine, or fetch arbitrary pages found that way.
- reputation: send the seed to a third-party reputation API.
- llm:        send evidence excerpts to a hosted model.

TLP rules (per PLAN.md, Stage 3):
- RED:          only local sources. No external request, no LLM. Overrides cannot re-enable.
- AMBER:        local + catalog. No web search, no hosted LLM. Reputation only if the case opts in.
- GREEN/CLEAR:  current behavior — every env-available source runs unless disabled per case.
Passive mode (any TLP): only local + catalog; no search, no per-seed reputation, no hosted LLM.
"""

TLP_LEVELS = ("CLEAR", "GREEN", "AMBER", "RED")
DEFAULT_TLP = "AMBER"

LOCAL_SOURCES = frozenset({"MISP local", "Histórico local", "Validação local"})
CATALOG_SOURCES = frozenset({"MITRE ATT&CK", "MISP Galaxy", "CIRCL OSINT", "ThreatDefence",
                             "CISA KEV", "Feodo Tracker", "OFAC SDN", "Ransomwhere"})
WEB_SEARCH_SOURCES = frozenset({
    "Busca web", "GitHub público", "Mwmbl", "Arquivo.pt",
    "Relatórios históricos na web", "Menções públicas", "Official cybercrime publications",
    "Denúncias BR", "Dorks de fraude",
})
REPUTATION_SOURCES = frozenset({"VirusTotal", "Shodan", "ThreatFox", "Ransomware.live",
                                "URLhaus", "MalwareBazaar", "RDAP", "crt.sh", "RIPEstat",
                                "OTX", "GreyNoise", "urlscan", "Censys", "CIRCL pDNS", "Chainabuse",
                                "mempool.space", "Etherscan", "Ahmia", "RansomLook", "IntelX"})
LLM_SOURCES = frozenset({"OpenCode"})
ALL_SOURCES = LOCAL_SOURCES | CATALOG_SOURCES | WEB_SEARCH_SOURCES | REPUTATION_SOURCES | LLM_SOURCES


def source_class(source):
    if source in LOCAL_SOURCES:
        return "local"
    if source in CATALOG_SOURCES:
        return "catalog"
    if source in WEB_SEARCH_SOURCES:
        return "web_search"
    if source in REPUTATION_SOURCES:
        return "reputation"
    if source in LLM_SOURCES:
        return "llm"
    return "web_search"  # unknown sources are treated as the most restricted (seed-sending) class


def normalize_tlp(value):
    value = (value or "").strip().upper()
    return value if value in TLP_LEVELS else DEFAULT_TLP


def permits_source(source, tlp, passive=False, overrides=None):
    """Return True if `source` may run for a case at this TLP / passive flag / overrides.

    `overrides` maps a source name to an explicit bool: True forces it on where the TLP allows
    opting in, False forces it off. Overrides can never enable a source the TLP forbids outright.
    """
    overrides = overrides or {}
    override = overrides.get(source)
    cls = source_class(source)

    if cls == "local":
        return override is not False

    tlp = normalize_tlp(tlp)
    if tlp == "RED":
        return False
    if passive and cls != "catalog":
        return False
    if cls == "catalog":
        return override is not False
    if tlp == "AMBER":
        if cls == "reputation":
            return override is True  # reputation is opt-in under AMBER
        return False  # web_search and hosted LLM are forbidden under AMBER
    # GREEN / CLEAR, not passive
    return override is not False


def effective_sources(available, tlp, passive=False, overrides=None):
    """Filter the env-available source list down to what the case policy allows, preserving order."""
    return [source for source in available if permits_source(source, tlp, passive, overrides)]


def permits_hosted_llm(tlp, passive=False, overrides=None):
    """Whether a hosted-model assessment may run for the case."""
    return permits_source("OpenCode", tlp, passive, overrides)
