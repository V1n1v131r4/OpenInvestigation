"""Unit tests for the per-case egress policy (policy.py)."""
import unittest

import policy

ALL = ["MISP local", "Histórico local", "MITRE ATT&CK", "MISP Galaxy", "CIRCL OSINT",
       "ThreatDefence", "Busca web", "GitHub público", "Mwmbl", "Arquivo.pt",
       "Relatórios históricos na web", "Menções públicas", "Official cybercrime publications",
       "VirusTotal", "Shodan", "ThreatFox", "Ransomware.live", "OpenCode"]


class Policy(unittest.TestCase):
    def test_red_allows_only_local_and_ignores_overrides(self):
        got = policy.effective_sources(ALL, "RED")
        self.assertEqual(got, ["MISP local", "Histórico local"])
        # An override cannot re-enable an external source under RED.
        forced = policy.effective_sources(ALL, "RED", overrides={"VirusTotal": True, "Busca web": True})
        self.assertEqual(forced, ["MISP local", "Histórico local"])
        self.assertFalse(policy.permits_hosted_llm("RED"))

    def test_amber_allows_local_and_catalog_but_not_web_or_llm(self):
        got = policy.effective_sources(ALL, "AMBER")
        self.assertEqual(got, ["MISP local", "Histórico local", "MITRE ATT&CK",
                               "MISP Galaxy", "CIRCL OSINT", "ThreatDefence"])
        self.assertNotIn("Busca web", got)
        self.assertNotIn("OpenCode", got)
        self.assertFalse(policy.permits_hosted_llm("AMBER"))

    def test_amber_reputation_is_opt_in_only(self):
        self.assertNotIn("VirusTotal", policy.effective_sources(ALL, "AMBER"))
        opted = policy.effective_sources(ALL, "AMBER", overrides={"VirusTotal": True, "Shodan": True})
        self.assertIn("VirusTotal", opted)
        self.assertIn("Shodan", opted)
        self.assertNotIn("ThreatFox", opted)  # not opted in
        # Opting in reputation must not drag web search or LLM along.
        self.assertNotIn("Busca web", opted)
        self.assertNotIn("OpenCode", opted)

    def test_clear_and_green_keep_current_behavior(self):
        for tlp in ("CLEAR", "GREEN"):
            self.assertEqual(policy.effective_sources(ALL, tlp), ALL)
            self.assertTrue(policy.permits_hosted_llm(tlp))

    def test_overrides_can_disable_an_allowed_source(self):
        got = policy.effective_sources(ALL, "CLEAR", overrides={"Busca web": False, "OpenCode": False})
        self.assertNotIn("Busca web", got)
        self.assertNotIn("OpenCode", got)
        self.assertIn("GitHub público", got)

    def test_passive_restricts_to_local_and_catalog_at_any_tlp(self):
        for tlp in ("CLEAR", "GREEN", "AMBER", "RED"):
            got = policy.effective_sources(ALL, tlp, passive=True)
            expected = ["MISP local", "Histórico local"] if tlp == "RED" else [
                "MISP local", "Histórico local", "MITRE ATT&CK", "MISP Galaxy", "CIRCL OSINT", "ThreatDefence"]
            self.assertEqual(got, expected, tlp)
            # No passive run may send a seed or evidence out.
            self.assertFalse(any(s in got for s in ("Busca web", "VirusTotal", "OpenCode")), tlp)

    def test_passive_overrides_cannot_enable_search_or_reputation(self):
        got = policy.effective_sources(ALL, "CLEAR", passive=True,
                                       overrides={"Busca web": True, "VirusTotal": True, "OpenCode": True})
        self.assertNotIn("Busca web", got)
        self.assertNotIn("VirusTotal", got)
        self.assertNotIn("OpenCode", got)

    def test_effective_sources_preserves_order_and_filters_unavailable(self):
        available = ["Histórico local", "MISP Galaxy", "Busca web"]
        self.assertEqual(policy.effective_sources(available, "CLEAR"), available)
        self.assertEqual(policy.effective_sources(available, "AMBER"), ["Histórico local", "MISP Galaxy"])

    def test_unknown_source_is_treated_as_seed_sending(self):
        self.assertEqual(policy.source_class("Mystery source"), "web_search")
        self.assertNotIn("Mystery source", policy.effective_sources(["Mystery source"], "AMBER"))
        self.assertIn("Mystery source", policy.effective_sources(["Mystery source"], "CLEAR"))

    def test_new_stage5_sources_are_classified(self):
        self.assertIn("CISA KEV", policy.CATALOG_SOURCES)
        self.assertIn("Feodo Tracker", policy.CATALOG_SOURCES)
        self.assertIn("URLhaus", policy.REPUTATION_SOURCES)
        self.assertTrue(policy.permits_source("CISA KEV", "AMBER"))          # catalog allowed under AMBER
        self.assertFalse(policy.permits_source("URLhaus", "AMBER"))          # reputation opt-in only
        self.assertTrue(policy.permits_source("URLhaus", "AMBER", overrides={"URLhaus": True}))
        self.assertFalse(policy.permits_source("CISA KEV", "RED"))           # nothing external under RED

    def test_normalize_tlp_defaults_to_amber(self):
        self.assertEqual(policy.normalize_tlp("red"), "RED")
        self.assertEqual(policy.normalize_tlp(""), "AMBER")
        self.assertEqual(policy.normalize_tlp("bogus"), "AMBER")
        self.assertEqual(policy.normalize_tlp(None), "AMBER")


if __name__ == "__main__":
    unittest.main()
