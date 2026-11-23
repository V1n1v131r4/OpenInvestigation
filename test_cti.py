"""Passive CTI checks using a temporary database and controlled source responses."""
import hashlib
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import app
import cti
from test_investigation import Client

EVENT = {"Event": {
    "uuid": "6f0407dd-e070-4213-a28a-aa8d963d9550",
    "info": "Boletim defensivo de teste", "date": "2026-11-18",
    "Attribute": [{"type": "ip-dst", "value": "192.0.2.80"},
                  {"type": "domain", "value": "example.org"},
                  {"type": "ip-dst", "value": "192.0.2.81", "deleted": True}],
    "Galaxy": [{"type": "mitre-intrusion-set", "GalaxyCluster": [{"value": "APT Exemplo"}]}],
}}
ATTACK_OBJECTS = [
    {"id": "group", "type": "intrusion-set", "name": "Grupo Exemplo", "aliases": ["APT Exemplo"],
     "external_references": [{"source_name": "mitre-attack", "external_id": "G0000",
                               "url": "https://attack.mitre.org/groups/G0000/"}]},
    {"id": "software", "type": "malware", "name": "Malware Exemplo"},
    {"type": "relationship", "source_ref": "group", "target_ref": "software", "relationship_type": "uses"},
    {"id": "revoked", "type": "intrusion-set", "name": "APT Exemplo", "revoked": True},
]
TD = ("type,value,confidence,context,actor,source,source_url,reported,review_by,framework\n"
      "ip,192.0.2.80,medium,,Ator Exemplo,Relatório,https://example.org/relatorio,2026-11-15,2026-12-01,artex\n"
      "user_agent,Exemplo/1.0,high,,Ator Exemplo,Relatório,https://example.org/relatorio,2026-11-15,,artex\n").encode()


class ThreatIntelligence(unittest.TestCase):
    def setUp(self):
        directory = self.enter(tempfile.TemporaryDirectory())
        self.enter(patch.object(app, "DB", Path(directory) / "cti.sqlite3"))
        self.enter(patch.dict(os.environ, {"OSINT_WEB": "0"}))
        app.initialize()

    def enter(self, manager):
        value = manager.__enter__()
        self.addCleanup(manager.__exit__, None, None, None)
        return value

    def collect(self, seeds):
        case_id = Client.call("/api/cti", {"seeds": seeds}, 201)["id"]
        path = f"/api/cti/{case_id}"
        return path, self.wait(path)

    def wait(self, path):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            data = Client.call(path)
            if data["status"] not in ("running", "queued"):
                return data
            time.sleep(.02)
        self.fail("Coleta CTI não terminou.")

    def test_real_historical_regression_returns_report_and_attribution_offline(self):
        path, case = self.collect("143.198.64.151")
        first = next(item for item in case["relations"] if item["origin"] == "143.198.64.151")
        self.assertEqual(first["kind"], "Relatório")
        self.assertEqual(first["source"], "CYFIRMA")
        self.assertEqual(first["date"], "2024-09-27")
        self.assertIn("cyfirma.com/research/", first["reference"])
        group = next(item for item in case["relations"] if item["kind"] == "Grupo")
        self.assertEqual(group["origin"], first["target"])
        self.assertEqual(group["target"], "Transparent Tribe")
        self.assertEqual(group["confidence"], "Atribuição da fonte")
        self.assertTrue(any(item["target"] == "Mythic" for item in Client.call(path)["relations"]))
        _, near = self.collect("143.198.64.15")
        self.assertEqual(near["status"], "empty")

    def test_keyword_case_queries_dorks_and_routes_web_evidence_to_opencode(self):
        import collectors

        self.enter(patch.dict(os.environ, {"OSINT_WEB": "1", "OSINT_SEARCH_URL": "http://search:8080/search",
                                          "OSINT_OPENCODE_MODEL": "opencode/big-pickle"}))
        self.enter(patch.object(cti.public_pages, "secondary_page", side_effect=OSError("Página indisponível")))
        self.enter(patch.object(cti, "attack_bundle", return_value=[]))
        self.enter(patch.object(cti, "open_index_mentions", return_value=[]))
        self.enter(patch.object(cti, "cached_feed", return_value=b'{"values":[]}'))
        self.enter(patch.object(cti, "provider_json", return_value={"items": []}))
        search = self.enter(patch.object(collectors, "web_search", return_value=[
            ("ARTEX no GitHub", "https://github.com/example/ARTEX", "Consulta · Repositório público"),
            ("Artexx", "https://example.org/other", "Consulta · Menção a Artexx"),
        ]))
        runner = self.enter(patch.object(cti.subprocess, "run", return_value=subprocess.CompletedProcess(
            [], 0, '{"parecer":"Contexto com base em ARTEX no GitHub (E1).","confianca":3}', "",
        )))
        _, case = self.collect("artex")
        self.assertEqual(case["status"], "done")
        self.assertEqual(case["seeds"][0]["kind"], "Termo")
        queries = [call.args[0] for call in search.call_args_list]
        self.assertIn('"artex"', queries)
        self.assertIn('"artex" site:github.com', queries)
        self.assertTrue(any("site:reddit.com" in query for query in queries))
        rows = {item["source"]: item for item in case["relations"]}
        self.assertEqual(len(case["relations"]), 2)
        self.assertEqual(rows["Busca web"]["reference"], "https://github.com/example/ARTEX")
        self.assertIn("ARTEX no GitHub", rows["OpenCode"]["detail"])
        command = runner.call_args.args[0]
        self.assertIn("opencode/big-pickle", command)
        self.assertIn("Repositório público", command[-1])

    def test_keyword_case_keeps_github_mentions_and_open_code_when_searxng_fails(self):
        import collectors

        self.enter(patch.dict(os.environ, {"OSINT_WEB": "1", "OSINT_SEARCH_URL": "http://search:8080/search",
                                          "OSINT_OPENCODE_MODEL": "opencode/big-pickle"}))
        self.enter(patch.object(cti.public_pages, "secondary_page", side_effect=OSError("Página indisponível")))
        self.enter(patch.object(cti, "attack_bundle", return_value=[]))
        self.enter(patch.object(cti, "open_index_mentions", return_value=[]))
        self.enter(patch.object(cti, "cached_feed", return_value=b'{"values":[]}'))
        self.enter(patch.object(collectors, "web_search", side_effect=collectors.SearchEnginesUnavailable(
            [["duckduckgo", "CAPTCHA"]])))
        github = self.enter(patch.object(cti, "provider_json", return_value={"items": [
            {"name": "ARTEX", "full_name": "V1n1v131r4/ARTEX", "private": False,
             "description": "Descrição pública do ARTEX", "html_url": "https://github.com/V1n1v131r4/ARTEX"},
        ]}))
        runner = self.enter(patch.object(cti.subprocess, "run", return_value=subprocess.CompletedProcess(
            [], 0, '{"parecer":"O GitHub contém um projeto chamado ARTEX (E1).","confianca":3}',
        )))
        _, case = self.collect("artex")
        self.assertEqual(case["status"], "partial")
        self.assertTrue(any(event["source"] == "Busca web" and event["status"] == "error" for event in case["events"]))
        self.assertEqual({row["source"] for row in case["relations"]}, {"GitHub público", "OpenCode"})
        self.assertIn("api.github.com/search/repositories?", github.call_args.args[0])
        self.assertIn("V1n1v131r4/ARTEX", runner.call_args.args[0][-1])

    def test_term_is_verified_and_automatically_expanded_before_assessment(self):
        import collectors

        self.enter(patch.dict(os.environ, {"OSINT_OPENCODE_MODEL": "opencode/big-pickle"}))
        self.enter(patch.object(cti, "configured_sources", return_value=["Busca web", "Histórico local", "OpenCode"]))
        reference = "https://example.org/first-report"
        alias_reference = "https://example.org/follow-up"
        def search(query):
            if '"Campaign Quartz"' in query:
                return [("Campaign Quartz report", reference, "Consulta · Campaign Quartz")]
            if '"Quartz Echo"' in query:
                return [("Quartz Echo follow-up", alias_reference, "Consulta · Quartz Echo")]
            return []
        engine = self.enter(patch.object(collectors, "web_search", side_effect=search))
        page = cti.public_pages.Page()
        page.feed('<meta property="article:published_time" content="2024-10-01">')
        reports = {
            reference: 'Campaign Quartz was observed on 2024-09-27. IOC 143[.]198[.]64[.]151. Alias: “Quartz Echo”.',
            alias_reference: 'Quartz Echo cites a separate address 8[.]8[.]8[.]8.',
        }
        self.enter(patch.object(cti.public_pages, "secondary_page", side_effect=lambda url, host: (
            page, "Report", url, reports[url], reports[url],
        )))
        def model(command, **kwargs):
            self.assertIn("CYFIRMA", command[-1])
            self.assertIn("Quartz Echo", command[-1])
            return subprocess.CompletedProcess([], 0,
                '{"parecer":"Coocorrência em E1.","confianca":3}')
        self.enter(patch.object(cti.subprocess, "run", side_effect=model))
        _, case = self.collect("Campaign Quartz")
        self.assertEqual(case["status"], "done")
        rows = case["relations"]
        verified = next(row for row in rows if row["relationship"] == "Menção verificada na página")
        self.assertEqual((verified["date"], verified["activity_date"]), ("2024-10-01", "2024-09-27"))
        pivot = next(row for row in rows if row["target"] == "143.198.64.151")
        self.assertEqual(pivot["origin_id"], verified["target_id"])
        self.assertTrue(any(row["origin"] == pivot["target"] and row["source"] == "CYFIRMA" for row in rows))
        summary = next(row for row in rows if row["source"] == "OpenCode")
        self.assertTrue(any(citation["url"] == reference for citation in summary["citations"]))
        self.assertTrue(any(event["source"] == "Expansão automática" and event["status"] == "done"
                            for event in case["events"]))
        self.assertFalse(any('8.8.8.8' in call.args[0] for call in engine.call_args_list))

    def test_failed_assessment_reports_cause_and_can_retry_without_web_search(self):
        import collectors

        self.enter(patch.dict(os.environ, {"OSINT_OPENCODE_MODEL": "opencode/big-pickle"}))
        self.enter(patch.object(cti, "configured_sources", return_value=["Busca web", "OpenCode"]))
        self.enter(patch.object(cti.public_pages, "secondary_page", side_effect=OSError("Página indisponível")))
        engine = self.enter(patch.object(collectors, "web_search", return_value=[
            ("ARTEX no GitHub", "https://github.com/example/ARTEX", "Consulta · Repositório público"),
        ]))
        runner = self.enter(patch.object(cti.subprocess, "run", side_effect=[
            subprocess.CompletedProcess([], 1, "", "HTTP 429 [response internal-token]"),
            subprocess.CompletedProcess([], 0, '{"parecer":"Contexto em E1.","confianca":3}', ""),
        ]))
        path, case = self.collect("artex")
        self.assertEqual(case["status"], "partial")
        failure = next(event for event in case["events"]
                       if event["source"] == "OpenCode" and event["status"] == "error")
        self.assertIn("limited model usage", failure["message"])
        self.assertNotIn("internal-token", failure["message"])
        searches = engine.call_count
        Client.call(path + "/assessment", {}, 201)
        case = self.wait(path)
        self.assertEqual(case["status"], "done")
        self.assertEqual(engine.call_count, searches)
        self.assertEqual(runner.call_count, 2)
        self.assertTrue(any(row["source"] == "OpenCode" for row in case["relations"]))

    def test_ioc_only_case_gets_one_assessment_after_correlation(self):
        import json

        ip = "143.198.64.151"
        file_hash = "a" * 64
        self.enter(patch.dict(os.environ, {"OSINT_OPENCODE_MODEL": "opencode/big-pickle"}))
        self.enter(patch.object(cti, "configured_sources", return_value=["Histórico local", "OpenCode"]))

        def model(command, **kwargs):
            payload = json.loads(command[-1].split("\n", 1)[1])
            entries = {entry["tipo"]: entry for entry in payload}
            self.assertEqual(entries["Hash"]["termo"], file_hash)
            self.assertEqual(entries["Hash"]["achados"], [])
            self.assertEqual(entries["IP"]["termo"], ip)
            self.assertTrue(any(row["fonte"] == "CYFIRMA" for row in entries["IP"]["achados"]))
            return subprocess.CompletedProcess([], 0, '{"parecer":"E1 documenta o IP. O hash segue sem evidência.","confianca":3}')

        runner = self.enter(patch.object(cti.subprocess, "run", side_effect=model))
        _, case = self.collect(f"{ip}\n{file_hash}")
        self.assertEqual(case["status"], "done")
        runner.assert_called_once()
        rows = [row for row in case["relations"] if row["source"] == "OpenCode"]
        self.assertEqual({row["origin"] for row in rows}, {ip, file_hash})
        self.assertEqual({row["target_id"] for row in rows}, {"case-assessment"})
        self.assertEqual({row["target"] for row in rows}, {"Parecer do caso"})

    def test_open_indexes_and_models_continue_after_independent_failures(self):
        import collectors

        fallback = "opencode/deepseek-v4.1-flash-free,opencode/beam-free"
        self.enter(patch.dict(os.environ, {"OSINT_OPENCODE_MODEL": "opencode/big-pickle",
                                          "OSINT_OPENCODE_FALLBACK_MODELS": fallback}))
        self.enter(patch.object(cti, "configured_sources", return_value=[
            "Busca web", "Mwmbl", "Arquivo.pt", "OpenCode",
        ]))
        self.enter(patch.object(collectors, "web_search", side_effect=collectors.SearchEnginesUnavailable(
            [["duckduckgo", "CAPTCHA"]])))
        self.enter(patch.object(cti.public_pages, "secondary_page", side_effect=OSError("Página indisponível")))

        def index(url, headers, source):
            if source == "Mwmbl":
                self.assertTrue(url.startswith("https://api.mwmbl.org/api/v2/search/"))
                return {"results": [{"url": "https://example.org/quartz", "title": "Campaign Quartz",
                                     "content": "Campaign Quartz citation"}]}
            self.assertTrue(url.startswith("https://arquivo.pt/textsearch?"))
            return {"response_items": [{
                "title": "Campaign Quartz archive", "snippet": "<em>Campaign Quartz</em>",
                "linkToNoFrame": "https://arquivo.pt/noFrame/replay/20240927000000/https://example.org/quartz",
                "tstamp": "20240927000000",
            }]}

        self.enter(patch.object(cti, "provider_json", side_effect=index))
        runner = self.enter(patch.object(cti.subprocess, "run", side_effect=[
            subprocess.CompletedProcess([], 1, "", "HTTP 429"),
            subprocess.CompletedProcess([], 0, '{"parecer":"Resposta sem suporte (E99).","confianca":3}', ""),
            subprocess.CompletedProcess([], 0, '{"parecer":"Análise das duas fontes (E1, E2).","confianca":3}', ""),
        ]))
        _, case = self.collect("Campaign Quartz")
        self.assertEqual(case["status"], "partial")
        rows = {row["source"]: row for row in case["relations"]}
        self.assertEqual(set(rows), {"Mwmbl", "Arquivo.pt", "OpenCode"})
        self.assertEqual(rows["Arquivo.pt"]["date_kind"], "Captura")
        self.assertEqual(rows["Arquivo.pt"]["date"], "2024-09-27")
        self.assertEqual(rows["OpenCode"]["model"], "opencode/beam-free")
        self.assertEqual(rows["OpenCode"]["case_confidence"], 3)
        self.assertEqual(len(rows["OpenCode"]["citations"]), 2)
        args = [call.args[0] for call in runner.call_args_list]
        self.assertEqual([arg[arg.index("--model") + 1] for arg in args],
                         ["opencode/big-pickle", *fallback.split(",")])
        self.assertEqual(len({arg[-1] for arg in args}), 1)
        self.assertTrue(any(event["status"] == "warning" and "valid citations" in event["message"]
                            for event in case["events"]))

    def test_explicit_free_quota_skips_fallback_in_same_free_tier(self):
        self.enter(patch.dict(os.environ, {"OSINT_OPENCODE_FALLBACK_MODELS": "opencode/deepseek-v4.1-flash-free"}))
        result = subprocess.CompletedProcess([], 1, "", "You've used today's free messages. They reset at 8:38 AM.")
        runner = self.enter(patch.object(cti.subprocess, "run", return_value=result))
        attempt = lambda *args: None
        with self.assertRaisesRegex(cti.ProviderError, "free quota is exhausted.*8:38 AM"):
            list(cti.enrich_case(cti.parse_seeds("artex"), [],
                                 ["opencode/big-pickle", "opencode/deepseek-v4.1-flash-free"], attempt))
        runner.assert_called_once()

    def test_assessment_prioritizes_configured_api_keys_and_isolates_credentials(self):
        config = {"OPENAI_API_KEY": "test-openai", "ANTHROPIC_API_KEY": "test-anthropic",
                  "OSINT_OPENCODE_MODEL": "opencode/big-pickle",
                  "OSINT_OPENCODE_FALLBACK_MODELS": "opencode/deepseek-v4.1-flash-free"}
        self.enter(patch.dict(os.environ, config, clear=True))
        models = cti.assessment_models()
        self.assertEqual(models, ["openai/gpt-5-mini", "anthropic/claude-sonnet-4-6",
                                  "opencode/big-pickle", "opencode/deepseek-v4.1-flash-free"])
        runner = self.enter(patch.object(cti.subprocess, "run", side_effect=[
            subprocess.CompletedProcess([], 1, "", "HTTP 429"),
            subprocess.CompletedProcess([], 0, '{"parecer":"Análise da evidência E1.","confianca":3}', ""),
        ]))
        rows = list(cti.enrich_case(cti.parse_seeds("artex"), [{"achados": [{"id": "E1"}]}],
                                    models, lambda *args: None))
        self.assertEqual(rows[0]["model"], "anthropic/claude-sonnet-4-6")
        first, second = (call.kwargs["env"] for call in runner.call_args_list)
        self.assertEqual(first.get("OPENAI_API_KEY"), "test-openai")
        self.assertNotIn("ANTHROPIC_API_KEY", first)
        self.assertEqual(second.get("ANTHROPIC_API_KEY"), "test-anthropic")
        self.assertNotIn("OPENAI_API_KEY", second)
        os.environ["OPENAI_API_KEY"] = ""
        self.assertEqual(cti.assessment_models()[0], "anthropic/claude-sonnet-4-6")
        os.environ["ANTHROPIC_API_KEY"] = ""
        self.assertEqual(cti.assessment_models()[0], "opencode/big-pickle")

    def test_confidence_accepts_zero_and_rejects_out_of_range(self):
        outputs = ['{"parecer":"E1 é insuficiente.","confianca":0}',
                   '{"parecer":"E1 é insuficiente.","confianca":6}']
        self.enter(patch.object(cti.subprocess, "run", side_effect=[
            subprocess.CompletedProcess([], 0, output, "") for output in outputs
        ]))
        payload = [{"achados": [{"id": "E1"}]}]
        self.assertEqual(cti.assess_with_model(payload, "opencode/big-pickle")[1], 0)
        with self.assertRaisesRegex(cti.ProviderError, "integer confidence score from 0 to 5"):
            cti.assess_with_model(payload, "opencode/big-pickle")

    def test_audit_rounds_cross_case_and_stix_export(self):
        ip = "143.198.64.151"
        self.enter(patch.dict(os.environ, {"OSINT_OPENCODE_MODEL": "opencode/big-pickle"}))
        self.enter(patch.object(cti, "configured_sources", return_value=["Histórico local", "OpenCode"]))
        output = ('{"parecer":"E1 documenta a ocorrência.","confianca":3,'
                  '"justificativa":"Há documentação, com cobertura limitada.",'
                  '"afirmacoes":[{"texto":"Há registro público.","evidencias":["E1","E999"]}],'
                  '"hipoteses":[{"texto":"Infraestrutura histórica.","favor":["E1"],"contra":[],"contexto":[]}]}')
        self.enter(patch.object(cti.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, output, "")))
        path, original = self.collect(ip)
        assessment = original["assessment"]
        evidence_id = assessment["citations"][0]["evidence_id"]
        self.assertEqual(assessment["afirmacoes"][0]["evidencias"], ["E1"])
        self.assertEqual(assessment["hipoteses"][0]["favor"], ["E1"])
        self.assertTrue(original["rounds"][0]["new_evidence"])
        self.assertTrue(any(event["id"] == evidence_id for event in original["timeline"]))
        self.assertTrue(any(item["found"] > 0 for item in original["rounds"][0]["coverage"]
                            if item["source"] == "Histórico local"))
        _, other = self.collect(ip)
        self.assertTrue(any(item["case_id"] == original["id"] and item["evidence_id"] == evidence_id
                            for item in other["related_cases"]))
        bundle = Client.call(path + "/stix")
        self.assertEqual(bundle["type"], "bundle")
        observable = next(item for item in bundle["objects"] if item["type"] == "ipv4-addr")
        self.assertEqual(observable["value"], ip)
        self.assertTrue(any(observable["id"] in item.get("object_refs", []) for item in bundle["objects"]))

        Client.call(path + "/expand", {}, 201)
        repeated = self.wait(path)
        self.assertEqual(len(repeated["rounds"]), 2)
        self.assertEqual(repeated["rounds"][0]["new_evidence"], [])
        self.assertEqual(repeated["rounds"][0]["assessment_change"]["previous_score"], 3)
        with app.database() as conn:
            cti.save(conn, original["id"], [cti.relation(
                {"kind": "IP", "value": ip}, "Relatório", "Fonte alternativa", "Documentado",
                "Fonte teste", reference="https://example.org/report",
            )])
        Client.call(path + "/review", {"result_id": evidence_id, "review": "rejected"}, 201)
        self.assertTrue(Client.call(path)["assessment"]["stale"])
        case_before_retry = Client.call(path)
        Client.call(path + "/assessment", {}, 201)
        reevaluated = self.wait(path)
        self.assertFalse(reevaluated["assessment"]["stale"])
        self.assertEqual(len(reevaluated["rounds"]), len(case_before_retry["rounds"]))
        self.assertNotEqual(reevaluated["assessment"]["citations"][0]["evidence_id"], evidence_id)

    def test_criminal_group_sources_distinguish_catalog_allegation_and_claims(self):
        import collectors

        seed = "LockBit"
        official = "https://www.justice.gov/usao-nj/pr/example"
        self.enter(patch.dict(os.environ, {"RANSOMWARE_LIVE_API_KEY": "test-token"}))
        self.enter(patch.object(cti, "configured_sources", return_value=[
            "MISP Galaxy", "Official cybercrime publications", "Ransomware.live",
        ]))
        catalog = b'{"values":[{"value":"LockBit","description":"Catalog entry","meta":{"synonyms":["ABCD"]}}]}'
        self.enter(patch.object(cti, "cached_feed", side_effect=lambda url, limit:
            catalog if url.endswith("/threat-actor.json") else b'{"values":[]}'))
        self.enter(patch.object(collectors, "web_search", return_value=[
            ("LockBit lookalike", "https://justice.gov.example.org/pr/lockbit", "Query · LockBit"),
            ("LockBit charges", official, "Query · LockBit"),
        ]))
        page = cti.public_pages.Page()
        page.feed('<meta property="article:published_time" content="2024-05-07">')
        loader = self.enter(patch.object(cti.public_pages, "secondary_page", return_value=(
            page, "US charges alleged LockBit operator", official, "", "The charges concern LockBit.",
        )))
        def provider(url, headers, source):
            self.assertEqual(headers["X-API-KEY"], "test-token")
            if url.endswith("/groups"):
                return {"groups": [{"group": "lockbit", "victims": 123}]}
            return {"group": "LockBit", "url": "https://www.ransomware.live/group/lockbit/123",
                    "description": "Tracked group", "victims": 123}
        self.enter(patch.object(cti, "provider_json", side_effect=provider))
        _, case = self.collect(seed)
        self.assertEqual(case["status"], "done")
        loader.assert_called_once_with(official, "justice.gov")
        rows = {row["relationship"]: row for row in case["relations"]}
        self.assertEqual(rows["Alias listed by catalog"]["target"], "ABCD")
        self.assertEqual(rows["Criminal allegation reported"]["date"], "2024-05-07")
        self.assertEqual(rows["Claims recorded by tracker"]["confidence"], "Unverified claims")

    def test_web_ioc_lookup_verifies_report_body_and_defanged_exact_match(self):
        import collectors

        self.enter(patch.object(cti, "configured_sources", return_value=["Relatórios históricos na web"]))
        url = "https://www.cyfirma.com/research/fixture/"
        search = self.enter(patch.object(collectors, "web_search", return_value=[
            ("Resultado fora do escopo", "https://143.198.64.151/", ""),
            ("Relatório de teste", url, ""),
        ]))
        page = cti.public_pages.Page()
        page.feed('<meta property="article:published_time" content="2024-09-27T10:00:00Z">')
        opened = self.enter(patch.object(cti.public_pages, "secondary_page", return_value=(
            page, "Relatório de teste", url, "Pesquisa sobre APT36.",
            "O registro histórico cita 143[.]198[.]64[.]151.",
        )))
        _, case = self.collect("143.198.64.151")
        self.assertIn('"143[.]198[.]64[.]151"', search.call_args.args[0])
        opened.assert_called_once_with(url, "cyfirma.com")
        self.assertEqual({item["target"] for item in case["relations"]}, {"Relatório de teste", "APT36"})
        self.assertTrue(all(item["date"] == "2024-09-27" for item in case["relations"]))
        self.assertFalse(cti.report_match(cti.parse_seeds("143.198.64.15")[0],
                                          "O evento cita 143[.]198[.]64[.]151."))

    def test_import_and_correlate_two_indicators_and_neutral_ip(self):
        Client.call("/api/cti/misp", {"events": [EVENT]}, 201)
        self.assertEqual(Client.call("/api/cti")["imported"], 1)
        path, case = self.collect("192.0.2.80\nexample.org\nEXAMPLE.ORG\n192.0.2.81")
        self.assertEqual(case["status"], "done")
        self.assertEqual(len(case["seeds"]), 3)
        direct = [item for item in case["relations"] if item["relationship"] == "Registrado no evento"]
        self.assertEqual({item["origin"] for item in direct}, {"192.0.2.80", "example.org"})
        self.assertEqual({item["target_id"] for item in direct}, {EVENT["Event"]["uuid"]})
        indirect = next(item for item in case["relations"] if item["target"] == "APT Exemplo")
        self.assertEqual(indirect["confidence"], "Contexto indireto")
        self.assertEqual(indirect["date"], "2026-11-18")
        Client.call(path + "/review", {"result_id": indirect["id"], "review": "confirmed"}, 201)
        expanded = Client.call(path + "/expand", {}, 201)
        self.assertEqual(expanded["pivots"], 1)
        self.wait(path)
        _, neutral = self.collect("192.0.2.99")
        self.assertEqual(neutral["status"], "empty")

    def test_attack_alias_matches_group_and_malware(self):
        self.enter(patch.object(cti, "configured_sources", return_value=["MISP local", "MITRE ATT&CK"]))
        self.enter(patch.object(cti, "attack_bundle", return_value=ATTACK_OBJECTS))
        path, case = self.collect("APT Exemplo")
        self.assertEqual(case["status"], "done")
        self.assertEqual({item["target"] for item in case["relations"]}, {"Grupo Exemplo", "Malware Exemplo"})
        Client.call(path + "/reference", {"origin": "Grupo Exemplo", "category": "forum", "title": "Discussão pública",
                                        "url": "https://example.org/forum", "detail": "A publicação menciona o grupo."}, 201)
        item = Client.call(path)["relations"][-1]
        self.assertEqual(item["confidence"], "A conferir")

    def test_threatdefence_matches_ioc_and_user_agent_with_detection_reference(self):
        self.enter(patch.object(cti, "configured_sources", return_value=["MISP local", "ThreatDefence"]))
        self.enter(patch.object(cti, "cached_feed", return_value=TD))
        _, case = self.collect("192.0.2.80\nua: Exemplo/1.0")
        self.assertEqual({item["origin_kind"] for item in case["relations"]}, {"IP", "User-Agent", "Framework"})
        detections = [item for item in case["relations"] if item["kind"] == "Detecção"]
        self.assertEqual(len(detections), 1)
        self.assertTrue(detections[0]["reference"].endswith("/frameworks/artex"))
        self.assertTrue(any("Review by: 2026-12-01" in item["detail"] for item in case["relations"]))

    def test_circl_index_matches_locally_and_remains_exact(self):
        number = hashlib.md5(b"192.0.2.80", usedforsecurity=False).hexdigest()
        entry = (number + "," + EVENT["Event"]["uuid"] + "\n").encode()
        import json
        fetch = self.enter(patch.object(cti, "download", return_value=json.dumps(EVENT).encode()))
        self.enter(patch.object(cti, "cached_feed", return_value=entry))
        found = list(cti.circl_matches(cti.parse_seeds("192.0.2.80")))
        self.assertTrue(found)
        self.assertEqual(found[0]["source"], "CIRCL OSINT")
        self.assertTrue(found[0]["reference"].endswith(".json"))
        self.assertNotIn("192.0.2.80", fetch.call_args.args[0])
