"""A → B workflow and optional live reference check."""
import io
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import urlsplit

import app
import collectors
import public_pages


TARGETS = (
    ("BunQr Labs", "organization", "bunqrlabs.com"),
    ("Over Security", "organization", "oversecurity.com.br"),
    ("Vinicius Vieira", "individual", "linkedin.com/in/v1n1v131r4"),
    ("Ricardo Longatto", "individual", "https://desecsecurity.com/curso/novo-pentest-profissional"),
    ("DESEC Security", "organization", "desecsecurity.com.br"),
)


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


def create_and_wait(target, kind, reference, timeout=10):
    created = Client.call("/api/cases", {"target": target, "target_type": kind,
                                        "reference": reference, "confirmed": True}, 201)
    path = f"/api/cases/{created['case_id']}"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        case = Client.call(path)
        if case["searches"][0]["status"] not in ("queued", "running"):
            return path, case
        time.sleep(.04)
    raise AssertionError(f"Busca ainda em execução: {target}")


def fixture_page(url):
    host = urlsplit(url).hostname
    if host == "bunqrlabs.com":
        return 200, None, "<title>BunQr Intelligence</title><h1>Cybersecurity powered by AI</h1>"
    if host == "oversecurity.com.br":
        return 301, "https://www.oversecurity.com.br/", ""
    if host == "www.oversecurity.com.br":
        return 200, None, "<title>Over Security Intelligence</title><h1>Serviços de cibersegurança</h1>"
    if host == "www.linkedin.com":
        raise OSError("HTTP 999")
    if host == "br.linkedin.com":
        return 200, None, "<title>LinkedIn</title><h1>Vinícius Vieira</h1><p>Perfil profissional</p>"
    if host == "desecsecurity.com.br":
        raise OSError("Referência não verificável no ambiente de teste")
    if host == "desecsecurity.com":
        if urlsplit(url).path == "/":
            return 200, None, "<title>Desec Security</title><h1>Educação e consultoria em cibersegurança</h1>"
        return 200, None, (
            '<title>Novo Pentest Profissional - Desec Security</title>'
            '<meta name="description" content="Formação em cibersegurança">'
            '<h1>Novo Pentest Profissional</h1><p>' + ("Informações do curso. " * 65)
            + '</p><h2>Ricardo Longatto</h2><p>Fundador da Desec Security e instrutor.</p>'
        )
    raise AssertionError(url)


class Investigation(unittest.TestCase):
    def setUp(self):
        folder = self.enter(tempfile.TemporaryDirectory())
        self.enter(patch.object(app, "DB", Path(folder) / "cases.sqlite3"))
        self.enter(patch.dict(os.environ, {"OSINT_WEB": "1", "OSINT_CORPUS_DIR": folder}))
        app.initialize()

    def enter(self, context):
        value = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        return value

    def test_confirmed_identity_to_evidence(self):
        self.enter(patch.object(public_pages, "request", side_effect=fixture_page))
        samples = [
            ("Bell Labs", "https://example.org/bell", "Pesquisa"),
            ("Android", "https://example.org/android", "Wiki"),
            ("Over Security", "https://oversecurity.com.br.example.org/", "Homônimo"),
            ("Vinícius Vieira", "https://br.linkedin.com/in/viniv", "Homônimo"),
        ]
        self.enter(patch.object(app, "SOURCE_MAP", {"Controle negativo": lambda _: samples}))
        for target, kind, reference in TARGETS:
            with self.subTest(target=target):
                path, case = create_and_wait(target, kind, reference)
                if reference == "desecsecurity.com.br":
                    self.assertEqual(case["searches"][0]["status"], "partial")
                    self.assertEqual(case["results"], [])
                    continue
                self.assertEqual(case["searches"][0]["status"], "done")
                self.assertEqual(len(case["results"]), 1)
                evidence = case["results"][0]
                self.assertEqual(evidence["source"], "Referência confirmada")
                if target == "Vinicius Vieira":
                    self.assertEqual(evidence["title"], "Vinícius Vieira")
                    self.assertEqual(evidence["url"], "https://br.linkedin.com/in/v1n1v131r4/en")
                elif target == "Ricardo Longatto":
                    self.assertIn("Ricardo Longatto Fundador", evidence["excerpt"])
                elif target == "BunQr Labs":
                    self.assertEqual(evidence["title"], "BunQr Intelligence")
                    self.assertTrue(any("título diferente" in event["message"] for event in case["events"]))
                manual = Client.call(path + "/manual", {"query": target, "parent_id": evidence["id"]}, 201)
                self.assertEqual(Client.call(path)["searches"][-1]["parent_id"], evidence["id"])
                self.assertEqual(Client.call(path)["searches"][-1]["id"], manual["search_id"])

    def test_individual_without_reference_is_rejected(self):
        result = Client.call("/api/cases", {"target": "Ricardo Longatto", "target_type": "individual",
                                           "confirmed": True}, expected=400)
        self.assertIn("reference", result["error"])

    def test_desec_at_alternate_public_domain(self):
        self.enter(patch.object(public_pages, "request", side_effect=fixture_page))
        self.enter(patch.object(app, "SOURCE_MAP", {}))
        _, case = create_and_wait("DESEC Security", "organization", "desecsecurity.com")
        self.assertEqual(case["searches"][0]["status"], "done")
        self.assertEqual(case["results"][0]["url"], "https://desecsecurity.com/")

    def test_reject_cross_domain_redirect(self):
        identity = {"target_type": "organization", "reference": "example.com"}
        with self.assertRaisesRegex(ValueError, "fora do domínio"):
            public_pages.collect(identity, load=lambda url: (301, "https://example.net/", ""))

    def test_reject_private_address(self):
        local = [(None, None, None, None, ("127.0.0.1", 443))]
        with patch.object(public_pages.socket, "getaddrinfo", return_value=local):
            with self.assertRaisesRegex(ValueError, "endereços públicos"):
                public_pages.public_address("example.com", 443)

    def test_name_and_profile_variants(self):
        identity = {"target": "Vinicius Vieira", "target_type": "individual",
                    "reference": "https://linkedin.com/in/v1n1v131r4"}
        self.assertTrue(collectors.identity_match("Vinícius Vieira",
                        "https://br.linkedin.com/in/v1n1v131r4/en", "", identity))
        self.assertFalse(collectors.identity_match("Vinícius Vieira",
                         "https://br.linkedin.com/in/v1n1v131r45/en", "", identity))

    def test_publish_links_only_for_confirmed_subject(self):
        html = """<title>Patrícia Pessoa</title><h1>Patrícia Pessoa</h1><p>Pesquisadora.</p>
        <script type="application/ld+json">{"@graph":[
          {"@type":"Person","name":"Patrícia Pessoa","sameAs":"https://example.com/perfil",
           "worksFor":{"name":"Instituto Exemplo","url":"https://example.net/instituto"},
           "citation":"https://example.org/artigo"},
          {"@type":"Person","name":"Outra Pessoa","sameAs":"https://example.com/outra"}
        ]}</script>"""
        self.enter(patch.object(public_pages, "request", return_value=(200, None, html)))
        self.enter(patch.object(app, "SOURCE_MAP", {}))
        _, case = create_and_wait("Patricia Pessoa", "individual", "https://example.org/pessoa")
        findings = {row["source"]: row for row in case["results"]}
        self.assertEqual(set(findings), {"Referência confirmada", "Perfil declarado",
                                        "Vínculo profissional declarado", "Citação publicada"})
        self.assertEqual(findings["Vínculo profissional declarado"]["title"], "Instituto Exemplo")
        for label, result in findings.items():
            if label != "Referência confirmada":
                self.assertIn("https://example.org/pessoa", result["excerpt"])
                self.assertNotIn("/outra", result["url"])

    def test_capture_pivot_export_and_persistence(self):
        self.enter(patch.object(public_pages, "request", side_effect=fixture_page))
        self.enter(patch.object(app, "SOURCE_MAP", {}))
        path, case = create_and_wait(*TARGETS[0])
        anchor = case["results"][0]["id"]
        dork = '"BunQr Labs" site:bunqrlabs.com filetype:pdf'
        query_id = Client.call(path + "/manual", {"query": dork, "parent_id": anchor}, 201)["search_id"]
        evidence_id = Client.call(path + "/capture", {
            "search_id": query_id, "source": "Site institucional", "title": "Guia Prático de Privacidade Digital",
            "url": "https://bunqrlabs.com/guia-privacidade-digital/",
            "excerpt": "Publicação educacional sobre privacidade digital.",
        }, 201)["result_id"]
        next_search = Client.call(path + "/manual", {
            "query": '"Guia Prático de Privacidade Digital"', "parent_id": evidence_id,
        }, 201)["search_id"]
        Client.call(path + "/reviews", {
            "claim": "A organização publica conteúdo educacional.",
            "rationale": "O guia está disponível no domínio confirmado.",
            "evidence": [{"id": evidence_id, "stance": "supports"}],
        }, 201)
        app.initialize()
        saved = Client.call(path)
        searches = {item["id"]: item for item in saved["searches"]}
        evidence = next(item for item in saved["results"] if item["id"] == evidence_id)
        self.assertEqual(searches[query_id]["query"], dork)
        self.assertEqual(searches[query_id]["parent_id"], anchor)
        self.assertEqual(evidence["search_id"], query_id)
        self.assertEqual(searches[next_search]["parent_id"], evidence_id)
        markdown = Client.call(path + "/report.md")
        self.assertIn(f"E-{evidence_id}", markdown.replace(r"\-", "-"))
        self.assertIn("Guia Prático de Privacidade Digital", markdown)

    def test_source_unavailable_with_saved_reference(self):
        self.enter(patch.object(public_pages, "request", side_effect=fixture_page))

        def unavailable(_):
            raise OSError("HTTP 503")

        self.enter(patch.object(app, "SOURCE_MAP", {"Fonte indisponível": unavailable}))
        _, case = create_and_wait(*TARGETS[1])
        self.assertEqual(case["searches"][0]["status"], "partial")
        self.assertEqual(len(case["results"]), 1)
        self.assertTrue(any(event["source"] == "Fonte indisponível" and event["state"] == "error"
                            for event in case["events"]))

    def test_no_match_does_not_use_homonym(self):
        self.enter(patch.dict(os.environ, {"OSINT_WEB": "0"}))
        self.enter(patch.object(app, "SOURCE_MAP", {"Índice": lambda _: [
            ("Vinícius Vieira", "https://br.linkedin.com/in/viniv", "Homônimo"),
        ]}))
        _, case = create_and_wait(*TARGETS[2])
        self.assertEqual(case["searches"][0]["status"], "no_match")
        self.assertEqual(case["results"], [])

    def test_gdelt_leads_remain_separate_from_evidence(self):
        self.enter(patch.dict(os.environ, {"OSINT_WEB": "0"}))
        self.enter(patch.object(app, "SOURCE_MAP", {"GDELT": collectors.gdelt, "CVM": collectors.cvm}))
        fake = self.enter(patch.object(collectors, "fetch", return_value={"articles": [
            {"title": "Conferência regional", "url": "https://example.org/evento",
             "domain": "example.org", "seendate": "20261121T130000Z"},
        ]}))
        cvm = self.enter(patch.object(collectors, "cvm_records", side_effect=AssertionError("CVM em caso individual")))
        path, case = create_and_wait(*TARGETS[2])
        self.assertEqual(case["searches"][0]["status"], "leads")
        self.assertEqual(fake.call_args.args[1]["query"], '"Vinicius Vieira"')
        cvm.assert_not_called()
        lead = case["results"][0]
        self.assertEqual(lead["is_lead"], 1)
        self.assertIn("Indexado em 2026-11-21", lead["excerpt"])
        Client.call(path + "/reviews", {
            "claim": "Hipótese", "rationale": "Menção ainda não verificada.",
            "evidence": [{"id": lead["id"], "stance": "supports"}],
        }, expected=400)
        markdown = Client.call(path + "/report.md")
        self.assertIn("## Lacunas", markdown)
        self.assertIn("Pista sem atribuição confirmada", markdown)

    def test_cvm_exact_company_or_cnpj(self):
        payload = ("DENOM_SOCIAL;DENOM_COMERC;CNPJ_CIA;CD_CVM;SIT_REG\n"
                   "AÇÚCAR EXEMPLO S.A.;AÇÚCAR;12.345.678/0001-95;123;ATIVO\n"
                   "OUTRA AÇÚCAR EXEMPLO S.A.;;99.999.999/0001-99;999;ATIVO\n").encode("latin-1")
        self.enter(patch.object(collectors, "_cvm_expires", 0))
        self.enter(patch.object(collectors, "_cvm_rows", ()))
        download = self.enter(patch.object(collectors, "download", return_value=payload))
        by_name = list(collectors.cvm("Açúcar Exemplo"))
        by_cnpj = list(collectors.cvm("12.345.678/0001-95"))
        self.assertEqual(len(by_name), 1)
        self.assertIn("Código CVM: 123", by_name[0][2])
        self.assertTrue(by_name[0][1].endswith("#row=2"))
        self.assertEqual(by_cnpj[0][0], by_name[0][0])
        download.assert_called_once()

    def test_querido_diario_preserves_source_and_excerpt(self):
        fake = self.enter(patch.object(collectors, "fetch", return_value={"gazettes": [
            {"territory_name": "Município Exemplo", "date": "2026-11-20",
             "url": "https://example.org/diario.pdf", "excerpts": ["<b>Organização Exemplo</b> citada no ato."]},
        ]}))
        result = list(collectors.items(collectors.querido_diario, "Organização Exemplo"))
        self.assertEqual(fake.call_args.args[1]["querystring"], '"Organização Exemplo"')
        self.assertEqual(result[0][1], "https://example.org/diario.pdf")
        self.assertIn("Organização Exemplo citada", result[0][2])

    def test_camara_requires_relevant_name(self):
        self.enter(patch.object(collectors, "fetch", return_value={"dados": [
            {"id": 12, "nome": "Pessoa Exemplo", "siglaPartido": "P", "siglaUf": "SP"},
            {"id": 13, "nome": "Outra Pessoa"},
        ]}))
        result = list(collectors.camara("Pessoa Exemplo"))
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0][1].endswith("/deputados/12"))
        self.assertIn("Partido: P", result[0][2])

    def test_minha_receita_is_limited_to_explicit_cnpj(self):
        data = {"cnpj": "33683111000280", "razao_social": "Empresa Exemplo",
                "nome_fantasia": "Exemplo", "qsa": [{"nome_socio": "Sócia Exemplo",
                "qualificacao_socio": "Administradora", "cnpj_cpf_do_socio": "IDENTIFICADOR-FORA-DO-ESCOPO"}]}
        fetch = self.enter(patch.object(collectors, "download", return_value=json.dumps(data).encode()))
        self.assertEqual(list(collectors.minha_receita("Empresa Exemplo")), [])
        fetch.assert_not_called()
        result = list(collectors.minha_receita("33.683.111/0002-80"))
        self.assertEqual(result[0], ("Empresa Exemplo", "https://minhareceita.org/33683111000280",
                                     "CNPJ: 33683111000280 · Nome fantasia: Exemplo"))
        self.assertEqual(result[1][2], "Sócia Exemplo · Administradora")
        self.assertNotIn("IDENTIFICADOR-FORA-DO-ESCOPO", repr(result))

    def test_institution_enriches_unambiguous_public_cnpj(self):
        html = """<title>Empresa Exemplo</title><meta name="generator" content="WordPress 6.7">
        <link rel="canonical" href="https://empresa-alternativa.example/">
        <h1>Empresa Exemplo</h1><footer>CNPJ nº 33.683.111/0002-80</footer>
        <script type="application/ld+json">{"@type":"Organization","name":"Empresa Exemplo",
        "sameAs":"https://marca-alternativa.example/"}</script>"""
        data = {"cnpj": "33683111000280", "razao_social": "Empresa Exemplo", "logradouro": "Rua Exemplo",
                "numero": "42", "municipio": "Cidade Exemplo", "qsa": [{"nome_socio": "Sócia Exemplo",
                "qualificacao_socio": "Administradora"}]}
        self.enter(patch.object(public_pages, "request", return_value=(200, None, html)))
        self.enter(patch.object(app, "SOURCE_MAP", {"Minha Receita": collectors.minha_receita}))
        download = self.enter(patch.object(collectors, "download", return_value=json.dumps(data).encode()))
        _, case = create_and_wait("Empresa Exemplo", "organization", "empresa.example")
        download.assert_called_once_with("https://minhareceita.org/33683111000280")
        found = {row["source"]: row for row in case["results"] if row["source"] != "Minha Receita"}
        self.assertEqual(found["CNPJ declarado"]["title"], "CNPJ 33683111000280")
        self.assertEqual(found["Domínio alternativo declarado"]["url"], "https://marca-alternativa.example/")
        self.assertEqual(found["Domínio canônico declarado"]["title"], "empresa-alternativa.example")
        self.assertEqual(found["Tecnologia declarada"]["title"], "WordPress")
        registry = [row for row in case["results"] if row["source"] == "Minha Receita"]
        self.assertEqual(len(registry), 3)
        self.assertIn("Rua Exemplo 42", registry[1]["excerpt"])
        self.assertIn("Sócia Exemplo · Administradora", registry[2]["excerpt"])
        self.assertTrue(all(row["is_lead"] for row in registry))

    def test_corporate_collection_opens_linked_pages_and_enriches_registry(self):
        opened = []
        def load(url):
            opened.append(url)
            if url == "https://empresa.example/":
                return 200, None, """<title>Empresa Exemplo</title><h1>Empresa Exemplo</h1>
                <a href="/privacidade">Privacidade</a>
                <a href="/sobre-nos">Sobre</a>
                <a href="https://outra.example/contato">Contato externo</a>
                <a href="/admin">Contato administrativo</a>
                <a href="/guia-publico.pdf">Guia público</a>"""
            if url.endswith("/privacidade"):
                return 200, None, """<title>Política de Privacidade</title><h1>Política de Privacidade</h1>
                <p>CNPJ: 33.683.111/0002-80</p>
                <a href="mailto:privacidade@empresa.example">Privacidade</a>"""
            if url.endswith("/sobre-nos"):
                return 200, None, """<title>Sobre a Empresa Exemplo</title><h1>Sobre a empresa</h1>
                <a href="https://www.linkedin.com/company/empresa-exemplo/">LinkedIn</a>
                <a href="https://wa.me/5511999999999?text=Mensagem">WhatsApp</a>"""
            raise AssertionError(url)

        self.enter(patch.object(public_pages, "request", side_effect=load))
        self.enter(patch.object(app, "SOURCE_MAP", {"Minha Receita": collectors.minha_receita}))
        registry = {"cnpj": "33683111000280", "razao_social": "Empresa Exemplo",
                    "qsa": [{"nome_socio": "Administradora Exemplo"}]}
        download = self.enter(patch.object(collectors, "download", return_value=json.dumps(registry).encode()))
        _, case = create_and_wait("Empresa Exemplo", "organization", "empresa.example")
        self.assertCountEqual(opened, ["https://empresa.example/", "https://empresa.example/privacidade",
                                       "https://empresa.example/sobre-nos"])
        download.assert_called_once_with("https://minhareceita.org/33683111000280")
        found = {row["source"]: row for row in case["results"]}
        self.assertIn("/privacidade", found["CNPJ declarado"]["url"])
        self.assertEqual(found["Contato institucional"]["title"], "privacidade@empresa.example")
        self.assertEqual(found["WhatsApp publicado"]["url"], "https://wa.me/5511999999999")
        self.assertIn("/company/empresa-exemplo", found["Canal institucional publicado"]["url"])
        self.assertIn("guia-publico.pdf", found["Documento público publicado"]["url"])
        self.assertTrue(any(row["message"] == "Consultando: 33683111000280" for row in case["events"]))
        self.assertTrue(any(row["message"] == "Abrindo https://empresa.example/privacidade" for row in case["events"]))

    def test_web_search_executes_corporate_plan_and_pivots_to_registry(self):
        self.enter(patch.dict(os.environ, {"OSINT_SEARCH_URL": "http://search:8080/search", "OSINT_WEB": "0"}))
        self.enter(patch.object(app, "SOURCE_MAP", {"Busca web": collectors.web_search,
                                                  "Minha Receita": collectors.minha_receita}))
        def search(endpoint, params):
            self.assertEqual(endpoint, "http://search:8080/search")
            self.assertEqual(params["format"], "json")
            if "site:casadosdados.com.br" not in params["q"]:
                return {"results": []}
            return {"results": [
                {"title": "Empresa Exemplo", "url": "https://cnpj.biz/exemplo",
                 "content": "Empresa Exemplo, CNPJ 33.683.111/0002-80."},
                {"title": "Empresa Exemplo", "url": "https://www.econodata.com.br/exemplo",
                 "content": "CNPJ: 33.683.111/0002-80."},
                {"title": "Outra Empresa", "url": "https://cnpj.biz/outra",
                 "content": "CNPJ 12.ABC.345/01DE-35."},
            ]}
        call = self.enter(patch.object(collectors, "fetch", side_effect=search))
        registry = {"cnpj": "33683111000280", "razao_social": "Empresa Exemplo"}
        download = self.enter(patch.object(collectors, "download", return_value=json.dumps(registry).encode()))
        _, case = create_and_wait("Empresa Exemplo", "organization", "empresa.example")
        self.assertEqual(call.call_count, 7)
        download.assert_called_once_with("https://minhareceita.org/33683111000280")
        self.assertTrue(any(row["source"] == "Minha Receita" for row in case["results"]))
        self.assertTrue(all(row["is_lead"] for row in case["results"]))
        self.assertFalse(any("12ABC" in row["title"] or "Outra Empresa" == row["title"]
                             for row in case["results"]))

    def test_web_outage_keeps_prior_hit_and_enriches_unique_directory_cnpj(self):
        self.enter(patch.dict(os.environ, {"OSINT_SEARCH_URL": "http://search:8080/search", "OSINT_WEB": "0"}))
        self.enter(patch.object(app, "SOURCE_MAP", {"Busca web": collectors.web_search,
                                                  "Minha Receita": collectors.minha_receita}))
        responses = [{"results": [{"title": "Empresa Exemplo", "url": "https://cnpj.biz/exemplo",
                                    "content": "CNPJ: 33.683.111/0002-80."}]},
                     {"results": [], "unresponsive_engines": [["DuckDuckGo", "CAPTCHA"], ["Bing", "timeout"]]}]
        search = self.enter(patch.object(collectors, "fetch", side_effect=responses))
        registry = {"cnpj": "33683111000280", "razao_social": "Empresa Exemplo"}
        download = self.enter(patch.object(collectors, "download", return_value=json.dumps(registry).encode()))
        _, case = create_and_wait("Empresa Exemplo", "organization", "empresa.example")
        self.assertEqual(search.call_count, 2)
        download.assert_called_once()
        self.assertEqual(case["searches"][0]["status"], "partial")
        self.assertTrue(any("DuckDuckGo: CAPTCHA" in row["message"] for row in case["events"]))
        self.assertTrue(any("consulta(s) web adiada(s)" in row["message"] for row in case["events"]))
        self.assertEqual({row["source"] for row in case["results"]}, {"Busca web", "CNPJ a conferir", "Minha Receita"})

    def test_registration_pivot_skips_irrelevant_sources(self):
        case = {"target_type": "organization"}
        registration = "33.683.111/0002-80"
        for collector in (collectors.gdelt, collectors.querido_diario, collectors.wikipedia, collectors.crossref):
            self.assertFalse(collectors.applies(collector, case, registration))
        for collector in (collectors.cvm, collectors.minha_receita, collectors.web_search):
            self.assertTrue(collectors.applies(collector, case, registration))

    def test_individual_web_round_uses_name_and_profile_anchor(self):
        identity = {"target_type": "individual", "reference": "https://linkedin.com/in/v1n1v131r4"}
        outcomes = collectors.web_queries("Vinicius Vieira", identity, True)
        self.assertEqual(outcomes[0], '"Vinicius Vieira" "v1n1v131r4"')
        self.assertEqual(len(outcomes), 4)
        self.assertEqual(collectors.web_queries("Citação pública", identity, False), ['"Citação pública"'])

    def test_ambiguous_cnpjs_do_not_trigger_cadastral_lookup(self):
        html = "<title>Empresa Exemplo</title><p>CNPJ 33.683.111/0002-80 · CNPJ 12.ABC.345/01DE-35</p>"
        self.assertEqual(public_pages.cnpj_value("12.ABC.345/01DE-35"), "12ABC34501DE35")
        self.assertEqual(public_pages.cnpj_value("12.ABC.345/01DE-34"), "")
        self.enter(patch.object(public_pages, "request", return_value=(200, None, html)))
        self.enter(patch.object(app, "SOURCE_MAP", {"Minha Receita": collectors.minha_receita}))
        download = self.enter(patch.object(collectors, "download"))
        _, case = create_and_wait("Empresa Exemplo", "organization", "empresa.example")
        download.assert_not_called()
        leads = [row for row in case["results"] if row["is_lead"]]
        self.assertEqual([row["source"] for row in leads], ["CNPJ a conferir", "CNPJ a conferir"])

    def test_verify_lead_preserves_source_and_opens_pivot(self):
        self.enter(patch.dict(os.environ, {"OSINT_WEB": "0"}))
        self.enter(patch.object(app, "SOURCE_MAP", {"GDELT": collectors.gdelt}))
        self.enter(patch.object(collectors, "fetch", return_value={"articles": [
            {"title": "Mentions", "url": "https://example.org/noticia"},
        ]}))
        path, case = create_and_wait(*TARGETS[0])
        other_path, _ = create_and_wait(*TARGETS[1])
        lead = case["results"][0]
        evidence = {"result_id": lead["id"], "note": "A matéria cita o domínio oficial da organização."}
        Client.call(other_path + "/verify", evidence, expected=404)
        Client.call(path + "/verify", {"result_id": lead["id"], "note": "x" * 1001}, expected=400)
        Client.call(path + "/verify", evidence, expected=201)
        Client.call(path + "/verify", evidence, expected=201)
        updated = Client.call(path)
        result = updated["results"][0]
        self.assertEqual(result["id"], lead["id"])
        self.assertEqual(result["source"], "GDELT")
        self.assertEqual(result["is_lead"], 1)
        self.assertTrue(result["verified_at"])
        self.assertEqual(result["verification_note"], evidence["note"])
        self.assertEqual(sum("validada pelo investigador" in event["message"] for event in updated["events"]), 1)
        Client.call(path + "/reviews", {"claim": "A organização foi mencionada.", "rationale": "A fonte identifica o domínio.",
                                       "evidence": [{"id": lead["id"], "stance": "supports"}]}, expected=201)
        Client.call(path + "/manual", {"query": "Nova consulta", "parent_id": lead["id"]}, expected=201)
        self.assertEqual(Client.call(path)["searches"][-1]["parent_id"], lead["id"])
        self.assertIn("A matéria cita o domínio oficial", Client.call(path + "/report.md"))

    def test_confirmed_expansion_uses_qsa_members_and_skips_rejected_and_duplicates(self):
        self.enter(patch.dict(os.environ, {"OSINT_WEB": "0"}))
        self.enter(patch.object(app, "SOURCE_MAP", {"Busca web": collectors.web_search}))
        self.enter(patch.dict(os.environ, {"OSINT_SEARCH_URL": "http://search:8080/search"}))
        fetch = self.enter(patch.object(collectors, "fetch", return_value={"results": []}))
        path, case = create_and_wait(*TARGETS[0])
        search_id = case["searches"][0]["id"]
        with app.database() as conn:
            def result(title, excerpt, source):
                return conn.execute(
                    "INSERT INTO results (search_id, source, title, url, excerpt, collected_at, is_lead) "
                    "VALUES (?, ?, ?, ?, ?, ?, 1)",
                    (search_id, source, title, "https://example.org/" + title[:3], excerpt, app.now()),
                ).lastrowid
            qsa = result("QSA · 33683111000280 · 1–2 de 2",
                         "Pessoa Pública · Administradora | Outra Pessoa · Sócia", "Minha Receita")
            rejected = result("Homônimo", "Organização sem relação", "Busca web")
            pending = result("Citação pendente", "Material ainda sem revisão", "Busca web")
        self.assertEqual(Client.call(path + "/expand", {}, expected=201)["search_ids"], [])
        Client.call(path + "/verify", {"result_id": qsa}, expected=201)
        Client.call(path + "/verify", {"result_id": rejected}, expected=201)
        Client.call(path + "/reject", {"result_id": rejected}, expected=201)
        created = Client.call(path + "/expand", {}, expected=201)["search_ids"]
        self.assertEqual(len(created), 2)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            saved = Client.call(path)
            branches = [row for row in saved["searches"] if row["id"] in created]
            if all(row["status"] == "no_match" for row in branches):
                break
            time.sleep(.02)
        self.assertEqual({row["query"] for row in branches}, {"Pessoa Pública", "Outra Pessoa"})
        self.assertTrue(all(row["parent_id"] == qsa for row in branches))
        self.assertIn('"Pessoa Pública" "BunQr Labs"', [call.args[1]["q"] for call in fetch.call_args_list])
        self.assertEqual(Client.call(path + "/expand", {}, expected=201)["search_ids"], [])
        self.assertNotIn("Homônimo", Client.call(path + "/report.md"))
        Client.call(path + "/verify", {"result_id": pending}, expected=201)
        second_round = Client.call(path + "/expand", {}, expected=201)["search_ids"]
        self.assertEqual(len(second_round), 1)
        while time.monotonic() < deadline:
            saved = Client.call(path)
            if saved["searches"][-1]["status"] == "no_match":
                break
            time.sleep(.02)
        self.assertEqual(saved["searches"][-1]["parent_id"], pending)

    def test_diagnostic_distinguishes_empty_and_limited_without_creating_cases(self):
        def limited(_query):
            raise HTTPError("https://example.org", 429, "Too Many Requests", {}, None)

        self.enter(patch.object(app, "DIAGNOSTIC_ROWS", {}))
        self.enter(patch.object(app, "DIAGNOSTIC_STARTED", None))
        self.enter(patch.object(app, "SOURCE_MAP", {
            "Vazia": lambda _: [],
            "Limitada": limited,
            "Ativa": lambda _: [("Resultado", "https://example.org/registro", "Teste")],
        }))
        Client.call("/api/diagnostics", {}, expected=202)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            checks = {row["source"]: row for row in Client.call("/api/diagnostics")["checks"]}
            if all(row["status"] != "running" for row in checks.values()):
                break
            time.sleep(.02)
        self.assertEqual(checks["Vazia"]["status"], "empty")
        self.assertEqual(checks["Ativa"]["status"], "ok")
        self.assertEqual(checks["Limitada"]["status"], "error")
        self.assertIn("HTTP 429", checks["Limitada"]["detail"])
        self.assertEqual(Client.call("/api/cases")["cases"], [])

    def test_rerun_keeps_results_and_creates_new_root_search(self):
        self.enter(patch.object(public_pages, "request", side_effect=fixture_page))
        self.enter(patch.object(app, "SOURCE_MAP", {}))
        path, case = create_and_wait(*TARGETS[0])
        original = case["results"][0]["id"]
        result = Client.call(path + "/rerun", {}, expected=201)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            saved = Client.call(path)
            if saved["searches"][-1]["status"] == "done":
                break
            time.sleep(.02)
        self.assertEqual(len(saved["searches"]), 2)
        self.assertIsNone(saved["searches"][-1]["parent_id"])
        self.assertEqual(saved["searches"][-1]["id"], result["search_id"])
        self.assertEqual(len(saved["results"]), 2)
        self.assertEqual(saved["results"][0]["id"], original)

    @unittest.skipUnless(os.getenv("OSINT_LIVE_TEST") == "1", "requer HTTPS público")
    def test_live_references(self):
        for target, kind, reference in TARGETS:
            with self.subTest(target=target):
                _, case = create_and_wait(target, kind, reference, timeout=90)
                self.assertTrue(any(item["source"] == "Referência confirmada" for item in case["results"]),
                                [(event["source"], event["message"]) for event in case["events"]])


if __name__ == "__main__":
    unittest.main()
