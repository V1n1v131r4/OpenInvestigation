"use strict";

const byId = (id) => document.getElementById(id);
const states = {
  queued: "Na fila", running: "Em execução", done: "Concluída",
  error: "Falhou", partial: "Parcial", interrupted: "Interrompida", manual: "Consulta manual", no_match: "Sem correspondência", leads: "Pistas para conferir",
};
const stances = {supports: "Apoia", contradicts: "Contradiz", context: "Contexto"};
let session, history, current, selected, caseWatch, snapshot, focusedCase, manualParent;
const catalog = [
  {name: "Diário Oficial da União", url: "https://www.in.gov.br/materia", domain: "in.gov.br",
    types: ["name", "place"], detail: "Atos federais por órgão, período e palavra-chave."},
  {name: "Querido Diário", url: "https://queridodiario.ok.org.br/", domain: "queridodiario.ok.org.br",
    types: ["name", "place", "cnpj"], detail: "Diários oficiais municipais por município ou termo."},
  {name: "Receita Federal · CNPJ", url: "https://solucoes.receita.fazenda.gov.br/Servicos/cnpjreva/",
    types: ["cnpj"], detail: "Comprovante de inscrição e situação cadastral."},
  {name: "CVM RAD", url: "https://www.rad.cvm.gov.br/ENET/frmConsultaExternaCVM.aspx", domain: "cvm.gov.br",
    types: ["name", "cnpj"], detail: "Documentos e fatos relevantes de companhias abertas."},
  {name: "CADE · Consulta pública",
    url: "https://sei.cade.gov.br/sei/modulos/pesquisa/md_pesq_processo_pesquisar.php?acao_externa=protocolo_pesquisar&acao_origem_externa=protocolo_pesquisar&id_orgao_acesso_externo=0",
    domain: "cade.gov.br", types: ["name", "process"], detail: "Processos e documentos por interessado ou número SEI."},
  {name: "CVM · Dados Abertos", url: "https://dados.cvm.gov.br/", domain: "dados.cvm.gov.br",
    types: ["name", "cnpj"], detail: "Cadastro e documentos de companhias abertas."},
  {name: "Minha Receita", url: "https://docs.minhareceita.org/como-usar/",
    types: ["cnpj"], detail: "Consulta cadastral automática quando a busca contém um CNPJ."},
  {name: "Câmara dos Deputados · Dados Abertos", url: "https://dadosabertos.camara.leg.br/", domain: "camara.leg.br",
    types: ["name", "place"], detail: "Deputados em exercício, proposições e eventos legislativos."},
  {name: "Senado Federal · Dados Abertos", url: "https://www12.senado.leg.br/dados-abertos", domain: "senado.leg.br",
    types: ["name", "place"], detail: "Parlamentares, matérias e pronunciamentos."},
  {name: "PJe · Comunicações", url: "https://comunica.pje.jus.br/", domain: "jus.br",
    types: ["name", "process"], detail: "Comunicações processuais públicas."},
  {name: "CARF · Acórdãos", url: "https://carf.economia.gov.br/", domain: "carf.economia.gov.br",
    types: ["name", "process"], detail: "Acórdãos e referências a processos fiscais públicos."},
  {name: "INPI · Marcas", url: "https://busca.inpi.gov.br/pePI/jsp/marcas/Pesquisa_classe_basica.jsp", domain: "inpi.gov.br",
    types: ["name", "process"], detail: "Busca oficial de marcas por nome e processo."},
  {name: "INPI · Patentes", url: "https://busca.inpi.gov.br/pePI/jsp/patentes/PatenteSearchBasico.jsp", domain: "inpi.gov.br",
    types: ["name", "process"], detail: "Pesquisa de patentes no portal do INPI."},
  {name: "TSE · Candidaturas e Contas", url: "https://divulgacandcontas.tse.jus.br/divulga/", domain: "tse.jus.br",
    types: ["name", "place"], detail: "Registros públicos eleitorais por candidato, local e eleição."},
  {name: "TSE · Dados abertos", url: "https://dadosabertos.tse.jus.br/", domain: "dadosabertos.tse.jus.br",
    types: ["name", "place"], detail: "Bases eleitorais para download."},
  {name: "Biblioteca Digital de Teses e Dissertações", url: "https://bdtd.ibict.br/", domain: "bdtd.ibict.br",
    types: ["name"], detail: "Teses e dissertações por título, autor ou instituição."},
  {name: "USP · Teses e Dissertações", url: "https://www.teses.usp.br/", domain: "teses.usp.br",
    types: ["name"], detail: "Produção acadêmica e publicações da USP."},
  {name: "Dados.gov.br", url: "https://dados.gov.br/", domain: "dados.gov.br",
    types: ["name", "place"], detail: "Catálogo de conjuntos de dados públicos brasileiros."},
  {name: "IBGE · Cidades e Estados", url: "https://www.ibge.gov.br/cidades-e-estados/", domain: "ibge.gov.br",
    types: ["place"], detail: "Contexto territorial e indicadores municipais."},
  {name: "MapBiomas", url: "https://plataforma.brasil.mapbiomas.org/", domain: "mapbiomas.org",
    types: ["place"], detail: "Séries de cobertura e uso da terra."},
];

function element(tag, text, className) {
  const result = document.createElement(tag);
  if (text !== undefined) result.textContent = text;
  if (className) result.className = className;
  return result;
}

async function request(path, payload, type = "json") {
  const options = payload ? {
    method: "POST",
    headers: {"Content-Type": "application/json", "X-OSINT-Session": session},
    body: JSON.stringify(payload),
  } : {};
  const response = await fetch(path, options);
  if (!response.ok) {
    const failure = await response.json();
    throw new Error(failure.error || "Falha na requisição.");
  }
  return response[type]();
}

function problem(error) {
  byId("error").textContent = error.message;
  byId("error").hidden = false;
}

function submit(form, callback, reset = true) {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = form.querySelector("button[type=submit], button:not([type])");
    button.disabled = true;
    byId("error").hidden = true;
    try {
      await callback(Object.fromEntries(new FormData(form)));
      if (reset) form.reset();
    } catch (error) {
      problem(error);
    } finally {
      button.disabled = false;
    }
  });
}

function renderCases() {
  byId("cases").replaceChildren(...history.map((entry) => {
    const button = element("button", entry.target);
    button.setAttribute("aria-current", String(entry.id === current));
    button.onclick = () => openCase(entry.id);
    return button;
  }));
}

async function loadCases() {
  const data = await request("/api/cases");
  session = data.session;
  history = data.cases;
  byId("sources").textContent = data.sources.join(" · ");
  renderCases();
}

async function openCase(caseId) {
  if (caseWatch) caseWatch.stop();
  const watch = {stop() {}};
  caseWatch = watch;
  current = caseId;
  selected = null;
  snapshot = null;
  focusedCase = null;
  byId("workspace").hidden = true;
  manualParent = null;
  byId("error").hidden = true;
  renderCases();
  location.hash = String(caseId);
  const path = "/api/cases/" + caseId;
  byId("connection").textContent = "Conectando";
  try {
    const data = await request(path);
    if (caseWatch !== watch) return;
    update(data);
    watchCase(path, watch);
  } catch (error) {
    if (caseWatch === watch) problem(error);
  }
}

function watchCase(path, watch) {
  const isCurrent = () => caseWatch === watch;
  const connection = byId("connection");
  let events;
  try {
    if (typeof EventSource === "function") events = new EventSource(path + "/stream");
  } catch {
    // Some embedded browsers expose EventSource but cannot open it.
  }

  if (typeof events?.close === "function") {
    watch.stop = () => {
      events.onopen = events.onmessage = events.onerror = null;
      events.close();
    };
    events.onopen = () => { if (isCurrent()) connection.textContent = "Conectado"; };
    events.onmessage = (event) => { if (isCurrent()) update(JSON.parse(event.data)); };
    events.onerror = () => {
      if (!isCurrent()) return;
      connection.textContent = "Reconectando";
      if (events.readyState === 2) {
        watch.stop();
        pollCase(path, watch);
      }
    };
    return;
  }
  pollCase(path, watch);
}

function pollCase(path, watch) {
  const connection = byId("connection");
  let timer;
  watch.stop = () => clearTimeout(timer);
  connection.textContent = "Atualizando";

  async function refresh() {
    if (caseWatch !== watch) return;
    try {
      const data = await request(path);
      if (caseWatch !== watch) return;
      update(data);
      connection.textContent = "Atualizando";
    } catch {
      if (caseWatch === watch) connection.textContent = "Reconectando";
    }
    if (caseWatch === watch) timer = setTimeout(refresh, 1000);
  }

  timer = setTimeout(refresh, 1000);
}

function pendingLead(result) {
  return Boolean(result.is_lead && !result.verified_at && !result.rejected_at);
}

function resultState(result) {
  if (result.rejected_at) return "Invalidada";
  if (result.verified_at) return "Confirmada";
  return pendingLead(result) ? "Pista a conferir" : "Evidência a conferir";
}

function isQsa(result) {
  return result.source === "Minha Receita" && result.title.startsWith("QSA · ");
}

function partnerNames(result) {
  return result.excerpt.split(" | ").map((entry) => entry.split(" · ", 1)[0].trim()).filter(Boolean);
}

function resultLabel(result) {
  return isQsa(result) ? partnerNames(result).join(", ") || result.title : result.title;
}

async function decideEvidence(result, confirmed) {
  const caseId = current;
  const path = "/api/cases/" + caseId;
  try {
    byId("error").hidden = true;
    await request(path + (confirmed ? "/verify" : "/reject"), {result_id: result.id});
    const data = await request(path);
    if (current !== caseId) return;
    update(data);
    if (selected === result.id) {
      const updated = snapshot.results.find((item) => item.id === result.id);
      if (updated) selectResult(updated, "detail");
    }
  } catch (error) {
    if (current === caseId) problem(error);
  }
}

function renderGraph(data) {
  const graph = byId("graph");
  const focusKey = graph.contains(document.activeElement) ? document.activeElement.dataset.focus : null;
  const {scrollTop, scrollLeft} = graph;
  const branches = new Map();
  const results = new Map();
  for (const search of data.searches) {
    if (!branches.has(search.parent_id)) branches.set(search.parent_id, []);
    branches.get(search.parent_id).push(search);
  }
  for (const result of data.results) {
    if (!results.has(result.search_id)) results.set(result.search_id, []);
    results.get(result.search_id).push(result);
  }

  function row(card, children) {
    const item = element("li", undefined, "map-row");
    item.append(card);
    if (children.length) {
      const list = element("ul", undefined, "map-children");
      list.append(...children);
      item.append(list);
    }
    return item;
  }

  function searchNode(search) {
    const card = element("div", undefined, "map-card search-card");
    const status = states[search.status];
    card.append(element("small", "Busca · " + status),
      element("strong", search.query));
    if (search.status !== "manual" && !search.identity_scoped) {
      card.append(element("small", "Alvo sem verificação"));
    }
    return row(card, (results.get(search.id) || []).map(evidenceNode));
  }

  function evidenceNode(result) {
    const state = result.rejected_at ? "rejected" : result.verified_at ? "verified" : pendingLead(result) ? "lead" : "evidence";
    const card = element("div", undefined, "map-card result-card " + state);
    card.dataset.result = result.id;
    const open = element("button", undefined, "map-result-title");
    open.type = "button";
    open.dataset.focus = "open-" + result.id;
    open.setAttribute("aria-pressed", String(result.id === selected));
    open.append(element("small", resultState(result)), element("strong", resultLabel(result)),
      element("small", isQsa(result) ? "Quadro societário · " + result.source : result.source));
    open.onclick = () => selectResult(result, "detail");
    card.append(open);
    if (data.case.reference) {
      const actions = element("div", undefined, "map-actions");
      if (!result.rejected_at) {
        const pivot = element("button", "Investigar a partir daqui", "map-pivot");
        pivot.type = "button";
        pivot.dataset.focus = "pivot-" + result.id;
        pivot.onclick = () => selectResult(result, "pivot");
        actions.append(pivot);
      }
      card.append(actions);
    }
    return row(card, (branches.get(result.id) || []).map(searchNode));
  }

  const target = element("div", undefined, "map-card target-card");
  target.append(element("small", "Alvo"), element("strong", data.case.target));
  const map = element("ul", undefined, "map-root");
  map.append(row(target, (branches.get(null) || []).map(searchNode)));
  graph.replaceChildren(map);
  graph.scrollTop = scrollTop;
  graph.scrollLeft = scrollLeft;
  if (focusKey) graph.querySelector('[data-focus="' + focusKey + '"]')?.focus({preventScroll: true});
}

function selectResult(result, action) {
  selected = result.id;
  const graph = byId("graph");
  for (const button of graph.querySelectorAll(".map-result-title")) {
    button.setAttribute("aria-pressed", String(button.dataset.focus === "open-" + selected));
  }
  renderInspector(result, action);
  const field = action === "pivot" ? "pivot-query" : "selected-title";
  byId(field)?.focus();
}

function renderInspector(result, action = "detail") {
  const inspector = byId("inspector");
  inspector.replaceChildren();
  if (!result) {
    inspector.append(element("p", "Selecione um resultado para conferir, confirmar ou invalidar. A busca pode continuar a partir dele.", "muted"));
    return;
  }
  const title = element("h3", resultLabel(result));
  title.id = "selected-title";
  title.tabIndex = -1;
  inspector.append(element("span", resultState(result), "result-status"), title,
    element("p", "E-" + result.id + " · " + result.source + " · " + date(result.collected_at), "muted"),
    element("p", result.excerpt || "Sem trecho disponível."));
  if (pendingLead(result)) {
    inspector.append(element("p", "Confira se a fonte se refere ao alvo antes de validar esta pista.", "muted"));
  }
  const dispositionAt = result.rejected_at || result.verified_at;
  if (dispositionAt) {
    inspector.append(element("p", resultState(result) + " em " + date(dispositionAt), "muted"));
    if (result.verification_note) inspector.append(element("p", result.verification_note));
  }
  if (result.published_at) {
    inspector.append(element("p", "Publicação em " + result.published_at.split("-").reverse().join("/"), "muted"));
  }
  if (result.url) {
    const url = new URL(result.url);
    if (["http:", "https:"].includes(url.protocol)) {
      const link = element("a", "Abrir fonte original");
      link.href = url.href;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      inspector.append(link);
    }
  }
  const form = element("form");
  const label = element("label", "Consulta para seguir E-" + result.id);
  const query = element("input");
  query.id = "pivot-query";
  query.name = "query";
  query.required = true;
  query.maxLength = 200;
  const registryCard = /^(?:CNPJ |(?:QSA|Endereço cadastral) · )([A-Z0-9]{12}[0-9]{2})(?:$| · )/;
  const derived = (isQsa(result) ? partnerNames(result)[0] : registryCard.exec(result.title)?.[1]) || result.title;
  query.value = derived.slice(0, 200);
  label.append(query);
  form.append(label, element("p", "Os resultados serão ligados a esta evidência no mesmo caso.", "muted"),
    element("button", "Buscar a partir desta evidência", "primary"));
  const pivotStatus = element("p", "", "muted");
  pivotStatus.setAttribute("role", "status");
  form.append(pivotStatus);
  submit(form, async (fields) => {
    const caseId = current;
    const path = "/api/cases/" + caseId;
    await request(path + "/searches", {query: fields.query, parent_id: result.id});
    const data = await request(path);
    if (current === caseId) {
      update(data);
      pivotStatus.textContent = "Busca vinculada a E-" + result.id + ". Acompanhe o novo ramo no grafo.";
    }
  }, false);
  const advanced = element("button", "Montar busca avançada a partir daqui");
  advanced.type = "button";
  advanced.onclick = () => {
    manualParent = result.id;
    byId("manual-parent").replaceChildren(element("span", "Pivô em E-" + result.id + " · " + result.title));
    const clear = element("button", "Remover vínculo");
    clear.type = "button";
    clear.onclick = () => {
      manualParent = null;
      byId("manual-parent").replaceChildren();
    };
    byId("manual-parent").append(" ", clear);
    const search = byId("manual-search");
    search.elements.term.value = derived.slice(0, 160);
    makeQuery();
    search.elements.term.focus();
  };
  if (snapshot.case.reference) {
    const actions = element("div", undefined, "inspector-actions");
    if (!result.rejected_at && action !== "pivot") {
      const pivot = element("button", "Investigar a partir daqui", "primary");
      pivot.type = "button";
      pivot.onclick = () => selectResult(result, "pivot");
      actions.append(pivot);
    }
    const decision = element("button", result.verified_at ? "Invalidar evidência" : "Confirmar evidência");
    decision.type = "button";
    decision.onclick = () => decideEvidence(result, !result.verified_at);
    actions.append(decision);
    if (!result.verified_at && !result.rejected_at) {
      const reject = element("button", "Invalidar");
      reject.type = "button";
      reject.onclick = () => decideEvidence(result, false);
      actions.append(reject);
    }
    inspector.append(actions);
    if (action === "pivot" && !result.rejected_at) inspector.append(form, advanced);
  }
}

function date(value) {
  return new Intl.DateTimeFormat("pt-BR", {dateStyle: "short", timeStyle: "medium"}).format(new Date(value));
}

function renderReview(data) {
  const picker = byId("evidence-list");
  const evidence = data.results.filter((row) => !row.rejected_at && !pendingLead(row));
  const available = new Set(evidence.map((row) => "e-" + row.id));
  for (const select of picker.querySelectorAll("select")) {
    if (!available.has(select.name)) select.parentElement.remove();
  }
  for (const row of evidence) {
    if (picker.querySelector('[name="e-' + row.id + '"]')) continue;
    const label = element("label", "E-" + row.id + " · " + row.title, "evidence-row");
    const select = element("select");
    select.name = "e-" + row.id;
    select.append(new Option("Sem vínculo", ""));
    for (const [value, title] of Object.entries(stances)) select.append(new Option(title, value));
    label.append(select);
    picker.append(label);
  }
  byId("review").querySelector("button").disabled = !evidence.length;
  byId("reviews").replaceChildren(...data.reviews.map((review) => {
    const article = element("article");
    article.append(element("h3", review.claim), element("p", review.rationale),
      element("p", review.evidence.map((item) => stances[item.stance] + " E-" + item.id).join(" · "), "muted"));
    return article;
  }));
}

function update(data) {
  if (snapshot) {
    const same = data.events.length === snapshot.events.length && data.reviews.length === snapshot.reviews.length;
    const stale = data.events.length < snapshot.events.length || data.reviews.length < snapshot.reviews.length;
    if (same || stale) return;
  }
  const previousSelection = snapshot?.results.find((item) => item.id === selected);
  snapshot = data;
  byId("workspace").hidden = false;
  byId("empty").hidden = true;
  byId("title").textContent = data.case.target;
  byId("goal").textContent = data.case.goal;
  const identity = byId("case-identity");
  if (data.case.reference) {
    const reference = data.case.target_type === "organization" ? "https://" + data.case.reference : data.case.reference;
    identity.replaceChildren("Referência confirmada no cadastro · ", browserLink(data.case.reference, reference));
  } else {
    identity.textContent = "Caso anterior à confirmação de alvo. Abra um novo caso para iniciar outra coleta.";
  }
  byId("manual-search").hidden = !data.case.reference;
  const rerun = byId("rerun");
  rerun.hidden = !data.case.reference;
  rerun.disabled = data.searches.some((search) => search.parent_id === null &&
    ["queued", "running"].includes(search.status));
  const active = data.searches.filter((search) => ["queued", "running"].includes(search.status)).length;
  const confirmed = data.results.filter((item) => item.verified_at && !item.rejected_at).length;
  const expand = byId("expand");
  expand.hidden = !data.case.reference;
  expand.disabled = !confirmed || active > 0;
  byId("expansion-note").textContent = !confirmed ? "Confirme evidências para ampliar a coleta a partir delas." :
    confirmed + " evidência(s) confirmada(s). A próxima rodada segue os vínculos ainda não explorados.";
  byId("expansion-note").hidden = !data.case.reference;
  byId("metrics").replaceChildren(...[
    data.searches.length + " buscas",
    data.results.filter((item) => !item.rejected_at && !pendingLead(item)).length + " evidências",
    data.results.filter(pendingLead).length + " pistas",
    confirmed + " confirmadas",
    active + " ativas",
  ].map((text) => element("span", text, "metric")));
  renderGraph(data);
  renderInstitution(data);
  const selection = data.results.find((item) => item.id === selected);
  if (selection && (selection.verified_at !== previousSelection?.verified_at ||
                    selection.rejected_at !== previousSelection?.rejected_at)) renderInspector(selection);
  byId("events").replaceChildren(...data.events.slice(-60).reverse().map((entry) => {
    const item = element("li", entry.message, entry.state);
    item.prepend(element("small", [date(entry.created_at), "Busca " + entry.search_id, entry.source].filter(Boolean).join(" · ")));
    return item;
  }));
  if (focusedCase !== current) {
    focusedCase = current;
    byId("evidence-list").replaceChildren();
    byId("review").reset();
    renderInspector(null);
    byId("manual-search").reset();
    byId("manual-search").elements.term.value = data.case.target.slice(0, 160);
    byId("manual-parent").replaceChildren();
    byId("capture").reset();
    byId("capture").elements.search_id.replaceChildren();
    makeQuery();
    renderDiscovery(data.case);
  }
  renderManual(data.searches);
  renderReview(data);
}

function renderInstitution(data) {
  const panel = byId("institution");
  panel.hidden = data.case.target_type !== "organization";
  if (panel.hidden) return;
  const types = new Set(["CNPJ declarado", "CNPJ a conferir", "Minha Receita", "CVM",
    "Domínio alternativo declarado", "Domínio canônico declarado", "Tecnologia declarada",
    "Site institucional", "Contato institucional", "WhatsApp publicado",
    "Canal institucional publicado", "Documento público publicado"]);
  const items = new Map();
  for (const result of data.results) {
    if (types.has(result.source)) items.set(result.source + "|" + result.url, result);
  }
  const content = byId("institution-results");
  content.replaceChildren();
  if (!items.size) {
    content.append(element("p", "Nenhum dado cadastral ou técnico publicado nas fontes consultadas.", "muted"));
    return;
  }
  for (const result of items.values()) {
    const button = element("button", undefined, "institution-result");
    button.type = "button";
    button.append(element("strong", resultLabel(result)),
      element("small", (isQsa(result) ? "Quadro societário" : result.source) + " · " + resultState(result)));
    button.onclick = () => {
      byId("graph").querySelector('[data-result="' + result.id + '"]')?.scrollIntoView({block: "nearest", inline: "nearest"});
      selectResult(result, "detail");
    };
    content.append(button);
  }
}

function renderDiscovery(target) {
  const container = byId("discovery-options");
  container.replaceChildren();
  if (!target.reference) return;
  const name = '"' + target.target.replaceAll('"', "") + '"';
  const profile = target.target_type === "individual";
  const queries = profile ? [
    ["Perfis públicos", name + " (site:instagram.com OR site:github.com OR site:youtube.com OR site:x.com)"],
    ["Vínculos profissionais", name + ' ("empresa" OR "equipe" OR "fundador" OR "professor")'],
    ["Citações públicas", name + ' ("palestrante" OR "entrevista" OR "publicação" OR "autor")'],
  ] : [
    ["CNPJ e razão social", name + ' ("CNPJ" OR "razão social" OR "nome fantasia")'],
    ["Cadastro por domínio", '"' + target.reference + '" ("CNPJ" OR "razão social")'],
    ["Diretórios e QSA", name + " (site:casadosdados.com.br OR site:cnpj.biz OR site:econodata.com.br OR site:transparencia.cc)"],
    ["Documentos societários", name + ' filetype:pdf ("quadro societário" OR "contrato social" OR "ata de assembleia")'],
    ["Perfis institucionais", name + " (site:linkedin.com/company OR site:instagram.com OR site:youtube.com)"],
    ["Publicações e atos", name + ' (site:in.gov.br OR site:queridodiario.ok.org.br OR site:dados.cvm.gov.br)'],
    ["Processos públicos", name + ' (site:jus.br OR site:cade.gov.br)'],
    ["Menções independentes", name + ' ("entrevista" OR "evento" OR "publicação")'],
  ];
  for (const [label, query] of queries) {
    const button = element("button", label);
    button.type = "button";
    button.onclick = () => {
      const form = byId("manual-search");
      form.elements.query.value = query.slice(0, 400);
      form.elements.query.focus();
    };
    container.append(button);
  }
}

let diagnosticTimer;

async function showDiagnosticResults(start = false) {
  clearTimeout(diagnosticTimer);
  const panel = byId("diagnostics");
  const button = byId("run-diagnostics");
  button.disabled = true;
  try {
    const data = await request("/api/diagnostics", start ? {} : undefined);
    const pending = data.checks.some((check) => check.status === "running");
    const status = {running: "Consultando", ok: "Respondeu", empty: "Sem resultados", error: "Indisponível"};
    byId("diagnostic-time").textContent = !data.started_at ? "Nenhum diagnóstico executado." :
      (pending ? "Diagnóstico em andamento" : "Diagnóstico concluído") + " · " + date(data.started_at);
    byId("diagnostic-results").replaceChildren(...data.checks.map((check) => {
      const item = element("li");
      item.append(element("strong", check.source + " · " + status[check.status]),
        element("p", [check.query, check.detail].filter(Boolean).join(" · "), "muted"));
      return item;
    }));
    button.disabled = pending;
    if (pending && !panel.hidden) diagnosticTimer = setTimeout(showDiagnosticResults, 700);
  } catch (error) {
    button.disabled = false;
    problem(error);
  }
}

function browserLink(label, url) {
  const link = element("a", label);
  link.href = url;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  return link;
}

function makeQuery() {
  const form = byId("manual-search");
  const fields = Object.fromEntries(new FormData(form));
  const quote = (value) => '"' + value.trim().replaceAll('"', "") + '"';
  const cleanDomain = fields.domain.trim();
  if (cleanDomain && !/^(?:[a-z0-9-]+\.)+[a-z0-9-]+$/i.test(cleanDomain)) {
    problem(new Error("Informe apenas o domínio, como gov.br."));
    return;
  }
  if (fields.after && fields.before && fields.after > fields.before) {
    problem(new Error("O início do período deve vir antes do fim."));
    return;
  }
  const term = fields.term.trim();
  const alias = fields.alias.trim();
  form.elements.query.value = [
    term && (alias ? "(" + quote(term) + " OR " + quote(alias) + ")" : quote(term)),
    cleanDomain && "site:" + cleanDomain,
    fields.extension && "filetype:" + fields.extension,
    fields.after && "after:" + fields.after,
    fields.before && "before:" + fields.before,
  ].filter(Boolean).join(" ");
  byId("error").hidden = true;
}

function renderCatalog() {
  const filter = byId("source-type").value;
  byId("catalog").replaceChildren(...catalog.filter((source) => filter === "all" || source.types.includes(filter))
    .map((source) => {
      const card = element("article");
      card.append(browserLink(source.name, source.url), element("p", source.detail, "muted"));
      if (source.domain) {
        const use = element("button", "Usar domínio na busca");
        use.onclick = () => {
          const form = byId("manual-search");
          form.elements.domain.value = source.domain;
          makeQuery();
          form.elements.query.focus();
        };
        card.append(use);
      }
      return card;
    }));
}

function renderManual(searches) {
  const manual = searches.filter((entry) => entry.status === "manual");
  const picker = byId("capture").elements.search_id;
  const saved = picker.value;
  if (picker.options.length !== manual.length) {
    picker.replaceChildren(...manual.map((entry) => new Option(entry.query, String(entry.id))));
    if (manual.some((entry) => String(entry.id) === saved)) picker.value = saved;
    byId("manual-list").replaceChildren(...manual.slice().reverse().map((entry) => {
      const card = element("article");
      const url = new URL("https://www.google.com/search");
      url.searchParams.set("q", entry.query);
      card.append(element("p", entry.query), browserLink("Abrir busca no navegador", url.href));
      return card;
    }));
  }
  if (!manual.length) byId("manual-list").replaceChildren();
  byId("capture-panel").hidden = manual.length === 0;
}

function download(content, filename, type) {
  const url = URL.createObjectURL(new Blob([content], {type}));
  const anchor = element("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

const caseForm = byId("new-case");

function previewReference() {
  const input = caseForm.elements.reference;
  const organization = caseForm.elements.target_type.value === "organization";
  byId("reference-label").textContent = organization ? "Domínio oficial" : "URL de perfil, currículo ou página pública";
  input.placeholder = organization ? "exemplo.com.br" : "https://exemplo.org/perfil";
  const preview = byId("reference-preview");
  preview.hidden = true;
  const value = input.value.trim();
  if (!value || (organization && !/^(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]+$/i.test(value))) return;
  try {
    const url = new URL(organization || !value.includes("://") ? "https://" + value : value);
    if (["http:", "https:"].includes(url.protocol) && !url.username && !url.password) {
      preview.href = url.href;
      preview.hidden = false;
    }
  } catch {
    // While editing, an incomplete URL simply has no preview.
  }
}

for (const field of ["target", "reference", "target_type"]) {
  caseForm.elements[field].addEventListener("input", () => {
    caseForm.elements.confirmed.checked = false;
    if (field === "target_type") caseForm.elements.reference.value = "";
    previewReference();
  });
}
caseForm.addEventListener("reset", () => queueMicrotask(previewReference));
submit(caseForm, async (fields) => {
  const created = await request("/api/cases", {...fields, confirmed: fields.confirmed === "on"});
  await loadCases();
  await openCase(created.case_id);
});
submit(byId("review"), (fields) => {
  const evidence = Object.entries(fields).filter(([key, value]) => key.startsWith("e-") && value)
    .map(([key, stance]) => ({id: Number(key.slice(2)), stance}));
  return request("/api/cases/" + current + "/reviews", {claim: fields.claim, rationale: fields.rationale, evidence});
});
byId("compose-query").onclick = makeQuery;
byId("graph-home").onclick = () => byId("graph").scrollTo({left: 0, top: 0, behavior: "smooth"});
byId("show-diagnostics").onclick = () => {
  byId("diagnostics").hidden = false;
  byId("diagnostics").scrollIntoView({block: "nearest"});
  showDiagnosticResults();
};
byId("close-diagnostics").onclick = () => {
  clearTimeout(diagnosticTimer);
  byId("diagnostics").hidden = true;
  byId("show-diagnostics").focus();
};
byId("run-diagnostics").onclick = () => showDiagnosticResults(true);
byId("expand").onclick = async () => {
  const button = byId("expand");
  const caseId = current;
  button.disabled = true;
  byId("error").hidden = true;
  try {
    const queued = await request(`/api/cases/${caseId}/expand`, {});
    const data = await request(`/api/cases/${caseId}`);
    if (current !== caseId) return;
    update(data);
    if (!queued.search_ids.length) {
      byId("expansion-note").textContent = "As evidências confirmadas já foram exploradas. Confirme novos achados para continuar.";
      button.disabled = false;
    }
  } catch (error) {
    if (current === caseId) {
      problem(error);
      button.disabled = false;
    }
  }
};
byId("rerun").onclick = async () => {
  const button = byId("rerun");
  const caseId = current;
  button.disabled = true;
  byId("error").hidden = true;
  try {
    await request(`/api/cases/${caseId}/rerun`, {});
    const data = await request(`/api/cases/${caseId}`);
    if (current === caseId) update(data);
  } catch (error) {
    if (current === caseId) {
      button.disabled = false;
      problem(error);
    }
  }
};
byId("source-type").onchange = renderCatalog;
renderCatalog();
submit(byId("manual-search"), async (fields) => {
  const caseId = current;
  const created = await request("/api/cases/" + caseId + "/manual", {
    query: fields.query, parent_id: manualParent,
  });
  if (current !== caseId) return;
  const data = await request("/api/cases/" + caseId);
  if (current !== caseId) return;
  update(data);
  byId("capture").elements.search_id.value = String(created.search_id);
  const path = byId("manual-list").querySelector("a");
  if (path) path.focus();
}, false);
submit(byId("capture"), async (fields) => {
  const caseId = current;
  const saved = await request("/api/cases/" + caseId + "/capture", {...fields, search_id: Number(fields.search_id)});
  if (current !== caseId) return;
  const data = await request("/api/cases/" + caseId);
  if (current !== caseId) return;
  update(data);
  const node = byId("graph").querySelector('[data-id="' + saved.result_id + '"]');
  if (node) node.click();
  const form = byId("capture");
  for (const field of ["title", "url", "excerpt", "published_at"]) form.elements[field].value = "";
}, false);
byId("export-json").onclick = () => {
  if (snapshot) download(JSON.stringify(snapshot, null, 2), "caso-" + current + ".json", "application/json");
};
byId("export-md").onclick = async () => {
  const caseId = current;
  try {
    const markdown = await request("/api/cases/" + caseId + "/report.md", null, "text");
    download(markdown, "caso-" + caseId + ".md", "text/markdown");
  } catch (error) {
    problem(error);
  }
};
loadCases().then(() => {
  byId("connection").textContent = "Local";
  const caseId = Number(location.hash.slice(1));
  if (history.some((entry) => entry.id === caseId)) openCase(caseId);
}).catch(problem);
