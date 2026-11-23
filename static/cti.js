"use strict";

const $ = (id) => document.getElementById(id);
let session, selectedCase, snapshot, selectedNode, poll;

// Stored CTI identifiers remain stable across app versions.
const englishLabels = new Map(Object.entries({
  "Termo": "Search term",
  "Domínio": "Domain",
  "Grupo": "Group",
  "Campanha": "Campaign",
  "Ferramenta": "Tool",
  "Técnica": "Technique",
  "Evento": "Event",
  "Relatório": "Report",
  "Detecção": "Detection",
  "Organização": "Organization",
  "Serviço": "Service",
  "Menção": "Mention",
  "Resultado web": "Web result",
  "Referência": "Reference",
  "Síntese": "Assessment",
  "Parecer do caso": "Case assessment",
  "MISP local": "Local MISP",
  "Histórico local": "Local history",
  "GitHub público": "Public GitHub",
  "Relatórios históricos na web": "Historical web reports",
  "Menções públicas": "Public mentions",
  "Busca web": "Web search",
  "Busca web pública": "Public web search",
  "Verificação web": "Web verification",
  "Expansão automática": "Automatic expansion",
  "Revisão": "Review",
  "Coleta": "Collection",
  "Registro manual": "Manual entry",
  "Projeto ou software": "Project or software",
  "Atividade de ameaça": "Threat activity",
  "Identidade ou organização": "Identity or organization",
  "Contexto em aberto": "Unclassified context",
  "Data da fonte": "Source date",
  "Atividade observada": "Observed activity",
  "Rodada de coleta": "Collection run",
  "Publicação": "Publication",
  "Captura": "Capture",
  "Publicado": "Published",
  "A conferir": "Needs review",
  "Contexto indireto": "Indirect context",
  "Reportado pela fonte": "Reported by source",
  "Correspondência textual": "Text match",
  "Atribuição da fonte": "Source attribution",
  "Indexada · a conferir": "Indexed · needs review",
  "Menção textual verificada": "Verified mention",
  "Coocorrência · a conferir": "Co-occurrence · needs review",
  "Síntese automática · a conferir": "Automated assessment · needs review",
  "Documentada pela fonte": "Documented by source",
  "Registrado no evento": "Recorded in event",
  "Coocorrência no evento": "Co-occurrence in event",
  "Indicador listado": "Listed indicator",
  "Detecções publicadas": "Published detections",
  "Identificado no catálogo": "Identified in catalog",
  "Referência citada": "Cited reference",
  "Relacionado": "Related",
  "Usa": "Uses",
  "Usado por": "Used by",
  "Atribuído a": "Attributed to",
  "Atribuição de": "Attribution of",
  "Classificações da fonte": "Source classifications",
  "Organização registrada pela fonte": "Organization reported by source",
  "Serviço observado": "Observed service",
  "Associação reportada": "Reported association",
  "IOC publicado no relatório": "IOC published in report",
  "Contexto publicado no relatório": "Context published in report",
  "Menção indexada": "Indexed mention",
  "Repositório público indexado": "Indexed public repository",
  "Captura indexada": "Indexed capture",
  "Menção verificada na página": "Mention verified on page",
  "Citado no contexto do termo": "Mentioned in the context of the term",
  "Síntese dos achados": "Summary of findings",
  "Menção em fórum": "Forum mention",
  "Handle publicado do grupo": "Published group handle",
  "Atribuição documentada": "Documented attribution"
}));
const label = (value) => englishLabels.get(value) ?? value;
const entityLabel = (value, kind) => kind === "Síntese" ? label(value) : value;

function eventMessage(message) {
  return message
    .replace(/^Consulta iniciada\.$/, "Query started.")
    .replace(/^(\d+) relação\(ões\) nova\(s\)/, "$1 new relationship(s)")
    .replace(/ · (\d+) encontradas\./, " · $1 found.")
    .replace(/^([0-9]+) relação\(ões\) registradas\.$/, "$1 relationship(s) recorded.")
    .replace(/ Fonte indisponível: /, " Source unavailable: ");
}

function el(tag, value, className) {
  const node = document.createElement(tag);
  if (value !== undefined) node.textContent = value;
  if (className) node.className = className;
  return node;
}

async function request(path, payload) {
  const response = await fetch(path, payload ? {
    method: "POST",
    headers: {"Content-Type": "application/json", "X-OSINT-Session": session},
    body: JSON.stringify(payload),
  } : {});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Could not reach the service.");
  return data;
}

function showError(error) {
  $("cti-error").textContent = error.message;
  $("cti-error").hidden = false;
}

function onSubmit(form, action) {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = form.querySelector("button");
    button.disabled = true;
    $("cti-error").hidden = true;
    try {
      await action(Object.fromEntries(new FormData(form)));
      form.reset();
    } catch (error) {
      showError(error);
    } finally {
      button.disabled = false;
    }
  });
}

async function home() {
  const data = await request("/api/cti");
  session = data.session;
  $("cti-sources").textContent = data.sources.map(label).join(" · ");
  $("cti-imported").textContent = data.imported + " event(s) in the local index.";
  $("cti-cases").replaceChildren(...data.cases.map((item) => {
    const button = el("button", item.title);
    button.setAttribute("aria-current", String(item.id === selectedCase));
    button.onclick = () => openCase(item.id);
    return button;
  }));
}

const graph = $("cti-graph");
const scene = $("cti-scene");
const camera = {x: 0, y: 0, scale: 1, width: 1, height: 1};
let nodes = new Map();
let drag;
const svgNS = "http://www.w3.org/2000/svg";

function moveCamera(x, y, scale) {
  Object.assign(camera, {x, y, scale});
  scene.style.transform = `translate(${x}px, ${y}px) scale(${scale})`;
  $("cti-zoom-level").value = Math.round(scale * 100) + "%";
}

function zoom(factor, x = graph.clientWidth / 2, y = graph.clientHeight / 2) {
  const scale = Math.max(.05, Math.min(3, camera.scale * factor));
  const ratio = scale / camera.scale;
  moveCamera(x - (x - camera.x) * ratio, y - (y - camera.y) * ratio, scale);
}

function fitGraph() {
  const scale = Math.min(1, (graph.clientWidth - 32) / camera.width, (graph.clientHeight - 32) / camera.height);
  moveCamera((graph.clientWidth - camera.width * scale) / 2,
    (graph.clientHeight - camera.height * scale) / 2, scale);
}

$("cti-zoom-in").onclick = () => zoom(1.25);
$("cti-zoom-out").onclick = () => zoom(.8);
$("cti-fit").onclick = fitGraph;
graph.addEventListener("wheel", (event) => {
  event.preventDefault();
  const rect = graph.getBoundingClientRect();
  zoom(Math.exp(-Math.max(-180, Math.min(180, event.deltaY)) * .002),
    event.clientX - rect.left, event.clientY - rect.top);
}, {passive: false});
graph.addEventListener("pointerdown", (event) => {
  if (event.button !== 0 || event.target.closest("button")) return;
  drag = {id: event.pointerId, x: event.clientX - camera.x, y: event.clientY - camera.y};
  graph.setPointerCapture(event.pointerId);
  graph.classList.add("dragging");
});
graph.addEventListener("pointermove", (event) => {
  if (drag?.id === event.pointerId) moveCamera(event.clientX - drag.x, event.clientY - drag.y, camera.scale);
});
graph.addEventListener("lostpointercapture", () => {
  drag = null;
  graph.classList.remove("dragging");
});
graph.addEventListener("keydown", (event) => {
  const offsets = {ArrowLeft: [48, 0], ArrowRight: [-48, 0], ArrowUp: [0, 48], ArrowDown: [0, -48]};
  if (offsets[event.key]) {
    const [dx, dy] = offsets[event.key];
    moveCamera(camera.x + dx, camera.y + dy, camera.scale);
  } else if (event.key === "+" || event.key === "=") zoom(1.25);
  else if (event.key === "-") zoom(.8);
  else if (event.key === "Escape") closeInspector();
  else return;
  event.preventDefault();
});

function selectNode(node) {
  selectedNode = node?.key;
  for (const item of nodes.values()) item.button.setAttribute("aria-pressed", String(item === node));
  inspect(node);
  if (node) {
    const x = node.x * camera.scale + camera.x;
    const y = node.y * camera.scale + camera.y;
    if (x < 0 || x > graph.clientWidth || y < 0 || y > graph.clientHeight) {
      moveCamera(graph.clientWidth / 2 - node.x * camera.scale,
        graph.clientHeight / 2 - node.y * camera.scale, camera.scale);
    }
  }
}

function closeInspector() {
  const button = nodes.get(selectedNode)?.button;
  selectNode(null);
  button?.focus({preventScroll: true});
}

$("cti-close").onclick = closeInspector;

function viewGraph(data, resetCamera) {
  const previous = nodes;
  const focused = graph.contains(document.activeElement) ? document.activeElement.dataset.node : null;
  nodes = new Map();
  const getNode = (kind, value, id = "") => {
    const key = JSON.stringify(id ? [kind, id, true] : [kind, value, false]);
    if (!nodes.has(key)) nodes.set(key, {key, kind, value, id, edges: [], neighbors: new Set()});
    return nodes.get(key);
  };
  const roots = data.seeds.map((seed) => getNode(seed.kind, seed.value));
  for (const root of roots) root.seed = true;
  const links = new Map();
  for (const relation of data.relations) {
    const from = getNode(relation.origin_kind, relation.origin, relation.origin_id);
    const to = getNode(relation.kind, relation.target, relation.target_id);
    from.edges.push({relation, other: to, outgoing: true});
    if (to !== from) to.edges.push({relation, other: from, outgoing: false});
    from.neighbors.add(to);
    to.neighbors.add(from);
    const key = JSON.stringify([from.key, to.key].sort());
    if (!links.has(key)) links.set(key, {from, to});
  }
  const columns = [];
  const place = (node, depth) => {
    if (node.depth !== undefined) return false;
    node.depth = depth;
    (columns[depth] ||= []).push(node);
    return true;
  };
  let frontier = roots.filter((root) => place(root, 0));
  for (const node of nodes.values()) {
    if (!frontier.length && place(node, 0)) frontier = [node];
    while (frontier.length) {
      frontier = frontier.flatMap((current) => [...current.neighbors]
        .filter((neighbor) => place(neighbor, current.depth + 1)));
    }
  }
  const rowCount = Math.max(1, ...columns.map((column) => column.length));
  camera.width = Math.max(1, columns.length) * 256;
  camera.height = rowCount * 90;
  columns.forEach((column, depth) => column.forEach((node, row) => {
    node.x = depth * 256 + 128;
    node.y = (row + (rowCount - column.length) / 2) * 90 + 45;
  }));
  const edges = document.createElementNS(svgNS, "svg");
  edges.setAttribute("width", camera.width);
  edges.setAttribute("height", camera.height);
  edges.setAttribute("aria-hidden", "true");
  for (const {from, to} of links.values()) {
    const path = document.createElementNS(svgNS, "path");
    const midpoint = (from.x + to.x) / 2;
    const d = from === to ? `M ${from.x} ${from.y - 29} c 45 -32 65 12 35 24` :
      from.x === to.x ? `M ${from.x} ${from.y} C ${from.x + 124} ${from.y}, ${to.x + 124} ${to.y}, ${to.x} ${to.y}` :
        `M ${from.x} ${from.y} C ${midpoint} ${from.y}, ${midpoint} ${to.y}, ${to.x} ${to.y}`;
    path.setAttribute("d", d);
    edges.append(path);
  }
  const buttons = [...nodes.values()].map((node) => {
    const button = el("button", undefined, "graph-node");
    node.button = button;
    button.dataset.node = node.key;
    button.dataset.kind = node.kind;
    button.classList.toggle("graph-seed", Boolean(node.seed));
    button.style.left = node.x + "px";
    button.style.top = node.y + "px";
    button.title = entityLabel(node.value, node.kind);
    button.setAttribute("aria-pressed", String(node.key === selectedNode));
    button.append(el("small", label(node.kind)), el("strong", entityLabel(node.value, node.kind)));
    button.onclick = () => selectNode(node);
    return button;
  });
  scene.replaceChildren(edges, ...buttons);
  if (resetCamera) fitGraph();
  else {
    const anchor = selectedNode || roots[0]?.key;
    const tracked = previous.get(anchor);
    const updated = nodes.get(anchor);
    if (tracked && updated) moveCamera(camera.x + (tracked.x - updated.x) * camera.scale,
      camera.y + (tracked.y - updated.y) * camera.scale, camera.scale);
  }
  if (focused) nodes.get(focused)?.button.focus({preventScroll: true});
}

function inspect(node) {
  const inspector = $("cti-inspector");
  $("cti-detail").hidden = !node;
  inspector.replaceChildren();
  if (!node) return;
  inspector.append(el("small", label(node.kind) + (node.seed ? " · Investigation input" : "")), el("h3", entityLabel(node.value, node.kind)));
  if (node.id) inspector.append(el("p", node.id, "muted"));
  if (!node.edges.length) inspector.append(el("p", "No relationships recorded for this node.", "muted"));
  for (const {relation, other, outgoing} of node.edges) {
    const article = el("article", undefined, "graph-evidence");
    article.id = "cti-evidence-" + relation.id;
    article.tabIndex = -1;
    const decision = {confirmed: "Confirmed", rejected: "Rejected"}[relation.review] || label(relation.confidence);
    const heading = el("h3", label(relation.relationship));
    article.append(el("small", decision, "result-status"), heading,
      el("p", (outgoing ? "→ " : "← ") + entityLabel(other.value, other.kind), "muted"),
      el("p", [label(relation.source), relation.date && (relation.date_kind ? label(relation.date_kind) + " " : "") + relation.date]
        .filter(Boolean).join(" · "), "muted"));
    if (relation.context) article.append(el("p", "Context · " + label(relation.context), "muted"));
    if (relation.model) article.append(el("p", "Model " + relation.model, "muted"));
    if (relation.activity_date) article.append(el("p", "Activity observed on " + relation.activity_date, "muted"));
    if (relation.detail) article.append(el("p", relation.detail));
    if (relation.reference) {
      const link = el("a", "Open source");
      link.href = relation.reference;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      article.append(link);
    }
    if (relation.citations?.length) {
      const references = el("details", undefined, "graph-citations");
      references.append(el("summary", "Assessment sources"));
      for (const citation of relation.citations) {
        const item = el("p");
        const link = el("a", citation.id + " · " + citation.titulo);
        link.href = citation.url;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        item.append(link);
        if (citation.copias_do_mesmo_texto) item.append(el("small", " · Republished text"));
        references.append(item);
      }
      article.append(references);
    }
    const actions = el("div", undefined, "inspector-actions");
    if (other !== node) {
      const follow = el("button", "View related node");
      follow.onclick = () => {
        selectNode(other);
        moveCamera(graph.clientWidth / 2 - other.x * camera.scale,
          graph.clientHeight / 2 - other.y * camera.scale, camera.scale);
        other.button.focus({preventScroll: true});
      };
      actions.append(follow);
    }
    for (const [value, label] of [["confirmed", "Confirm"], ["rejected", "Reject"]]) {
      const button = el("button", label);
      button.disabled = relation.review === value;
      button.onclick = async () => {
        const caseId = selectedCase;
        button.disabled = true;
        try {
          await request("/api/cti/" + caseId + "/review", {result_id: relation.id, review: value});
          if (selectedCase === caseId) await refresh(caseId);
        } catch (error) { button.disabled = false; showError(error); }
      };
      actions.append(button);
    }
    article.append(actions);
    inspector.append(article);
  }
}

function openEvidence(id) {
  const node = [...nodes.values()].find((item) => item.edges.some(({relation}) => relation.id === id));
  if (!node) return;
  selectNode(node);
  const entry = $("cti-evidence-" + id);
  entry?.focus();
}

function evidenceControl(citation) {
  if (citation.evidence_id) {
    const button = el("button", citation.id + " · " + citation.titulo);
    button.type = "button";
    button.onclick = () => openEvidence(citation.evidence_id);
    return button;
  }
  const link = el("a", citation.id + " · " + citation.titulo);
  link.href = citation.url;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  return link;
}

function renderIntelligence(data) {
  const rounds = $("cti-rounds");
  rounds.replaceChildren();
  for (const [index, round] of (data.rounds || []).entries()) {
    const panel = el("details");
    panel.open = index === 0;
    panel.append(el("summary", round.started_at + " · " + round.new_evidence.length + " new evidence item(s)"));
    const outcomes = el("ul");
    for (const item of round.coverage) {
      const status = {running: "Running", error: "Unavailable", done: item.found === 0 ? "No findings" : "Queried"};
      outcomes.append(el("li", label(item.source) + " · " + (status[item.status] || item.status) + " · " + eventMessage(item.message)));
    }
    panel.append(outcomes);
    if (round.assessment_change) {
      const change = round.assessment_change;
      const scores = [change.previous_score, change.score].filter(Number.isInteger);
      const shift = scores.length ? " · confidence " + scores.map((score) => score + "/5").join(" → ") : "";
      panel.append(el("p", (change.changed ? "Assessment changed" : "Assessment recorded") + shift));
    }
    for (const item of round.new_evidence) panel.append(evidenceControl({
      id: label(item.source), titulo: [item.target, label(item.context)].filter(Boolean).join(" · "), evidence_id: item.id,
    }));
    rounds.append(panel);
  }
  if (!rounds.children.length) rounds.append(el("p", "No collection runs recorded."));

  const timeline = $("cti-timeline");
  timeline.replaceChildren();
  for (const event of data.timeline || []) {
    const item = el("p");
    item.append(evidenceControl({id: event.date + " · " + label(event.label), titulo: event.target, evidence_id: event.id}),
      el("small", " · " + label(event.source)));
    timeline.append(item);
  }
  if (!timeline.children.length) timeline.append(el("p", "No dates recorded."));

  const related = $("cti-related");
  related.replaceChildren();
  for (const entry of data.related_cases || []) {
    const item = el("p");
    const link = el("a", entry.title);
    link.href = "#cti-" + entry.case_id;
    link.onclick = async (event) => {
      event.preventDefault();
      await openCase(entry.case_id);
      if (selectedCase === entry.case_id) openEvidence(entry.evidence_id);
    };
    item.append(link, el("span", " · " + [entry.origin + " → " + entry.target, label(entry.source), entry.date]
      .filter(Boolean).join(" · ")));
    related.append(item);
  }
  if (!related.children.length) related.append(el("p", "No related cases found."));
}

function latestConclusion(relations) {
  return [...relations].reverse().find((row) =>
    row.source === "OpenCode" && row.kind === "Síntese" && row.review !== "rejected" && row.detail);
}

function renderConclusion(current, active, assessment) {
  const status = $("cti-conclusion-status");
  status.textContent = current?.stale ? "Assessment out of date. A cited evidence item was rejected." : active
    ? (current ? "Previous assessment · a new run is in progress." : "The assessment will be generated after collection and correlation.")
    : assessment?.status === "error"
      ? (current ? "Previous assessment · the latest assessment is pending." : "Assessment pending. See Live activity.")
      : current ? "" : "No assessment available for this case.";
  status.hidden = !status.textContent;
  $("cti-conclusion-content").hidden = !current;
  if (!current) return;
  $("cti-conclusion-text").textContent = current.detail;
  $("cti-conclusion-model").textContent = current.model ? "Model · " + current.model : "OpenCode";
  const citations = current.citations || [];
  const byId = new Map(citations.map((item) => [item.id, item]));
  const claims = $("cti-claims");
  const hypotheses = $("cti-hypotheses");
  claims.replaceChildren();
  hypotheses.replaceChildren();
  if (current.afirmacoes?.length) claims.append(el("h3", "Claims and evidence"));
  for (const claim of current.afirmacoes || []) {
    const item = el("div", undefined, "cti-analysis-item");
    item.append(el("p", claim.texto));
    for (const id of claim.evidencias) if (byId.has(id)) item.append(evidenceControl(byId.get(id)));
    claims.append(item);
  }
  if (current.hipoteses?.length) hypotheses.append(el("h3", "Hypotheses"));
  for (const hypothesis of current.hipoteses || []) {
    const item = el("div", undefined, "cti-analysis-item");
    item.append(el("p", hypothesis.texto));
    for (const [key, label] of [["favor", "Supporting"], ["contra", "Contradicting"], ["contexto", "Context"]]) {
      const ids = (hypothesis[key] || []).filter((id) => byId.has(id));
      if (!ids.length) continue;
      const group = el("div");
      group.append(el("small", label));
      for (const id of ids) group.append(evidenceControl(byId.get(id)));
      item.append(group);
    }
    hypotheses.append(item);
  }
  $("cti-conclusion-sources").hidden = !citations.length;
  $("cti-conclusion-citations").replaceChildren(...citations.map((citation) => {
    const entry = el("li");
    entry.append(evidenceControl(citation));
    return entry;
  }));
}

function render(data) {
  const previous = snapshot;
  snapshot = data;
  $("cti-empty").hidden = true;
  $("cti-workspace").hidden = false;
  $("cti-title").textContent = data.title;
  $("cti-seeds").textContent = data.seeds.map((seed) => seed.value).join(" · ");
  const active = ["queued", "running"].includes(data.status);
  const labels = {queued: "Queued", running: "Search in progress", partial: "Search finished · partial results",
    done: "Search finished", empty: "Search finished · no relationships", interrupted: "Search interrupted"};
  const status = el("span", undefined, "metric cti-status" + (active ? " active" : ""));
  status.append(el("span", active ? "◌" : "●", "cti-status-icon"), el("span", labels[data.status] || data.status));
  const conclusion = data.assessment || latestConclusion(data.relations);
  const score = conclusion?.case_confidence;
  const hasScore = Number.isInteger(score) && score >= 0 && score <= 5;
  const confidence = el("details", undefined, "metric cti-confidence");
  confidence.open = $("cti-counts").querySelector(".cti-confidence")?.open || false;
  confidence.append(el("summary", hasScore
    ? "Confidence " + score + "/5" + (conclusion.stale ? " · out of date" : "")
    : "Confidence pending"),
    el("p", conclusion?.confidence_reason || "The score reflects evidence quality and independence."));
  if (hasScore && Number.isInteger(conclusion.cited_domains)) {
    confidence.append(el("p", conclusion.cited_domains + " cited domain(s). Different domains may republish the same source."));
  }
  $("cti-counts").replaceChildren(status, el("span", data.relations.length + " relationships", "metric"), confidence);
  $("cti-expand").disabled = active;
  const latestEvents = new Map(data.events.map((event) => [event.source, event]));
  const assessment = latestEvents.get("OpenCode");
  if (!previous || previous.status !== data.status || previous.relations.length !== data.relations.length ||
      previous.relations.some((row, index) => row.review !== data.relations[index]?.review) ||
      assessment?.id !== previous.events.filter((event) => event.source === "OpenCode").at(-1)?.id) {
    renderConclusion(conclusion, active, assessment);
    renderIntelligence(data);
  }
  $("cti-assessment").hidden = active || (!conclusion?.stale && assessment?.status !== "error");
  $("cti-assessment").disabled = active;
  $("cti-assessment").textContent = conclusion?.stale ? "Reassess case" : "Retry assessment";
  const searchErrors = [...latestEvents.values()].filter((event) => event.status === "error" &&
    ["Busca web", "GitHub público", "Mwmbl", "Arquivo.pt", "OpenCode"].includes(event.source));
  $("cti-event-count").textContent = searchErrors.length
    ? "· Failed: " + [...new Set(searchErrors.map((event) => label(event.source)))].join(", ")
    : data.events.length ? "(" + data.events.length + ")" : "";
  if (searchErrors.some((event) => !previous?.events.some((item) =>
    item.created_at === event.created_at && item.source === event.source && item.status === event.status))) {
    $("cti-activity").open = true;
  }
  $("events").replaceChildren(...data.events.slice(-35).reverse().map((item) => {
    const line = el("li", eventMessage(item.message), item.status);
    line.prepend(el("small", label(item.source) + " · " + new Date(item.created_at).toLocaleTimeString("en-US")));
    return line;
  }));
  if (!previous || previous.relations.length !== data.relations.length ||
      previous.relations.some((item, index) => item.review !== data.relations[index]?.review)) {
    viewGraph(data, !previous);
    inspect(nodes.get(selectedNode));
  }
  return active;
}

async function refresh(caseId) {
  clearTimeout(poll);
  try {
    const data = await request("/api/cti/" + caseId);
    if (selectedCase !== caseId) return;
    if (render(data)) poll = setTimeout(() => refresh(caseId), 800);
  } catch (error) {
    if (selectedCase === caseId) showError(error);
  }
}

async function openCase(caseId) {
  selectedCase = caseId;
  snapshot = null;
  selectedNode = null;
  $("cti-activity").open = false;
  $("cti-conclusion-sources").open = false;
  $("cti-error").hidden = true;
  location.hash = "cti-" + caseId;
  for (const button of $("cti-cases").querySelectorAll("button")) button.removeAttribute("aria-current");
  await refresh(caseId);
  await home();
}

onSubmit($("cti-new"), async (fields) => {
  const created = await request("/api/cti", fields);
  await openCase(created.id);
});
onSubmit($("cti-import"), async () => {
  const file = $("cti-file").files[0];
  if (!file || file.size > 4_500_000) throw new Error("The file must be 4.5 MB or smaller.");
  const parsed = JSON.parse(await file.text());
  const payload = parsed.response || parsed;
  const events = Array.isArray(payload) ? payload : [payload];
  await request("/api/cti/misp", {events});
  await home();
});
onSubmit($("cti-reference"), async (fields) => {
  const caseId = selectedCase;
  await request("/api/cti/" + caseId + "/reference", fields);
  if (selectedCase === caseId) await refresh(caseId);
});
$("cti-expand").onclick = async () => {
  const caseId = selectedCase;
  const button = $("cti-expand");
  button.disabled = true;
  try {
    await request("/api/cti/" + caseId + "/expand", {});
    if (selectedCase === caseId) await refresh(caseId);
  } catch (error) { if (selectedCase === caseId) button.disabled = false; showError(error); }
};
$("cti-assessment").onclick = async () => {
  const caseId = selectedCase;
  const button = $("cti-assessment");
  button.disabled = true;
  $("cti-error").hidden = true;
  try {
    await request("/api/cti/" + caseId + "/assessment", {});
    if (selectedCase === caseId) await refresh(caseId);
  } catch (error) {
    if (selectedCase === caseId) {
      button.disabled = false;
      showError(error);
    }
  }
};
$("cti-export").onclick = () => {
  if (!snapshot) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(snapshot, null, 2)], {type: "application/json"}));
  const link = el("a");
  link.href = url;
  link.download = "openinvestigation-" + snapshot.id + ".json";
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
};
$("cti-export-stix").onclick = async () => {
  if (!snapshot) return;
  const caseId = snapshot.id;
  try {
    const bundle = await request("/api/cti/" + caseId + "/stix");
    const url = URL.createObjectURL(new Blob([JSON.stringify(bundle, null, 2)], {type: "application/json"}));
    const link = el("a");
    link.href = url;
    link.download = "openinvestigation-" + caseId + ".stix.json";
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  } catch (error) { showError(error); }
};
home().then(() => {
  const caseId = Number(/^#cti-(\d+)$/.exec(location.hash)?.[1]);
  if (caseId) openCase(caseId);
}).catch(showError);
