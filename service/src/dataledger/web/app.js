// DataLedger console: read-only views over the indexed ledger plus public verification tools.

const view = document.getElementById("view");
const title = document.getElementById("page-title");
const statusBox = document.getElementById("chain-status");
let directory = {};
let datasetNames = {};

const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ESC[c]);
const short = (h, a = 6, b = 4) => (h && h.length > a + b + 2 ? `${h.slice(0, a + 2)}…${h.slice(-b)}` : h || "");
const num = (n) => Number(n ?? 0).toLocaleString();
const pct = (bps) => `${(bps / 100).toFixed(bps % 100 ? 2 : 0)}%`;
const time = (ts) => (ts ? new Date(ts * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "");
const badge = (text, cls) => `<span class="badge b-${esc(cls ?? String(text).toLowerCase())}">${esc(text)}</span>`;
const hash = (h, a = 8, b = 6) => `<span class="hash" title="${esc(h)}">${esc(short(h, a, b))}</span>`;
const who = (addr) => {
  if (!addr) return "";
  const label = directory[addr];
  return label
    ? `<span title="${esc(addr)}">${esc(label)}</span>`
    : `<span class="hash" title="${esc(addr)}">${esc(short(addr))}</span>`;
};
// Summaries carry short addresses (0x1234…abcd); swap in directory names where we know them.
const labelled = (text) =>
  Object.entries(directory).reduce((t, [addr, name]) => t.split(`${addr.slice(0, 6)}…${addr.slice(-4)}`).join(name), String(text ?? ""));
const CLASS_COLORS = { Public: "var(--ok)", Internal: "var(--info)", Confidential: "var(--warn)", Restricted: "var(--bad)" };

async function api(path, options) {
  const res = await fetch(path, options);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.detail || res.statusText);
  return body;
}

function qualityBadge(q) {
  if (!q || !q.count) return '<span class="faint">not audited</span>';
  const ok = q.passed === q.count;
  return badge(`${ok ? "Passed" : "Failed"} · ${pct(q.min_score_bps)}`, ok ? "passed" : "failed");
}

// ------------------------------------------------------------------ chain status

async function refreshStatus() {
  try {
    const h = await api("/api/health");
    const lag = h.indexer_lag;
    statusBox.innerHTML = `
      <span class="chip"><span class="dot"></span>Chain ${esc(h.chain_id)}</span>
      <span class="chip">Block #${num(h.head_block)}</span>
      <span class="chip"><span class="dot ${lag > 2 ? "lag" : ""}"></span>${lag > 2 ? `Indexer ${lag} blocks behind` : "Indexer in sync"}</span>
      ${h.gateway ? `<span class="chip">Gateway ${who(h.gateway)}</span>` : ""}`;
  } catch {
    statusBox.innerHTML = '<span class="chip"><span class="dot down"></span>API unreachable</span>';
  }
}

// ------------------------------------------------------------------ pages

async function overview() {
  const [o, health] = await Promise.all([api("/api/overview"), api("/api/health")]);
  const s = o.stats;
  const kpi = (label, value, sub = "") =>
    `<div class="card kpi"><div class="label">${esc(label)}</div><div class="value">${value}</div><div class="sub">${esc(sub)}</div></div>`;
  const total = Object.values(o.by_classification).reduce((a, b) => a + b, 0) || 1;
  const classes = ["Public", "Internal", "Confidential", "Restricted"];
  return `
    <p class="lead">Every dataset version is anchored on-chain as a Merkle root of its canonical records and a SHA-256
    file fingerprint. The data itself stays off-chain, encrypted per object; access grants, reads and quality
    attestations are recorded as ledger events.</p>
    <div class="grid kpis">
      ${kpi("Datasets", num(s.datasets), "registered on-chain")}
      ${kpi("Versions anchored", num(s.versions), `${num(s.lineage_edges)} lineage links`)}
      ${kpi("Records anchored", num(s.records_anchored), "provable one by one")}
      ${kpi("Active grants", num(s.active_grants), `${num(s.pending_requests)} requests pending`)}
      ${kpi("Reads logged", num(s.reads_logged), "each one a chain event")}
      ${kpi("Quality attestations", num(s.attestations), "by independent auditors")}
    </div>
    <div class="grid two section">
      <div class="card">
        <div class="spread"><h2>Recent activity</h2><a href="#/audit">Full audit trail →</a></div>
        ${activityList(o.recent_activity)}
      </div>
      <div class="grid" style="align-content:start">
        <div class="card">
          <h2>Datasets by classification</h2>
          <div class="bars">${classes.map((c) => `<div style="width:${((o.by_classification[c] || 0) / total) * 100}%;background:${CLASS_COLORS[c]}"></div>`).join("")}</div>
          <div class="split-list">${classes.map((c) => `<div><span><span class="swatch" style="background:${CLASS_COLORS[c]}"></span>${c}</span><strong>${o.by_classification[c] || 0}</strong></div>`).join("")}</div>
        </div>
        <div class="card">
          <h2>Ledger contracts</h2>
          <dl class="kv">
            <dt>DataRegistry</dt><dd>${hash(health.contracts.dataRegistry, 10, 8)}</dd>
            <dt>AccessLedger</dt><dd>${hash(health.contracts.accessLedger, 10, 8)}</dd>
            <dt>QualityLedger</dt><dd>${hash(health.contracts.qualityLedger, 10, 8)}</dd>
            <dt>Crypto-shredded</dt><dd>${num(s.shredded_objects)} object${s.shredded_objects === 1 ? "" : "s"}</dd>
          </dl>
        </div>
      </div>
    </div>`;
}

function activityList(items) {
  if (!items.length) return '<div class="empty">No activity yet.</div>';
  return `<ul class="activity">${items
    .map(
      (e) => `<li><span class="mark ${e.source}"></span><div>
        <div>${esc(labelled(e.summary))}</div>
        <div class="meta">${time(e.occurred_at)} · ${esc(e.event)}${e.block_number ? ` · block #${num(e.block_number)}` : " · off-chain gateway"}</div>
      </div></li>`,
    )
    .join("")}</ul>`;
}

async function datasets() {
  const list = await api("/api/datasets");
  if (!list.length) return '<div class="card empty">No datasets registered yet.</div>';
  return `<div class="card table-wrap"><table>
    <thead><tr><th>Dataset</th><th>Classification</th><th>Owner</th><th>Latest version</th><th class="num">Records</th><th>Quality</th><th class="num">Active grants</th><th class="num">Reads</th></tr></thead>
    <tbody>${list
      .map((d) => {
        const v = d.latest_version;
        return `<tr class="link" data-href="#/datasets/${d.dataset_id}">
          <td><a href="#/datasets/${d.dataset_id}"><strong>${esc(d.name)}</strong></a><div class="faint">#${d.dataset_id}${d.archived ? " · archived" : ""}</div></td>
          <td>${badge(d.classification_label)}</td>
          <td>${who(d.owner)}</td>
          <td style="white-space:nowrap">${v ? `v${v.version} ${badge(v.status_label)}<div class="faint">${time(v.committed_at)}</div>` : '<span class="faint">none</span>'}</td>
          <td class="num">${v ? num(v.record_count) : "–"}</td>
          <td>${qualityBadge(d.latest_quality)}</td>
          <td class="num">${num(d.active_grants)}</td>
          <td class="num">${num(d.access_count)}</td>
        </tr>`;
      })
      .join("")}</tbody></table></div>`;
}

async function dataset(id) {
  const d = await api(`/api/datasets/${encodeURIComponent(id)}`);
  title.textContent = d.name;
  const schema = d.schema || { columns: [] };
  const tab = sessionStorage.getItem("ds-tab") || "versions";
  const panels = {
    versions: d.versions.map(versionCard).join("") || '<div class="empty">No versions yet.</div>',
    schema: schemaTable(schema),
    access: accessPanel(d),
    activity: `<div class="card">${activityList(d.activity)}</div>`,
  };
  const labels = { versions: `Versions (${d.versions.length})`, schema: "Schema", access: "Access", activity: "Activity" };
  return `
    <div class="card ds-header">
      <div>
        <h2>${esc(d.name)} ${badge(d.classification_label)} ${d.archived ? badge("Archived", "neutral") : ""}</h2>
        <div class="muted">${esc(schema.description || "")}</div>
        <dl class="facts">
          <div><dt>Owner</dt><dd>${who(d.owner)}${schema.owner_team && schema.owner_team !== directory[d.owner] ? ` <span class="faint">· ${esc(schema.owner_team)}</span>` : ""}</dd></div>
          <div><dt>Stewards</dt><dd>${d.stewards.map(who).join(", ") || '<span class="faint">none</span>'}</dd></div>
          <div><dt>Registered</dt><dd>${time(d.created_at)} · block #${num(d.created_block)}</dd></div>
          <div><dt>Schema hash</dt><dd>${hash(d.schema_hash)}</dd></div>
          <div><dt>Reads logged</dt><dd>${num(d.access_count)}</dd></div>
          <div><dt>Lineage</dt><dd><a href="#/lineage/${d.dataset_id}">Open graph →</a></dd></div>
        </dl>
      </div>
    </div>
    <div class="tabs" role="tablist">${Object.keys(panels)
      .map((k) => `<button role="tab" data-tab="${k}" class="${k === tab ? "active" : ""}">${labels[k]}</button>`)
      .join("")}</div>
    ${Object.entries(panels)
      .map(([k, html]) => `<section data-panel="${k}" ${k === tab ? "" : "hidden"}>${html}</section>`)
      .join("")}`;
}

function versionCard(v) {
  const ref = (r) => `<a class="ref" href="#/datasets/${r.dataset_id}">${esc(r.name)} v${r.version}</a>`;
  const q = v.quality;
  const attestations = q
    ? q.attestations
        .map((a) => `${badge(a.passed ? "Passed" : "Failed", a.passed ? "passed" : "failed")} ${pct(a.score_bps)} by ${who(a.auditor)} · <a href="/api/documents/${esc(a.report_hash)}" target="_blank" rel="noopener">report</a>`)
        .join("<br>")
    : '<span class="faint">not audited</span>';
  const objectState = v.object ? badge(v.object.state, v.object.state === "anchored" ? "ok" : v.object.state) : '<span class="faint">not held by this gateway</span>';
  return `<article class="version ${v.status_label.toLowerCase()}">
    <header>
      <div class="row"><span class="vnum">v${v.version}</span>${badge(v.status_label)}<span class="faint">${time(v.committed_at)} by ${who(v.committer)}</span></div>
      <a class="hash" href="#/audit" title="${esc(v.tx_hash)}">tx ${esc(short(v.tx_hash))}</a>
    </header>
    <dl class="kv">
      <dt>Records</dt><dd>${num(v.record_count)}</dd>
      <dt>Merkle root</dt><dd>${hash(v.merkle_root, 14, 10)}</dd>
      <dt>File SHA-256</dt><dd>${hash(v.content_hash, 14, 10)}</dd>
      <dt>Encrypted object</dt><dd>${objectState} <span class="hash">${esc(short(v.storage_uri, 20, 6))}</span></dd>
      <dt>Derived from</dt><dd class="refs">${v.parents.map(ref).join("") || '<span class="faint">source data</span>'}</dd>
      <dt>Used by</dt><dd class="refs">${v.children.map(ref).join("") || '<span class="faint">no downstream versions</span>'}</dd>
      <dt>Quality</dt><dd>${attestations}</dd>
    </dl>
    ${v.status_reason ? `<div class="note ${v.status_label === "Withdrawn" ? "bad" : "warn"}">${esc(v.status_label)}: ${esc(v.status_reason)}</div>` : ""}
  </article>`;
}

function schemaTable(schema) {
  return `<div class="card table-wrap"><table>
    <thead><tr><th>Column</th><th>Type</th><th>Required</th><th>Personal data</th><th>Description</th></tr></thead>
    <tbody>${schema.columns
      .map(
        (c) => `<tr><td><code>${esc(c.name)}</code>${schema.primary_key?.includes(c.name) ? ' <span class="badge b-info">key</span>' : ""}</td>
        <td>${esc(c.type)}</td><td>${c.required ? "yes" : ""}</td><td>${c.pii ? badge("PII", "warn") : ""}</td><td class="muted">${esc(c.description)}</td></tr>`,
      )
      .join("")}</tbody></table></div>`;
}

function grantState(g) {
  if (g.revoked) return badge("Revoked", "revoked");
  return g.active ? badge("Active", "active") : badge("Expired", "expired");
}

function accessPanel(d) {
  const grants = d.grants.length
    ? `<table><thead><tr><th>Grantee</th><th>Purpose</th><th>Granted by</th><th>Expires</th><th>State</th></tr></thead><tbody>${d.grants
        .map((g) => `<tr><td>${who(g.grantee)}</td><td>${esc(g.purpose || "")}<div class="hash">${esc(short(g.purpose_hash))}</div></td><td>${who(g.granted_by)}</td><td>${time(g.expires_at)}</td><td>${grantState(g)}</td></tr>`)
        .join("")}</tbody></table>`
    : `<div class="empty">${d.classification_label === "Public" ? "Public dataset: readable by any signed-in account." : "No grants."}</div>`;
  const requests = d.access_requests.length
    ? `<table><thead><tr><th>#</th><th>Requester</th><th>Purpose</th><th>Requested</th><th>Decision</th></tr></thead><tbody>${d.access_requests
        .map((r) => `<tr><td>${r.request_id}</td><td>${who(r.requester)}</td><td>${esc(r.purpose)}</td><td>${time(r.requested_at)}</td><td>${badge(r.status)}${r.reason ? `<div class="muted">${esc(r.reason)}</div>` : ""}</td></tr>`)
        .join("")}</tbody></table>`
    : '<div class="empty">No access requests.</div>';
  const reads = d.recent_reads.length
    ? `<table><thead><tr><th>When</th><th>Reader</th><th>Version</th><th>Receipt</th><th>Tx</th></tr></thead><tbody>${d.recent_reads
        .map((r) => `<tr><td>${time(r.accessed_at)}</td><td>${who(r.accessor)}</td><td>v${r.version}</td><td>${hash(r.receipt_hash)}</td><td>${hash(r.tx_hash)}</td></tr>`)
        .join("")}</tbody></table>`
    : '<div class="empty">No reads logged.</div>';
  return `<div class="grid">
    <div class="card table-wrap"><h2>Grants</h2>${grants}</div>
    <div class="card table-wrap"><h2>Access requests</h2>${requests}</div>
    <div class="card table-wrap"><h2>Reads logged on-chain</h2>${reads}</div>
  </div>`;
}

async function lineage(id) {
  const g = await api(id ? `/api/lineage?dataset_id=${encodeURIComponent(id)}` : "/api/lineage");
  if (!g.nodes.length) return '<div class="card empty">No versions anchored yet.</div>';
  const focus = id ? Number(id) : null;
  return `<p class="lead">Each box is an immutable dataset version; arrows show which upstream versions it was built from,
    as declared on-chain when the version was committed. ${focus ? '<a href="#/lineage">Show the full graph</a>.' : "Open a dataset to focus on its upstream and downstream versions."}</p>
    <div class="lineage-wrap">${lineageSvg(g, focus)}</div>
    <div class="legend">
      ${Object.entries(CLASS_COLORS).map(([k, c]) => `<span style="--c:${c}">${k}</span>`).join("")}
      <span style="--c:transparent;border:0">Dashed red border: withdrawn version</span>
    </div>`;
}

function lineageSvg(g, focus) {
  const W = 230, H = 74, GX = 110, GY = 22, PAD = 28;
  const nodes = new Map(g.nodes.map((n) => [n.id, { ...n, parents: [] }]));
  g.edges.forEach((e) => nodes.get(e.to)?.parents.push(e.from));
  const depth = new Map();
  const visit = (id, trail = new Set()) => {
    if (depth.has(id)) return depth.get(id);
    if (trail.has(id)) return 0;
    trail.add(id);
    const d = Math.max(-1, ...nodes.get(id).parents.filter((p) => nodes.has(p)).map((p) => visit(p, trail))) + 1;
    depth.set(id, d);
    return d;
  };
  nodes.forEach((_, id) => visit(id));
  const columns = [];
  nodes.forEach((n, id) => (columns[depth.get(id)] ||= []).push(n));
  columns.forEach((col) => col.sort((a, b) => a.dataset_id - b.dataset_id || a.version - b.version));
  const pos = new Map();
  columns.forEach((col, ci) => col.forEach((n, ri) => pos.set(n.id, { x: PAD + ci * (W + GX), y: PAD + ri * (H + GY) })));
  const width = PAD * 2 + columns.length * W + (columns.length - 1) * GX;
  const height = PAD * 2 + Math.max(...columns.map((c) => c.length)) * (H + GY) - GY;
  const edges = g.edges
    .filter((e) => pos.has(e.from) && pos.has(e.to))
    .map((e) => {
      const a = pos.get(e.from), b = pos.get(e.to);
      const x1 = a.x + W, y1 = a.y + H / 2, x2 = b.x - 6, y2 = b.y + H / 2, mx = (x1 + x2) / 2;
      return `<path class="edge" marker-end="url(#arrow)" d="M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}"/>`;
    })
    .join("");
  const boxes = [...nodes.values()]
    .map((n) => {
      const p = pos.get(n.id);
      const q = n.quality ? (n.quality.passed === n.quality.count ? `quality ${pct(n.quality.min_score_bps)}` : "quality failed") : "not audited";
      const cls = [n.status.toLowerCase(), focus === n.dataset_id ? "focus" : ""].join(" ");
      return `<g class="node ${cls}" data-href="#/datasets/${n.dataset_id}" transform="translate(${p.x},${p.y})">
        <title>${esc(n.name)} v${n.version} (${esc(n.status)})</title>
        <rect width="${W}" height="${H}" rx="9"/>
        <rect class="bar" width="5" height="${H}" rx="2" style="fill:${CLASS_COLORS[n.classification] || "var(--faint)"}"/>
        <text class="t" x="16" y="24">${esc(n.name)} · v${n.version}</text>
        <text class="s" x="16" y="44">${n.record_count != null ? `${num(n.record_count)} records` : ""} · ${esc(n.status)}</text>
        <text class="s" x="16" y="61">${esc(q)}</text>
      </g>`;
    })
    .join("");
  return `<svg width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" role="img" aria-label="Dataset lineage graph">
    <defs><marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="var(--faint)"/></marker></defs>
    ${edges}${boxes}</svg>`;
}

async function access() {
  const [requests, list] = await Promise.all([api("/api/access-requests"), api("/api/datasets")]);
  const counts = requests.reduce((acc, r) => ({ ...acc, [r.status]: (acc[r.status] || 0) + 1 }), {});
  return `<p class="lead">Consumers ask for access with a stated purpose; dataset owners or stewards approve a time-boxed
    grant on-chain. The gateway rechecks the grant on-chain for every read and logs the read before any data leaves.</p>
    <div class="grid kpis">
      ${["pending", "approved", "rejected", "cancelled"].map((s) => `<div class="card kpi"><div class="label">${s[0].toUpperCase() + s.slice(1)}</div><div class="value">${counts[s] || 0}</div></div>`).join("")}
      <div class="card kpi"><div class="label">Active grants</div><div class="value">${list.reduce((a, d) => a + d.active_grants, 0)}</div></div>
    </div>
    <div class="card table-wrap section"><h2>Access requests</h2>${
      requests.length
        ? `<table><thead><tr><th>#</th><th>Dataset</th><th>Requester</th><th>Purpose</th><th>Requested</th><th>Decision</th><th>Decided by</th></tr></thead><tbody>${requests
            .map((r) => `<tr><td>${r.request_id}</td><td><a href="#/datasets/${r.dataset_id}">${esc(r.name)}</a></td><td>${who(r.requester)}</td><td>${esc(r.purpose)}</td><td>${time(r.requested_at)}</td><td>${badge(r.status)}${r.reason ? `<div class="muted">${esc(r.reason)}</div>` : ""}</td><td>${who(r.decided_by)}</td></tr>`)
            .join("")}</tbody></table>`
        : '<div class="empty">No requests yet.</div>'
    }</div>`;
}

async function audit() {
  const [events, list] = await Promise.all([api("/api/audit?limit=300"), api("/api/datasets")]);
  const contracts = [...new Set(events.map((e) => e.contract || "Gateway"))];
  return `<p class="lead">One timeline for every ledger event (indexed from the chain, with block and transaction) and
    every gateway action that happens off-chain, such as staging an encrypted upload or destroying a data key.</p>
    <div class="filters">
      <select id="f-dataset"><option value="">All datasets</option>${list.map((d) => `<option value="${d.dataset_id}">${esc(d.name)}</option>`).join("")}</select>
      <select id="f-source"><option value="">All sources</option>${contracts.map((c) => `<option>${esc(c)}</option>`).join("")}</select>
    </div>
    <div class="card table-wrap"><table>
      <thead><tr><th>When</th><th>Source</th><th>Event</th><th>Summary</th><th>Actor</th><th>Block / tx</th></tr></thead>
      <tbody id="audit-rows">${events
        .map(
          (e) => `<tr data-dataset="${e.dataset_id ?? ""}" data-source="${esc(e.contract || "Gateway")}">
            <td class="muted" style="white-space:nowrap">${time(e.occurred_at)}</td>
            <td>${badge(e.contract || "Gateway", e.source === "chain" ? "info" : "neutral")}</td>
            <td><code>${esc(e.event)}</code></td>
            <td>${esc(labelled(e.summary))}</td>
            <td>${who(e.actor)}</td>
            <td>${e.block_number ? `#${num(e.block_number)}<div>${hash(e.tx_hash)}</div>` : '<span class="faint">off-chain</span>'}</td>
          </tr>`,
        )
        .join("")}</tbody></table></div>`;
}

async function verify() {
  const g = await api("/api/lineage");
  g.nodes.forEach((n) => (datasetNames[n.dataset_id] = n.name));
  const options = g.nodes.map((n) => `<option value="${n.dataset_id}:${n.version}">${esc(n.name)} v${n.version} (${esc(n.status)})</option>`).join("");
  return `<p class="lead">Anyone can check data against the chain without an account: these checks call the ledger
    contracts directly and never need access to the stored data.</p>
    <div class="grid two" style="grid-template-columns:1fr 1fr">
      <div class="card">
        <h2>Verify a file</h2>
        <form id="verify-file" class="stack">
          <label>CSV file<input type="file" name="file" accept=".csv,text/csv" required></label>
          <label>Compare record by record with (optional)
            <select name="target"><option value="">Look up by file fingerprint only</option>${options}</select></label>
          <button class="primary" type="submit">Verify file</button>
        </form>
        <div id="file-result"></div>
      </div>
      <div class="card">
        <h2>Verify a record proof</h2>
        <form id="verify-record" class="stack">
          <label><span>Proof JSON from <code>dataledger prove</code> or the records API</span>
            <textarea name="proof" required placeholder='{"dataset_id": 2, "version": 2, "index": 17, "canonical": "...", "proof": ["0x..."]}'></textarea></label>
          <button class="primary" type="submit">Check on-chain</button>
        </form>
        <div id="record-result"></div>
      </div>
    </div>`;
}

function fileResult(r) {
  const rows = (pairs) => `<dl class="kv">${pairs.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join("")}</dl>`;
  const name = (id) => `<a href="#/datasets/${esc(id)}">${esc(datasetNames[id] || `dataset #${id}`)}</a> v${esc(r.version)}`;
  switch (r.result) {
    case "exact_match":
      return `<div class="result ok"><div class="headline">Exact match</div>
        <p>This file is byte-for-byte the content anchored as ${name(r.dataset_id)} (${esc(r.status)}).</p>
        ${rows([["File SHA-256", hash(r.content_hash, 14, 10)], ["Merkle root", hash(r.merkle_root, 14, 10)], ["Records", num(r.record_count)]])}</div>`;
    case "records_match":
      return `<div class="result ok"><div class="headline">Records match</div>
        <p>The bytes differ (formatting, line endings or column order), but every record matches the Merkle root of ${name(r.dataset_id)}.</p>
        ${rows([["Merkle root", hash(r.merkle_root, 14, 10)], ["Records", num(r.record_count)]])}</div>`;
    case "mismatch":
      return `<div class="result bad"><div class="headline">Mismatch: this is not the anchored data</div>
        <p>Compared with ${name(r.dataset_id)} (${esc(r.status)}).</p>
        ${rows([
          ["Computed root", hash(r.merkle_root, 14, 10)],
          ["Anchored root", hash(r.anchored_merkle_root, 14, 10)],
          ["Records", `${num(r.record_count)} in file · ${num(r.anchored_record_count)} anchored`],
          ["File SHA-256", hash(r.content_hash, 14, 10)],
        ])}</div>`;
    default:
      return `<div class="result warn"><div class="headline">Not anchored</div>
        <p>No version on this chain has this file fingerprint. Pick a dataset version above to compare record by record.</p>
        ${rows([["File SHA-256", hash(r.content_hash, 14, 10)]])}</div>`;
  }
}

function wireVerify() {
  const fileForm = document.getElementById("verify-file");
  fileForm?.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const out = document.getElementById("file-result");
    const data = new FormData();
    data.append("file", fileForm.file.files[0]);
    const [d, v] = (fileForm.target.value || ":").split(":");
    if (d) {
      data.append("dataset_id", d);
      data.append("version", v);
    }
    fileForm.querySelector("button").disabled = true;
    try {
      out.innerHTML = fileResult(await api("/api/verify/file", { method: "POST", body: data }));
    } catch (err) {
      out.innerHTML = `<div class="result bad">${esc(err.message)}</div>`;
    } finally {
      fileForm.querySelector("button").disabled = false;
    }
  });
  const recordForm = document.getElementById("verify-record");
  recordForm?.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const out = document.getElementById("record-result");
    try {
      const proof = JSON.parse(recordForm.proof.value);
      const body = { dataset_id: proof.dataset_id, version: proof.version, index: proof.index, proof: proof.proof };
      if (proof.canonical != null) body.canonical = proof.canonical;
      else body.record = proof.record;
      const r = await api("/api/verify/record", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      out.innerHTML = r.valid
        ? `<div class="result ok"><div class="headline">Record verified on-chain</div><p>Record ${esc(proof.index)} is part of ${esc(datasetNames[proof.dataset_id] || `dataset #${proof.dataset_id}`)} v${esc(proof.version)} (${esc(r.status)}).</p><dl class="kv"><dt>Leaf</dt><dd>${hash(r.leaf, 14, 10)}</dd></dl></div>`
        : `<div class="result bad"><div class="headline">Proof rejected</div><p>The record, its position or the proof does not match the anchored Merkle root.</p></div>`;
    } catch (err) {
      out.innerHTML = `<div class="result bad">${esc(err.message)}</div>`;
    }
  });
}

// ------------------------------------------------------------------ router

const ROUTES = {
  overview: ["Overview", overview],
  datasets: ["Datasets", datasets],
  lineage: ["Lineage", lineage],
  access: ["Access", access],
  audit: ["Audit trail", audit],
  verify: ["Verify", verify],
};

async function render() {
  const [, page = "overview", id] = location.hash.split("/");
  const route = page === "datasets" && id ? ["Dataset", () => dataset(id)] : ROUTES[page] || ROUTES.overview;
  document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("active", a.dataset.route === page || (!ROUTES[page] && a.dataset.route === "overview")));
  title.textContent = route[0];
  try {
    view.innerHTML = await route[1](id);
  } catch (err) {
    view.innerHTML = `<div class="card empty">Could not load this page: ${esc(err.message)}</div>`;
  }
  if (page === "verify") wireVerify();
}

view.addEventListener("click", (ev) => {
  const tabButton = ev.target.closest("[data-tab]");
  if (tabButton) {
    sessionStorage.setItem("ds-tab", tabButton.dataset.tab);
    view.querySelectorAll("[data-tab]").forEach((b) => b.classList.toggle("active", b === tabButton));
    view.querySelectorAll("[data-panel]").forEach((p) => (p.hidden = p.dataset.panel !== tabButton.dataset.tab));
    return;
  }
  const row = ev.target.closest("[data-href]");
  if (row && !ev.target.closest("a")) location.hash = row.dataset.href;
});

view.addEventListener("change", (ev) => {
  if (!["f-dataset", "f-source"].includes(ev.target.id)) return;
  const ds = document.getElementById("f-dataset").value;
  const src = document.getElementById("f-source").value;
  document.querySelectorAll("#audit-rows tr").forEach((tr) => {
    tr.hidden = (ds && tr.dataset.dataset !== ds) || (src && tr.dataset.source !== src);
  });
});

window.addEventListener("hashchange", render);
api("/api/directory")
  .then((d) => (directory = d))
  .catch(() => {})
  .finally(() => {
    refreshStatus();
    render();
  });
setInterval(refreshStatus, 5000);
