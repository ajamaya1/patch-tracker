"use strict";

/* Patch Tracker — vulnerability triage console.
   Loads the daily-generated data.json and presents it the way a vulnerability-
   management engineer triages: risk-ranked, with an "act now" lane, platform
   views, CISA KEV deadlines, and a detail drawer with remediation guidance. */

const SEV_RANK = { critical: 4, important: 3, high: 3, moderate: 2, medium: 2, low: 1 };
const SOURCE_LABEL = { apple: "Apple", microsoft: "Microsoft",
  "cisa-kev": "CISA KEV", nvd: "NVD" };
// Priority is a remediation-urgency tier (P1 = act first), deliberately
// distinct from CVE/CVSS severity so the two scales aren't confused.
const BAND_LABEL = { critical: "P1", high: "P2", medium: "P3", low: "P4" };
const bandLabel = (b) => BAND_LABEL[b] || b;

const VIEWS = [
  { id: "all", label: "All patches", icon: "≡", desc: "Recent activity (last ~30 days) plus the latest monthly Microsoft rollup.",
    pred: () => true },
  { id: "zeroday", label: "Zero-day", icon: "", danger: true,
    desc: "Actively exploited in the wild — zero-days and CISA KEV entries.",
    pred: (p) => p.exploited_count > 0 },
  { id: "windows", label: "Windows", icon: "▢",
    desc: "Microsoft Patch Tuesday updates, split by client and server.",
    pred: (p) => p.source === "microsoft" },
  { id: "apple", label: "Apple", icon: "", desc: "macOS, iOS and related Apple security releases.",
    pred: (p) => p.source === "apple" },
  { id: "thirdparty", label: "Third-party", icon: "◆",
    desc: "Browsers and third-party software (CISA KEV + NVD advisories).",
    pred: (p) => p.source === "cisa-kev" || p.source === "nvd" },
];

const state = {
  data: null,
  view: "all",
  sort: "date",
  filters: { q: "", cve: "", platform: "", affected: "", minSev: 0, minCvss: 0,
    exploited: false, newonly: false, overdue: false },
  results: [],
};

// Reset every filter and clear the toolbar controls (sort is left as-is).
function resetFilters() {
  Object.assign(state.filters, { q: "", cve: "", platform: "", affected: "",
    minSev: 0, minCvss: 0, exploited: false, newonly: false, overdue: false });
  for (const el of document.querySelectorAll(".toolbar input, .toolbar select")) {
    if (el.type === "checkbox") el.checked = false;
    else if (el.id !== "sort") el.value = "";
  }
}

const $ = (s) => document.querySelector(s);
const todayISO = new Date().toISOString().slice(0, 10);

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
const fmtDate = (s) => (s ? String(s).slice(0, 10) : "—");
const sevRank = (s) => SEV_RANK[(s || "").toLowerCase()] || 0;
function sevClass(s) {
  const r = sevRank(s);
  return r >= 4 ? "sev-critical" : r === 3 ? "sev-important"
    : r === 2 ? "sev-moderate" : "sev-low";
}
function isOverdue(p) { return !!(p.due_date && fmtDate(p.due_date) < todayISO); }

const FIX_LABEL = { microsoft: "MSRC update", apple: "Apple advisory",
  "cisa-kev": "Vendor advisory", nvd: "Vendor advisory" };

// The most decision-relevant CVE in a patch (exploited first, then highest CVSS).
function leadCve(p) {
  const cves = p.cves || [];
  return cves.find((c) => c.exploited) ||
    cves.slice().sort((a, b) => (b.base_score || 0) - (a.base_score || 0))[0] || null;
}
// A specific, actionable destination — not a generic catalog/API URL. The lead
// CVE's per-vendor page (MSRC vulnerability / Apple HT / NVD detail) links to
// the actual KB / patched build / vendor references.
function primaryFixUrl(p) {
  const c = leadCve(p);
  if (c && c.url) return c.url;
  const links = (p.remediation && p.remediation.links) || [];
  const good = links.map((l) => l.url)
    .find((u) => u && !/known-exploited-vulnerabilities-catalog\/?$/.test(u));
  return good || p.url || null;
}
function dueDays(d) {
  if (!d) return null;
  return Math.round((new Date(fmtDate(d)) - new Date(todayISO)) / 86400000);
}

/* ---------------- Load ---------------- */
async function load() {
  try {
    const resp = await fetch("data.json?t=" + Date.now(), { cache: "no-store" });
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    state.data = await resp.json();
  } catch (e) {
    $("#list").innerHTML =
      '<p class="empty">Could not load <code>data.json</code>. Run ' +
      "<code>patch-tracker build-site</code> or wait for the daily Action.</p>";
    $("#updated").textContent = "Failed to load data";
    return;
  }
  const when = state.data.generated_at ? new Date(state.data.generated_at) : null;
  $("#updated").innerHTML = "Updated<br>" + (when ? when.toUTCString() : "—");
  initViewFromHash();
  renderViews();
  wire();
  render();
}

function initViewFromHash() {
  const h = (location.hash || "").replace("#", "");
  if (VIEWS.some((v) => v.id === h)) state.view = h;
}

/* ---------------- Sidebar views ---------------- */
function renderViews() {
  const nav = $("#views");
  nav.innerHTML = VIEWS.map((v) => {
    const n = state.data.patches.filter(v.pred).length;
    return `<button class="view-btn ${v.id === state.view ? "active" : ""} ${v.danger ? "danger" : ""}"
      data-view="${v.id}"><span class="vlabel">${esc(v.label)}</span>
      <span class="vcount">${n}</span></button>`;
  }).join("");
  nav.querySelectorAll(".view-btn").forEach((b) =>
    b.addEventListener("click", () => setView(b.dataset.view)));
}

function setView(id) {
  state.view = id;
  location.hash = id;
  resetFilters();          // each view starts clean — no lingering filters
  renderViews();
  render();
}

/* ---------------- KPIs ---------------- */
function kpi(id, num, label, filterAttr) {
  return `<div class="kpi k-${id}" data-kpi="${filterAttr || ""}">
    <div class="kn">${num}</div><div class="kl">${label}</div></div>`;
}
function renderKPIs() {
  const ps = state.data.patches;
  const s = state.data.stats;
  const actnow = ps.filter((p) => p.exploited_count > 0 || isOverdue(p)).length;
  const overdue = ps.filter(isOverdue).length;
  $("#kpis").innerHTML =
    kpi("actnow", actnow, "Act now", "actnow") +
    kpi("exploit", s.exploited_cves || 0, "Exploited CVEs", "exploited") +
    kpi("crit", s.by_severity?.Critical || 0, "Critical patches", "crit") +
    kpi("new", s.new_cves || 0, `New CVEs (${state.data.new_window_days}d)`, "new") +
    kpi("overdue", overdue, "KEV overdue", "overdue") +
    kpi("total", s.total_patches || 0, "Patches tracked", "");
  $("#kpis").querySelectorAll(".kpi").forEach((el) =>
    el.addEventListener("click", () => applyKPI(el.dataset.kpi)));
}
function applyKPI(kind) {
  const f = state.filters;
  if (kind === "actnow" || kind === "exploited") {
    f.exploited = !f.exploited; $("#exploited").checked = f.exploited;
  } else if (kind === "new") {
    f.newonly = !f.newonly; $("#newonly").checked = f.newonly;
  } else if (kind === "crit") {
    f.minSev = f.minSev === 4 ? 0 : 4;
    $("#severity").value = f.minSev ? "critical" : "";
  } else if (kind === "overdue") {
    f.overdue = !f.overdue;
  }
  render();
}

/* ---------------- Filtering / sorting ---------------- */
function cveFiltersActive() {
  const f = state.filters;
  return !!(f.cve || f.minSev || f.minCvss || f.exploited || f.newonly || f.affected);
}
function cveMatches(c) {
  const f = state.filters;
  if (f.cve && !c.cve_id.toLowerCase().includes(f.cve)) return false;
  if (f.minSev && sevRank(c.severity) < f.minSev) return false;
  if (f.minCvss && !(c.base_score != null && c.base_score >= f.minCvss)) return false;
  if (f.exploited && !c.exploited) return false;
  if (f.newonly && !c.is_new) return false;
  if (f.affected) {
    const k = c.product_kinds || [];
    if (f.affected === "both") { if (!(k.includes("client") && k.includes("server"))) return false; }
    else if (!k.includes(f.affected)) return false;
  }
  return true;
}
function patchMatches(p) {
  const f = state.filters;
  if (f.platform && p.platform !== f.platform) return false;
  if (f.affected) {
    const a = p.affected || {};
    if (f.affected === "both") { if (!(a.client && a.server)) return false; }
    else if (!a[f.affected]) return false;
  }
  if (f.overdue && !isOverdue(p)) return false;
  if (f.q) {
    const hay = (p.title + " " + (p.product || "") + " " + p.patch_id).toLowerCase();
    if (!hay.includes(f.q)) return false;
  }
  return true;
}
const SORTERS = {
  priority: (a, b) => (b.patch.priority?.score || 0) - (a.patch.priority?.score || 0),
  severity: (a, b) => (sevRank(b.patch.severity) - sevRank(a.patch.severity)) ||
    ((b.patch.priority?.score || 0) - (a.patch.priority?.score || 0)),
  cvss: (a, b) => (b.patch.max_cvss || 0) - (a.patch.max_cvss || 0),
  date: (a, b) => String(b.patch.release_date || "").localeCompare(String(a.patch.release_date || "")),
  due: (a, b) => (a.patch.due_date || "9999").localeCompare(b.patch.due_date || "9999"),
};
function computeResults() {
  const view = VIEWS.find((v) => v.id === state.view);
  const active = cveFiltersActive();
  const out = [];
  for (const p of state.data.patches) {
    if (!view.pred(p)) continue;
    if (!patchMatches(p)) continue;
    const cves = active ? p.cves.filter(cveMatches) : p.cves;
    if (active && cves.length === 0) continue;
    out.push({ patch: p, cves });
  }
  out.sort(SORTERS[state.sort] || SORTERS.priority);
  state.results = out;
  return out;
}

/* ---------------- Badges ---------------- */
function dueBadge(p) {
  if (!p.due_date) return "";
  const d = dueDays(p.due_date);
  if (d == null) return "";
  if (d < 0) return `<span class="badge due overdue">KEV overdue ${-d}d</span>`;
  return `<span class="badge due">KEV due ${d}d</span>`;
}
function patchBadges(p, full) {
  // Cards stay scannable: source, platform, severity + the few decisive risk
  // signals. The drawer (full) shows the complete set.
  let b = `<span class="badge src-${esc(p.source)}">${esc(SOURCE_LABEL[p.source] || p.source)}</span>`;
  if (p.platform) b += `<span class="badge platform">${esc(p.platform)}</span>`;
  if (p.severity) b += `<span class="badge ${sevClass(p.severity)}">${esc(p.severity)}</span>`;
  if (p.exploited_count) b += `<span class="badge exploit">Exploited</span>`;
  b += dueBadge(p);
  if (p.new_count) b += `<span class="badge new">${p.new_count} new</span>`;
  if (full) {
    if (p.ransomware_count) b += `<span class="badge ransom">Ransomware</span>`;
    const a = p.affected || {};
    if (a.client) b += `<span class="badge kind">${a.client} client</span>`;
    if (a.server) b += `<span class="badge kind">${a.server} server</span>`;
    if (p.patch_tuesday) b += `<span class="badge plain">Patch Tuesday ${fmtDate(p.patch_tuesday)}</span>`;
    if (p.servicing) {
      const hp = p.servicing.hotpatch || {};
      b += `<span class="badge plain">${esc(p.servicing.channel)}-release · ${hp.is_hotpatch_month ? "hotpatch" : "cumulative"}</span>`;
    }
  }
  return b;
}

/* ---------------- Cards ---------------- */
function render() {
  renderViews();
  renderKPIs();
  const view = VIEWS.find((v) => v.id === state.view);
  $("#view-title").textContent = view.label;
  $("#view-desc").textContent = view.desc;

  const results = computeResults();
  const shown = results.reduce((n, r) => n + r.cves.length, 0);
  $("#resultcount").textContent = `${results.length} patches · ${shown} CVEs`;
  $("#empty").hidden = results.length !== 0;

  $("#list").innerHTML = results.map(({ patch: p, cves }, i) => {
    const pr = p.priority || { score: 0, band: "low", reasons: [] };
    const sub = [p.product, p.version, fmtDate(p.release_date), `${cves.length} CVEs`]
      .filter(Boolean).join(" · ");
    const reasons = pr.reasons && pr.reasons.length
      ? `<div class="preasons">Why: <b>${esc(pr.reasons.join(" · "))}</b></div>` : "";
    const fixUrl = primaryFixUrl(p);
    const fixChip = fixUrl
      ? `<a class="pnext-cta" href="${esc(fixUrl)}" target="_blank" rel="noopener" title="Open the vendor advisory / patch reference for the lead CVE">${esc(FIX_LABEL[p.source] || "Advisory")} &rarr;</a>`
      : "";
    const next = p.remediation
      ? `<div class="pnext"><span class="pnext-label">Action</span> ${esc(p.remediation.summary)} ${fixChip}</div>` : "";
    return `<article class="pcard b-${pr.band}" data-i="${i}" tabindex="0">
      <div class="rail b-${pr.band}" title="Remediation priority ${bandLabel(pr.band)} (P1 = act first) · score ${pr.score}/100"><span class="band-tag">PRIORITY</span><span class="score">${pr.score}</span><span class="band">${bandLabel(pr.band)}</span></div>
      <div class="pbody">
        <div class="pcard-head"><span class="ptitle">${esc(p.title)}</span>
          <span class="psub">${esc(sub)}</span></div>
        <div class="pbadges">${patchBadges(p, false)}</div>
        ${next}
        ${reasons}
      </div>
    </article>`;
  }).join("");

  $("#list").querySelectorAll(".pcard").forEach((el) => {
    const open = () => openDrawer(results[+el.dataset.i]);
    el.addEventListener("click", open);
    el.addEventListener("keydown", (e) => { if (e.key === "Enter") open(); });
    // Let in-card links (the Fix link) open the vendor URL without also
    // triggering the drawer.
    el.querySelectorAll("a").forEach((a) =>
      a.addEventListener("click", (e) => e.stopPropagation()));
  });
}

/* ---------------- Detail drawer ---------------- */
function remediationHTML(p) {
  const r = p.remediation;
  if (!r) return "";
  let h = `<div class="rem rem-${esc(r.urgency)}"><div class="rem-head">
    <span class="rem-urgency ${esc(r.urgency)}">${esc((r.urgency || "").toUpperCase())}</span>
    <span class="rem-note">${esc(r.note)}</span></div>
    <div class="rem-summary">${esc(r.summary)}</div>`;
  if (p.servicing) {
    const sv = p.servicing, hp = sv.hotpatch || {};
    h += `<div class="rem-servicing"><b>Windows servicing:</b> ${esc(sv.channel_label)}.
      <b>${esc(hp.update_type)}</b> — ${esc(hp.note)}
      <span class="muted">Eligible: ${esc(sv.eligible_skus)}. ${esc(sv.preview_note)}</span></div>`;
  }
  for (const sec of r.sections || []) {
    h += `<div class="rem-sec"><div class="aud">${esc(sec.audience)}</div><ul>`;
    for (const step of sec.steps || []) h += `<li>${esc(step)}</li>`;
    h += `</ul></div>`;
  }
  if (r.links && r.links.length) {
    h += `<div class="rem-links">` + r.links.map((l) =>
      `<a class="btn-link" href="${esc(l.url)}" target="_blank" rel="noopener">${esc(l.label)} ↗</a>`).join("") + `</div>`;
  }
  return h + `</div>`;
}
function cveTable(cves) {
  const rows = cves.slice().sort((a, b) =>
    (b.exploited - a.exploited) || (b.is_new - a.is_new) || (sevRank(b.severity) - sevRank(a.severity)) ||
    ((b.base_score || 0) - (a.base_score || 0)))
    .map((c) => {
      const url = c.url || ("https://nvd.nist.gov/vuln/detail/" + c.cve_id);
      const due = c.due_date ? (dueDays(c.due_date) < 0
        ? `<span class="pill overdue">overdue</span>` : fmtDate(c.due_date)) : "—";
      return `<tr class="${c.exploited ? "exploited" : ""}">
        <td class="cve"><a href="${esc(url)}" target="_blank" rel="noopener">${esc(c.cve_id)}</a></td>
        <td><span class="sevdot ${sevClass(c.severity)}"></span>${esc(c.severity || "—")}</td>
        <td>${c.base_score != null ? esc(c.base_score) : "—"}</td>
        <td>${c.exploited ? '<span class="pill yes">exploited</span>' : "—"}${c.ransomware ? ' <span class="pill ransom">ransom</span>' : ""}</td>
        <td>${due}</td>
        <td>${c.is_new ? '<span class="pill new">new</span>' : "—"}</td>
        <td>${esc((c.product_kinds || []).join(", ") || "—")}</td>
        <td>${esc(c.impact || "—")}</td></tr>`;
    }).join("");
  return `<table class="cvetable"><thead><tr><th>CVE</th><th>Severity</th><th>CVSS</th>
    <th>Exploited</th><th>KEV due</th><th>New</th><th>Affected</th><th>Impact</th></tr></thead>
    <tbody>${rows}</tbody></table>`;
}
function openDrawer({ patch: p, cves }) {
  const pr = p.priority || { score: 0, band: "low" };
  const drawer = $("#drawer");
  drawer.innerHTML = `
    <div class="drawer-head">
      <div class="dh-score b-${pr.band}" title="Remediation priority (P1 = act first)">
        <span class="dh-num">${pr.score}</span><span class="dh-band">${bandLabel(pr.band)}</span></div>
      <div class="dh-meta"><h2>${esc(p.title)}</h2>
        <div class="psub">${esc(SOURCE_LABEL[p.source] || p.source)} · ${esc(p.platform || "")} · released ${fmtDate(p.release_date)}</div></div>
      <button class="drawer-close" id="drawer-close" aria-label="Close">&times;</button>
    </div>
    <div class="drawer-body">
      <div class="pbadges">${patchBadges(p, true)}</div>
      <div class="section-title">Remediation</div>
      ${remediationHTML(p)}
      <div class="section-title">Vulnerabilities (${cves.length})</div>
      ${cveTable(cves)}
    </div>`;
  drawer.hidden = false;
  $("#overlay").hidden = false;
  document.body.style.overflow = "hidden";
  $("#drawer-close").addEventListener("click", closeDrawer);
}
function closeDrawer() {
  $("#drawer").hidden = true;
  $("#overlay").hidden = true;
  document.body.style.overflow = "";
}

/* ---------------- Export ---------------- */
function download(name, mime, content) {
  const url = URL.createObjectURL(new Blob([content], { type: mime }));
  const a = document.createElement("a");
  a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
const stamp = () => new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
const csvCell = (v) => { const s = v == null ? "" : String(v);
  return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
function exportCSV() {
  const head = ["priority", "band", "patch_id", "source", "platform", "patch_title",
    "release_date", "due_date", "cve_id", "severity", "cvss", "exploited",
    "ransomware", "new", "affected_kinds", "impact"];
  const lines = [head.join(",")];
  for (const { patch: p, cves } of state.results) {
    const pr = p.priority || {};
    for (const c of cves) lines.push([pr.score, pr.band, p.patch_id, p.source,
      p.platform, p.title, fmtDate(p.release_date), c.due_date || "", c.cve_id,
      c.severity || "", c.base_score != null ? c.base_score : "", c.exploited,
      c.ransomware, c.is_new, (c.product_kinds || []).join("|"), c.impact || ""]
      .map(csvCell).join(","));
  }
  download(`patch-tracker-${state.view}-${stamp()}.csv`, "text/csv", lines.join("\n") + "\n");
}
function exportJSON() {
  download(`patch-tracker-${state.view}-${stamp()}.json`, "application/json",
    JSON.stringify({ generated_at: state.data.generated_at, exported_at: new Date().toISOString(),
      view: state.view, filters: state.filters,
      patches: state.results.map(({ patch, cves }) => ({ ...patch, cves })) }, null, 2));
}
function exportHTML() {
  const sec = state.results.map(({ patch: p, cves }) => {
    const pr = p.priority || {};
    const rows = cves.map((c) => `<tr class="${c.exploited ? "x" : ""}"><td>${esc(c.cve_id)}</td>
      <td>${esc(c.severity || "—")}</td><td>${c.base_score != null ? esc(c.base_score) : "—"}</td>
      <td>${c.exploited ? "yes" : ""}</td><td>${c.due_date ? fmtDate(c.due_date) : ""}</td>
      <td>${c.is_new ? "new" : ""}</td><td>${esc((c.product_kinds || []).join(", ") || "—")}</td>
      <td>${esc(c.impact || "—")}</td></tr>`).join("");
    const rem = (p.remediation?.sections || []).map((s) =>
      `<p><b>${esc(s.audience)}</b></p><ul>${s.steps.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>`).join("");
    return `<h2>[${pr.score} ${pr.band}] ${esc(p.title)} <small>${esc(SOURCE_LABEL[p.source] || p.source)} ·
      ${esc(p.platform || "")} · ${fmtDate(p.release_date)}${p.due_date ? " · KEV due " + fmtDate(p.due_date) : ""}</small></h2>
      <p><b>${esc((p.remediation?.urgency || "").toUpperCase())}</b> — ${esc(p.remediation?.note || "")}</p>${rem}
      <table><thead><tr><th>CVE</th><th>Sev</th><th>CVSS</th><th>Exploited</th><th>KEV due</th>
      <th>New</th><th>Affected</th><th>Impact</th></tr></thead><tbody>${rows}</tbody></table>`;
  }).join("");
  download(`patch-tracker-${state.view}-${stamp()}.html`, "text/html",
    `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Patch Tracker — ${esc(state.view)}</title>
<style>body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:24px;color:#16202c}
h1{margin:0 0 4px}.meta{color:#667;font-size:14px;margin-bottom:18px}
h2{margin:22px 0 6px;font-size:16px;border-bottom:2px solid #e3e8ee;padding-bottom:4px}
h2 small{font-weight:400;color:#789;font-size:12px}ul{margin:4px 0 8px 18px}
table{border-collapse:collapse;width:100%;font-size:13px;margin:6px 0 8px}
th,td{border:1px solid #dce3ea;padding:5px 8px;text-align:left}th{background:#f3f6f9}tr.x{background:#fdecec}
</style></head><body><h1>Patch Tracker report — ${esc(state.view)}</h1>
<div class="meta">Generated ${esc(new Date().toUTCString())} · data updated ${esc(state.data.generated_at)} ·
${state.results.length} patches</div>${sec || "<p>No matches.</p>"}</body></html>`);
}

/* ---------------- Wire up ---------------- */
function wire() {
  const f = state.filters;
  const on = (id, ev, fn) => $(id).addEventListener(ev, fn);
  on("#search", "input", (e) => { f.q = e.target.value.trim().toLowerCase(); render(); });
  on("#cve", "input", (e) => { f.cve = e.target.value.trim().toLowerCase(); render(); });
  on("#affected", "change", (e) => { f.affected = e.target.value; render(); });
  on("#severity", "change", (e) => { f.minSev = sevRank(e.target.value); render(); });
  on("#cvss", "input", (e) => { f.minCvss = parseFloat(e.target.value) || 0; render(); });
  on("#exploited", "change", (e) => { f.exploited = e.target.checked; render(); });
  on("#newonly", "change", (e) => { f.newonly = e.target.checked; render(); });
  on("#sort", "change", (e) => { state.sort = e.target.value; render(); });
  on("#reset", "click", () => { resetFilters(); render(); });
  $("#sort").value = state.sort;   // reflect the default sort (release date)
  document.querySelectorAll("[data-export]").forEach((b) => b.addEventListener("click", () => {
    const k = b.dataset.export;
    if (k === "csv") exportCSV(); else if (k === "json") exportJSON(); else exportHTML();
  }));
  $("#overlay").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });
  window.addEventListener("hashchange", () => { initViewFromHash(); render(); });
}

load();
