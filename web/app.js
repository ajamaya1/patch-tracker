"use strict";

// Static dashboard: load the JSON dataset generated daily by the GitHub
// Actions workflow and render a filterable view of patches, CVEs, affected
// products, Windows servicing info and remediation guidance, with client-side
// export of the current filtered view.

const SEV_RANK = { critical: 4, important: 3, high: 3, moderate: 2,
  medium: 2, low: 1 };
const SOURCE_LABEL = { apple: "Apple", microsoft: "Microsoft",
  "cisa-kev": "Third-party (KEV)" };

const state = {
  data: null,
  filters: {
    q: "", cve: "", source: "", platform: "", affected: "", minSev: 0,
    minCvss: 0, exploited: false, newonly: false,
  },
  view: [],
};

const $ = (s) => document.querySelector(s);

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}
const fmtDate = (s) => (s ? String(s).slice(0, 10) : "—");
const sevRank = (sev) => SEV_RANK[(sev || "").toLowerCase()] || 0;
function sevClass(sev) {
  const r = sevRank(sev);
  return r >= 4 ? "sev-critical" : r === 3 ? "sev-important"
    : r === 2 ? "sev-moderate" : "sev-low";
}

async function load() {
  try {
    const resp = await fetch("data.json?t=" + Date.now(), { cache: "no-store" });
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    state.data = await resp.json();
  } catch (err) {
    $("#updated").textContent = "Failed to load data.json";
    $("#list").innerHTML =
      '<p class="empty">Could not load <code>data.json</code>. Run ' +
      "<code>patch-tracker build-site</code> or wait for the daily Action.</p>";
    return;
  }
  renderHeader();
  renderStats();
  populatePlatforms();
  render();
}

function renderHeader() {
  const d = state.data;
  const when = d.generated_at ? new Date(d.generated_at) : null;
  $("#updated").textContent = when ? "Updated " + when.toUTCString() : "Updated —";
  $("#footer-meta").textContent =
    `${d.patches.length} patches · new window ${d.new_window_days}d`;
}

function statCard(num, label, cls) {
  return `<div class="card ${cls || ""}"><div class="num">${num}</div>` +
    `<div class="label">${label}</div></div>`;
}

function renderStats() {
  const s = state.data.stats;
  const bySrc = s.by_source || {};
  const kind = s.by_product_kind || {};
  let html =
    statCard(s.total_patches, "Patches") +
    statCard(s.total_cves, "CVEs") +
    statCard(s.exploited_cves || 0, "Exploited", "alert") +
    statCard(s.new_cves || 0, `New (${state.data.new_window_days}d)`, "new");
  if (bySrc["cisa-kev"])
    html += statCard(bySrc["cisa-kev"], "Third-party zero-days", "alert");
  if (kind.client) html += statCard(kind.client, "Win client CVEs");
  if (kind.server) html += statCard(kind.server, "Win server CVEs");
  html += statCard(bySrc.apple || 0, "Apple");
  html += statCard(bySrc.microsoft || 0, "Microsoft");
  $("#stats").innerHTML = html;
}

function populatePlatforms() {
  const platforms = [...new Set(state.data.patches.map((p) => p.platform)
    .filter(Boolean))].sort();
  const sel = $("#platform");
  for (const pl of platforms) {
    const o = document.createElement("option");
    o.value = pl; o.textContent = pl;
    sel.appendChild(o);
  }
}

function cveFiltersActive() {
  const f = state.filters;
  return !!(f.cve || f.minSev || f.minCvss || f.exploited || f.newonly ||
    f.affected);
}

function cveMatches(c) {
  const f = state.filters;
  if (f.cve && !c.cve_id.toLowerCase().includes(f.cve)) return false;
  if (f.minSev && sevRank(c.severity) < f.minSev) return false;
  if (f.minCvss && !(c.base_score != null && c.base_score >= f.minCvss))
    return false;
  if (f.exploited && !c.exploited) return false;
  if (f.newonly && !c.is_new) return false;
  if (f.affected && !(c.product_kinds || []).includes(f.affected)) return false;
  return true;
}

function patchMatches(p) {
  const f = state.filters;
  if (f.source && p.source !== f.source) return false;
  if (f.platform && p.platform !== f.platform) return false;
  if (f.affected && !(p.affected && p.affected[f.affected])) return false;
  if (f.q) {
    const hay = (p.title + " " + (p.product || "") + " " + p.patch_id)
      .toLowerCase();
    if (!hay.includes(f.q)) return false;
  }
  return true;
}

function computeView() {
  const active = cveFiltersActive();
  const out = [];
  for (const p of state.data.patches) {
    if (!patchMatches(p)) continue;
    const cves = active ? p.cves.filter(cveMatches) : p.cves;
    if (active && cves.length === 0) continue;
    out.push({ patch: p, cves });
  }
  state.view = out;
  return out;
}

function patchBadges(p) {
  let b = `<span class="badge src-${esc(p.source)}">${esc(SOURCE_LABEL[p.source] || p.source)}</span>`;
  if (p.platform)
    b += `<span class="badge platform">${esc(p.platform)}</span>`;
  if (p.severity)
    b += `<span class="badge ${sevClass(p.severity)}">${esc(p.severity)}</span>`;
  if (p.exploited_count)
    b += `<span class="badge exploit">⚠ ${p.exploited_count} exploited</span>`;
  if (p.new_count)
    b += `<span class="badge new">${p.new_count} new</span>`;
  const a = p.affected || {};
  if (a.client) b += `<span class="badge kind">💻 ${a.client} client</span>`;
  if (a.server) b += `<span class="badge kind">🖥️ ${a.server} server</span>`;
  if (p.patch_tuesday)
    b += `<span class="badge ptues">Patch Tuesday ${fmtDate(p.patch_tuesday)}</span>`;
  if (p.servicing) {
    const hp = p.servicing.hotpatch || {};
    const cls = hp.is_hotpatch_month ? "hotpatch" : "cumulative";
    const txt = hp.is_hotpatch_month ? "Hotpatch · no reboot" : "Cumulative · reboot";
    b += `<span class="badge ${cls}" title="${esc(hp.note || "")}">${esc(p.servicing.channel)}-release · ${txt}</span>`;
  }
  return b;
}

function remediationHTML(p) {
  const r = p.remediation;
  if (!r) return "";
  let h = `<div class="rem rem-${esc(r.urgency)}">`;
  h += `<div class="rem-head"><span class="rem-urgency ${esc(r.urgency)}">${esc((r.urgency || "").toUpperCase())}</span>`
    + ` <span>${esc(r.note)}</span></div>`;
  h += `<p class="rem-summary">${esc(r.summary)}</p>`;
  if (p.servicing) {
    const sv = p.servicing, hp = sv.hotpatch || {};
    h += `<div class="rem-servicing"><b>Windows servicing:</b> ${esc(sv.channel_label)}.
      <b>${esc(hp.update_type)}</b> — ${esc(hp.note)}
      <span class="muted">Eligible: ${esc(sv.eligible_skus)}. ${esc(sv.preview_note)}</span></div>`;
  }
  for (const sec of r.sections || []) {
    h += `<div class="rem-sec"><div class="aud">${esc(sec.icon || "")} ${esc(sec.audience)}</div><ul>`;
    for (const step of sec.steps || []) h += `<li>${esc(step)}</li>`;
    h += `</ul></div>`;
  }
  if (r.links && r.links.length) {
    h += `<div class="rem-links">` + r.links.map((l) =>
      `<a class="btn btn-link" href="${esc(l.url)}" target="_blank" rel="noopener">${esc(l.label)} ↗</a>`)
      .join("") + `</div>`;
  }
  return h + `</div>`;
}

function cveRows(cves) {
  return cves.slice().sort((a, b) =>
    (b.exploited - a.exploited) || (b.is_new - a.is_new) ||
    (sevRank(b.severity) - sevRank(a.severity)))
    .map((c) => {
      const url = c.url || ("https://nvd.nist.gov/vuln/detail/" + c.cve_id);
      const kinds = (c.product_kinds || []).join(", ") || "—";
      return `<tr class="${c.exploited ? "exploited" : ""}">` +
        `<td class="cve"><a href="${esc(url)}" target="_blank" rel="noopener">${esc(c.cve_id)}</a></td>` +
        `<td>${esc(c.severity || "—")}</td>` +
        `<td>${c.base_score != null ? esc(c.base_score) : "—"}</td>` +
        `<td>${esc(c.impact || "—")}</td>` +
        `<td>${c.exploited ? '<span class="pill yes">exploited</span>' : "—"}</td>` +
        `<td>${c.is_new ? '<span class="pill new">new</span>' : "—"}</td>` +
        `<td>${esc(kinds)}</td></tr>`;
    }).join("");
}

function render() {
  const view = computeView();
  const list = $("#list");
  const shownCves = view.reduce((n, v) => n + v.cves.length, 0);
  $("#resultcount").textContent =
    `${view.length} of ${state.data.patches.length} patches · ${shownCves} CVEs shown`;
  $("#empty").hidden = view.length !== 0;
  const filtered = cveFiltersActive();

  list.innerHTML = view.map(({ patch: p, cves }) => {
    const cveLabel = filtered && cves.length !== p.cve_count
      ? `${cves.length} of ${p.cve_count} CVEs` : `${p.cve_count} CVEs`;
    const sub = [p.product, p.version, "released " + fmtDate(p.release_date),
      cveLabel].filter(Boolean).join(" · ");
    return `<div class="patch${filtered ? " open" : ""}">
      <div class="patch-head">
        <span class="chev">▶</span>
        <span class="patch-title">${esc(p.title)}
          <span class="patch-sub">${esc(sub)}</span></span>
        ${patchBadges(p)}
      </div>
      <div class="cves">
        ${remediationHTML(p)}
        <table>
          <thead><tr><th>CVE</th><th>Severity</th><th>CVSS</th>
            <th>Impact</th><th>Exploited</th><th>New</th>
            <th>Affected</th></tr></thead>
          <tbody>${cveRows(cves)}</tbody>
        </table>
      </div>
    </div>`;
  }).join("");

  list.querySelectorAll(".patch-head").forEach((head) => {
    head.addEventListener("click", () =>
      head.parentElement.classList.toggle("open"));
  });
}

/* ---------------------------- Export ---------------------------- */

function download(filename, mime, content) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
const stamp = () => new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
function csvCell(v) {
  const s = v == null ? "" : String(v);
  return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

function exportCSV() {
  const head = ["patch_id", "source", "platform", "patch_title", "release_date",
    "patch_tuesday", "servicing", "patch_severity", "cve_id", "cve_severity",
    "cvss", "exploited", "new", "affected_kinds", "impact", "first_seen"];
  const lines = [head.join(",")];
  for (const { patch: p, cves } of state.view) {
    const sv = p.servicing ? (p.servicing.hotpatch || {}).update_type : "";
    for (const c of cves) {
      lines.push([p.patch_id, p.source, p.platform, p.title,
        fmtDate(p.release_date), p.patch_tuesday || "", sv, p.severity || "",
        c.cve_id, c.severity || "", c.base_score != null ? c.base_score : "",
        c.exploited, c.is_new, (c.product_kinds || []).join("|"),
        c.impact || "", c.first_seen || ""].map(csvCell).join(","));
    }
  }
  download(`patch-tracker-${stamp()}.csv`, "text/csv", lines.join("\n") + "\n");
}

function exportJSON() {
  const payload = {
    generated_at: state.data.generated_at,
    exported_at: new Date().toISOString(),
    filters: state.filters,
    patches: state.view.map(({ patch, cves }) => ({ ...patch, cves })),
  };
  download(`patch-tracker-${stamp()}.json`, "application/json",
    JSON.stringify(payload, null, 2));
}

function exportHTML() {
  const sections = state.view.map(({ patch: p, cves }) => {
    const rem = p.remediation ? remediationHTML(p) : "";
    const rows = cves.map((c) => `<tr class="${c.exploited ? "x" : ""}">
      <td>${esc(c.cve_id)}</td><td>${esc(c.severity || "—")}</td>
      <td>${c.base_score != null ? esc(c.base_score) : "—"}</td>
      <td>${esc(c.impact || "—")}</td><td>${c.exploited ? "yes" : ""}</td>
      <td>${c.is_new ? "new" : ""}</td>
      <td>${esc((c.product_kinds || []).join(", ") || "—")}</td></tr>`).join("");
    return `<h2>${esc(p.title)} <small>${esc(SOURCE_LABEL[p.source] || p.source)}
      · ${esc(p.platform || "")} · ${fmtDate(p.release_date)}</small></h2>
      ${rem}
      <table><thead><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Impact</th>
      <th>Exploited</th><th>New</th><th>Affected</th></tr></thead>
      <tbody>${rows}</tbody></table>`;
  }).join("");
  const doc = `<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Patch Tracker report ${stamp()}</title><style>
body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:24px;color:#16202c}
h1{margin:0 0 4px} .meta{color:#667;margin-bottom:18px;font-size:14px}
h2{margin:22px 0 6px;font-size:16px;border-bottom:2px solid #e3e8ee;padding-bottom:4px}
h2 small{font-weight:400;color:#789;font-size:12px}
.rem{border-left:4px solid #888;background:#f7f9fb;padding:8px 12px;margin:8px 0;border-radius:4px;font-size:13px}
.rem-critical{border-color:#d23;background:#fdecec}.rem-high{border-color:#e8910c;background:#fff6e8}
.rem .aud{font-weight:600;margin:6px 0 2px}.rem ul{margin:2px 0 8px 18px}
.rem-urgency{font-weight:700}.rem-servicing{margin:4px 0;font-size:12px}
.rem-links a{margin-right:8px} .muted{color:#789}
table{border-collapse:collapse;width:100%;font-size:13px;margin-bottom:8px}
th,td{border:1px solid #dce3ea;padding:5px 8px;text-align:left}
th{background:#f3f6f9} tr.x{background:#fdecec}
</style></head><body>
<h1>🛡️ Patch Tracker report</h1>
<div class="meta">Generated ${esc(new Date().toUTCString())} · data updated
  ${esc(state.data.generated_at)} · ${state.view.length} patches ·
  ${state.view.reduce((n, v) => n + v.cves.length, 0)} CVEs</div>
${sections || "<p>No patches match the current filters.</p>"}
</body></html>`;
  download(`patch-tracker-${stamp()}.html`, "text/html", doc);
}

/* ---------------------------- Controls ---------------------------- */

function wireControls() {
  const f = state.filters;
  const on = (id, ev, fn) => $(id).addEventListener(ev, fn);
  on("#search", "input", (e) => { f.q = e.target.value.trim().toLowerCase(); render(); });
  on("#cve", "input", (e) => { f.cve = e.target.value.trim().toLowerCase(); render(); });
  on("#source", "change", (e) => { f.source = e.target.value; render(); });
  on("#platform", "change", (e) => { f.platform = e.target.value; render(); });
  on("#affected", "change", (e) => { f.affected = e.target.value; render(); });
  on("#severity", "change", (e) => { f.minSev = sevRank(e.target.value); render(); });
  on("#cvss", "input", (e) => { f.minCvss = parseFloat(e.target.value) || 0; render(); });
  on("#exploited", "change", (e) => { f.exploited = e.target.checked; render(); });
  on("#newonly", "change", (e) => { f.newonly = e.target.checked; render(); });
  on("#reset", "click", () => {
    Object.assign(f, { q: "", cve: "", source: "", platform: "", affected: "",
      minSev: 0, minCvss: 0, exploited: false, newonly: false });
    for (const el of document.querySelectorAll(".controls input, .controls select")) {
      if (el.type === "checkbox") el.checked = false; else el.value = "";
    }
    render();
  });
  document.querySelectorAll("[data-export]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const k = btn.getAttribute("data-export");
      if (k === "csv") exportCSV(); else if (k === "json") exportJSON();
      else if (k === "html") exportHTML();
    });
  });
}

wireControls();
load();
