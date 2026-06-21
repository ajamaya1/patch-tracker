"use strict";

// Static dashboard: load the JSON dataset generated daily by the GitHub
// Actions workflow and render a filterable view of patches and their CVEs.

const state = {
  data: null,
  filters: { q: "", source: "", severity: "", exploited: false, newonly: false },
};

const $ = (sel) => document.querySelector(sel);

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function fmtDate(s) {
  return s ? String(s).slice(0, 10) : "—";
}

function sevClass(sev) {
  const s = (sev || "").toLowerCase();
  if (s.includes("crit")) return "sev-critical";
  if (s.includes("import") || s === "high") return "sev-important";
  if (s.includes("moder") || s === "medium") return "sev-moderate";
  if (s.includes("low")) return "sev-low";
  return "sev-low";
}

async function load() {
  try {
    const resp = await fetch("data.json?t=" + Date.now(), { cache: "no-store" });
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    state.data = await resp.json();
  } catch (err) {
    $("#updated").textContent = "Failed to load data.json";
    $("#list").innerHTML =
      '<p class="empty">Could not load <code>data.json</code>. ' +
      "Run <code>patch-tracker build-site</code> or wait for the daily " +
      "GitHub Action.</p>";
    return;
  }
  renderHeader();
  renderStats();
  render();
}

function renderHeader() {
  const d = state.data;
  const when = d.generated_at ? new Date(d.generated_at) : null;
  $("#updated").textContent = when
    ? "Updated " + when.toUTCString()
    : "Updated —";
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
  $("#stats").innerHTML =
    statCard(s.total_patches, "Patches") +
    statCard(s.total_cves, "CVEs") +
    statCard(s.exploited_cves || 0, "Exploited", "alert") +
    statCard(s.new_cves || 0, `New (${state.data.new_window_days}d)`, "new") +
    statCard(bySrc.apple || 0, "Apple") +
    statCard(bySrc.microsoft || 0, "Microsoft");
}

function matches(patch) {
  const f = state.filters;
  if (f.source && patch.source !== f.source) return false;
  if (f.severity && (patch.severity || "").toLowerCase() !== f.severity)
    return false;
  if (f.exploited && !patch.exploited_count) return false;
  if (f.newonly && !patch.new_count) return false;
  if (f.q) {
    const hay = (
      patch.title + " " + (patch.product || "") + " " + patch.patch_id + " " +
      patch.cves.map((c) => c.cve_id).join(" ")
    ).toLowerCase();
    if (!hay.includes(f.q)) return false;
  }
  return true;
}

function patchBadges(p) {
  let b = `<span class="badge src-${esc(p.source)}">${esc(p.source)}</span>`;
  if (p.severity)
    b += `<span class="badge ${sevClass(p.severity)}">${esc(p.severity)}</span>`;
  if (p.exploited_count)
    b += `<span class="badge exploit">⚠ ${p.exploited_count} exploited</span>`;
  if (p.new_count)
    b += `<span class="badge new">${p.new_count} new</span>`;
  if (p.patch_tuesday)
    b += `<span class="badge ptues">Patch Tuesday ${fmtDate(p.patch_tuesday)}</span>`;
  return b;
}

function cveRows(p) {
  return p.cves
    .slice()
    .sort((a, b) => (b.exploited - a.exploited) || (b.is_new - a.is_new))
    .map((c) => {
      const cveUrl = c.url || ("https://nvd.nist.gov/vuln/detail/" + c.cve_id);
      return `<tr class="${c.exploited ? "exploited" : ""}">` +
        `<td class="cve"><a href="${esc(cveUrl)}" target="_blank" rel="noopener">${esc(c.cve_id)}</a></td>` +
        `<td>${esc(c.severity || "—")}</td>` +
        `<td>${c.base_score != null ? esc(c.base_score) : "—"}</td>` +
        `<td>${esc(c.impact || "—")}</td>` +
        `<td>${c.exploited ? '<span class="pill yes">exploited</span>' : "—"}</td>` +
        `<td>${c.is_new ? '<span class="pill new">new</span>' : "—"}</td>` +
        `</tr>`;
    })
    .join("");
}

function render() {
  const list = $("#list");
  const visible = state.data.patches.filter(matches);
  $("#resultcount").textContent =
    `${visible.length} of ${state.data.patches.length} patches`;
  $("#empty").hidden = visible.length !== 0;

  list.innerHTML = visible.map((p, i) => {
    const sub = [
      p.product, p.version, "released " + fmtDate(p.release_date),
      p.cve_count + " CVEs",
    ].filter(Boolean).join(" · ");
    return `<div class="patch" data-i="${i}">
      <div class="patch-head">
        <span class="chev">▶</span>
        <span class="patch-title">${esc(p.title)}
          <span class="patch-sub">${esc(sub)}</span></span>
        ${patchBadges(p)}
      </div>
      <div class="cves">
        <table>
          <thead><tr><th>CVE</th><th>Severity</th><th>CVSS</th>
            <th>Impact</th><th>Exploited</th><th>New</th></tr></thead>
          <tbody>${cveRows(p)}</tbody>
        </table>
      </div>
    </div>`;
  }).join("");

  // Keep a parallel list so click handlers map back to filtered patches.
  list.querySelectorAll(".patch-head").forEach((head) => {
    head.addEventListener("click", () =>
      head.parentElement.classList.toggle("open"));
  });
}

function wireControls() {
  const f = state.filters;
  $("#search").addEventListener("input", (e) => {
    f.q = e.target.value.trim().toLowerCase();
    render();
  });
  $("#source").addEventListener("change", (e) => {
    f.source = e.target.value; render();
  });
  $("#severity").addEventListener("change", (e) => {
    f.severity = e.target.value; render();
  });
  $("#exploited").addEventListener("change", (e) => {
    f.exploited = e.target.checked; render();
  });
  $("#newonly").addEventListener("change", (e) => {
    f.newonly = e.target.checked; render();
  });
}

wireControls();
load();
