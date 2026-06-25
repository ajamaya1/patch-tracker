# Flattening + HTML report. The HTML is self-contained (data inlined) and ships
# the same theme switcher as the TUI vibe: dark, retro CRT, amber, light.

function ConvertTo-IaFlatRows {
    param([object[]]$Items)
    foreach ($it in $Items) {
        if (-not $it.Assignments) {
            [pscustomobject]@{ area = $it.Area; resource_type = $it.ResourceType; resource_name = $it.Name
                platform = $it.Platform; target = '(unassigned)'; target_kind = ''; group_name = ''
                exclude = $false; intent = ''; filter = ''; filter_type = '' }
            continue
        }
        foreach ($a in $it.Assignments) {
            $t = $a.Target
            [pscustomobject]@{
                area = $it.Area; resource_type = $it.ResourceType; resource_name = $it.Name; platform = $it.Platform
                target = (Get-IaTargetDisplay -Target $t); target_kind = $t.Kind
                group_name = $t.GroupName; exclude = $t.IsExclude; intent = $a.Intent
                filter = $t.FilterName; filter_type = $(if ($t.FilterId) { $t.FilterType } else { '' })
            }
        }
    }
}

function New-IaHtmlReport {
    param([object[]]$Items, [string]$Title = 'Intune Assignments')
    $rows = @(ConvertTo-IaFlatRows -Items $Items)
    $assigned = @($Items | Where-Object { $_.Assignments.Count -gt 0 }).Count
    $edges = @($Items | ForEach-Object { $_.Assignments }).Count
    $groups = @($Items | ForEach-Object { $_.Assignments } | ForEach-Object { $_.Target.GroupId } | Where-Object { $_ } | Select-Object -Unique).Count
    $kpis = @(
        @{ l = 'Resources'; n = $Items.Count }, @{ l = 'Assigned'; n = $assigned }
        @{ l = 'Unassigned'; n = ($Items.Count - $assigned) }, @{ l = 'Edges'; n = $edges }
        @{ l = 'Groups'; n = $groups }
    )
    $kpiHtml = ($kpis | ForEach-Object { "<div class='kpi'><div class='n'>$($_.n)</div><div class='l'>$($_.l)</div></div>" }) -join ''
    $data = ($rows | ConvertTo-Json -Depth 5 -Compress)
    if ($rows.Count -le 1) { $data = "[$data]" }  # ConvertTo-Json unwraps single element

    $tpl = Get-IaHtmlTemplate
    $tpl.Replace('__TITLE__', [System.Net.WebUtility]::HtmlEncode($Title)).Replace('__KPIS__', $kpiHtml).Replace('__DATA__', $data)
}

function Get-IaHtmlTemplate {
    @'
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>__TITLE__</title>
<style>
:root{--bg:#0b1220;--panel:#121a2b;--panel2:#0f1726;--line:#22304b;--text:#e6edf7;
  --muted:#8a9ac0;--accent:#3b82f6;--inc:#7ee2a8;--exc:#ff89ab;--virtual:#ffd479;--chip:#1b2a44}
body[data-theme=retro]{--bg:#020a02;--panel:#04140a;--panel2:#020d05;--line:#0c5a22;--text:#39ff6a;
  --muted:#1f9c47;--accent:#7dffae;--inc:#9dffc0;--exc:#ff8d8d;--chip:#062611;font-family:ui-monospace,Courier New,monospace}
body[data-theme=amber]{--bg:#0a0600;--panel:#170f02;--panel2:#0d0800;--line:#5a3a0c;--text:#ffb000;
  --muted:#9c6b1f;--accent:#ffd479;--inc:#ffe6a8;--exc:#ff9d7d;--chip:#241607;font-family:ui-monospace,Courier New,monospace}
body[data-theme=light]{--bg:#f3f5f9;--panel:#fff;--panel2:#eef2f8;--line:#d6deea;--text:#1b2434;
  --muted:#5b6678;--accent:#2563eb;--inc:#197a43;--exc:#c01244;--chip:#eaf0fb}
body[data-theme=deepsea]{--bg:#02101e;--panel:#06223a;--panel2:#041a30;--line:#0d3a55;--text:#d6f0f6;
  --muted:#6fa8bd;--accent:#5fe2dc;--inc:#6ee2a8;--exc:#ff8c78;--virtual:#ffd479;--chip:#06283f;
  background-image:radial-gradient(circle at 18% 30%,rgba(60,170,200,.10),transparent 40%),radial-gradient(circle at 80% 70%,rgba(40,120,170,.10),transparent 40%)}
body[data-theme=deepsea] header{background:linear-gradient(180deg,#08263f,#02101e);border-bottom:1px solid #0d3a55}
body[data-theme=deepsea] th{background:#06283f;color:#9fe8e2}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
  font:14px/1.5 -apple-system,Segoe UI,Roboto,Arial,sans-serif}
header{padding:18px 22px;border-bottom:1px solid var(--line)}
h1{margin:0;font-size:18px} .sub{color:var(--muted);font-size:12px;margin-top:3px}
.kpis{display:flex;gap:12px;flex-wrap:wrap;padding:14px 22px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:10px 16px;min-width:110px}
.kpi .n{font-size:21px;font-weight:700}.kpi .l{color:var(--muted);font-size:11px;text-transform:uppercase}
.controls{display:flex;gap:10px;flex-wrap:wrap;padding:0 22px 14px;align-items:center}
input,select{background:var(--panel2);border:1px solid var(--line);color:var(--text);border-radius:8px;padding:9px 12px;font-size:13px}
.count{color:var(--muted);font-size:12px;margin-left:auto}.wrap{padding:0 22px 40px}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:9px;overflow:hidden}
th,td{text-align:left;padding:9px 13px;border-bottom:1px solid var(--line)}
th{position:sticky;top:0;background:var(--panel2);font-size:11px;text-transform:uppercase;color:var(--muted);cursor:pointer}
tr:hover td{background:#80808015}.chip{background:var(--chip);border:1px solid var(--line);border-radius:999px;padding:2px 9px;font-size:11px}
.inc{color:var(--inc)}.exc{color:var(--exc);font-weight:600}.virtual{color:var(--virtual)}.muted{color:var(--muted)}
/* ---- Lego: studded bricks on a baseplate ---- */
body[data-theme=lego]{--bg:#1b2030;--panel:#2a3147;--panel2:#222a40;--line:#0f1320;--text:#f4f7ff;--muted:#aeb7cc;--accent:#f5c518;--inc:#3cba54;--exc:#e8442a;--virtual:#2f80ed;--chip:#0c1020;font-family:Verdana,Segoe UI,Tahoma,sans-serif;background-image:radial-gradient(circle at center,#2b3350 5px,transparent 6px);background-size:36px 36px}
body[data-theme=lego] header{background:#f5c518;border-bottom:7px solid #c08f00}
body[data-theme=lego] h1,body[data-theme=lego] .sub{color:#1b2030}
body[data-theme=lego] .kpi{position:relative;border:none;border-radius:5px 5px 9px 9px;color:#fff;box-shadow:inset 0 -6px 0 rgba(0,0,0,.28),0 3px 0 rgba(0,0,0,.35);margin-top:12px}
body[data-theme=lego] .kpi .l{color:rgba(255,255,255,.85)}
body[data-theme=lego] .kpi::before{content:"";position:absolute;top:-9px;left:12px;right:12px;height:13px;background:radial-gradient(circle at 11px 7px,rgba(255,255,255,.45) 6px,transparent 7px);background-size:30px 13px;background-repeat:repeat-x}
body[data-theme=lego] .kpi:nth-child(5n+1){background:#e8442a}
body[data-theme=lego] .kpi:nth-child(5n+2){background:#3cba54}
body[data-theme=lego] .kpi:nth-child(5n+3){background:#2f80ed}
body[data-theme=lego] .kpi:nth-child(5n+4){background:#f5c518;color:#1b2030}
body[data-theme=lego] .kpi:nth-child(5n+4) .l{color:rgba(27,32,48,.8)}
body[data-theme=lego] .kpi:nth-child(5n){background:#e07b1a}
body[data-theme=lego] .chip{border-radius:4px;border:none;color:#fff;font-weight:700;box-shadow:inset 0 -3px 0 rgba(0,0,0,.3)}
body[data-theme=lego] td:first-child .chip{background:#2f80ed}
body[data-theme=lego] tr:nth-child(3n) td:first-child .chip{background:#3cba54}
body[data-theme=lego] tr:nth-child(3n+1) td:first-child .chip{background:#e8442a}
body[data-theme=lego] table{border:3px solid #0f1320;border-radius:8px}
body[data-theme=lego] th{background:#f5c518;color:#1b2030;font-weight:800}
</style></head><body data-theme="dark">
<header><h1>__TITLE__</h1><div class="sub">Generated by TIDE · static report</div></header>
<div class="kpis">__KPIS__</div>
<div class="controls">
  <input type="search" id="q" placeholder="Search resource, group, filter…">
  <select id="area"><option value="">All areas</option></select>
  <select id="theme"><option value="dark">Dark</option><option value="retro">Retro CRT</option>
    <option value="amber">Amber</option><option value="deepsea">Deep Sea</option><option value="lego">Lego</option><option value="light">Light</option></select>
  <span class="count" id="count"></span>
</div>
<div class="wrap"><table id="t"><thead><tr>
  <th data-k="area">Area</th><th data-k="resource_name">Resource</th><th data-k="platform">Platform</th>
  <th data-k="target">Assigned to</th><th data-k="intent">Intent</th><th data-k="filter">Filter</th>
</tr></thead><tbody id="tb"></tbody></table></div>
<script>
const DATA=__DATA__;const tb=document.getElementById('tb'),q=document.getElementById('q'),
 areaSel=document.getElementById('area'),themeSel=document.getElementById('theme'),countEl=document.getElementById('count');
[...new Set(DATA.map(r=>r.area))].sort().forEach(a=>{const o=document.createElement('option');o.value=a;o.textContent=a;areaSel.appendChild(o)});
let sk='area',sd=1;
function esc(s){return(s==null?'':''+s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
function render(){const term=q.value.toLowerCase(),area=areaSel.value;
 let rows=DATA.filter(r=>(!area||r.area===area)&&(!term||[r.resource_name,r.group_name,r.target,r.filter,r.area].join(' ').toLowerCase().includes(term)));
 rows.sort((a,b)=>(''+a[sk]).localeCompare(''+b[sk])*sd);
 tb.innerHTML=rows.map(r=>{let c=r.exclude?'exc':(['allUsers','allDevices'].includes(r.target_kind)?'virtual':'inc');
  let t=r.target==='(unassigned)'?'<span class=muted>unassigned</span>':`<span class=${c}>${esc(r.target)}</span>`;
  return `<tr><td><span class=chip>${esc(r.area)}</span></td><td>${esc(r.resource_name)}</td><td class=muted>${esc(r.platform)}</td><td>${t}</td><td>${esc(r.intent)}</td><td class=muted>${esc(r.filter)}</td></tr>`}).join('');
 countEl.textContent=rows.length+' row(s)'}
document.querySelectorAll('th').forEach(th=>th.onclick=()=>{const k=th.dataset.k;sd=(k===sk)?-sd:1;sk=k;render()});
themeSel.onchange=()=>document.body.dataset.theme=themeSel.value;
q.oninput=areaSel.onchange=render;render();
</script></body></html>
'@
}
