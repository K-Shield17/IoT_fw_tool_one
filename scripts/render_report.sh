#!/usr/bin/env bash
set -euo pipefail
ROOTFS="$1"; CORRELATED="$2"; EVIDENCE="$3"; ASSETS="$4"; OUTDIR="$5"

# Order cases by analyst priority, then confidence.
jq '
  def sev: if .=="CRITICAL" then 4 elif .=="HIGH" then 3 elif .=="MEDIUM" then 2 elif .=="LOW" then 1 else 0 end;
  def conf: if .=="HIGH" then 3 elif .=="MEDIUM" then 2 else 1 end;
  .security_cases |= sort_by([-(.severity|sev),-(.confidence|conf),.asset,.title])
' "$CORRELATED" > "$OUTDIR/raw/correlated.sorted.json"

raw_count="$(wc -l < "$EVIDENCE" | tr -d ' ')"
asset_count="$(wc -l < "$ASSETS" | tr -d ' ')"

jq -n \
  --arg tool "IoT_fw_tool" --arg rootfs "$ROOTFS" --argjson raw_evidence "$raw_count" --argjson assets "$asset_count" \
  --slurpfile c "$OUTDIR/raw/correlated.sorted.json" \
  --slurpfile ev "$EVIDENCE" \
  --slurpfile as "$ASSETS" '
  ($c[0]) as $r |
  ($r.security_cases) as $cases |
  {
    tool:$tool,
    rootfs:$rootfs,
    summary:{
      overall_risk:(if any($cases[]?; .severity=="CRITICAL") then "CRITICAL" elif any($cases[]?; .severity=="HIGH") then "HIGH" elif any($cases[]?; .severity=="MEDIUM") then "MEDIUM" else "LOW" end),
      critical_cases:([$cases[]?|select(.severity=="CRITICAL")]|length),
      high_cases:([$cases[]?|select(.severity=="HIGH")]|length),
      medium_cases:([$cases[]?|select(.severity=="MEDIUM")]|length),
      security_cases:($cases|length),
      analyzed_assets:$assets,
      raw_evidence:$raw_evidence
    },
    security_cases:$cases,
    systemic_findings:$r.systemic_findings,
    informational:$r.informational,
    raw_evidence:$ev,
    assets:$as
  }' > "$OUTDIR/report.json"

# Analyst-oriented HTML. Priority cases are visible first; raw evidence is collapsed.
{
cat <<'HTML'
<!doctype html><html><head><meta charset="utf-8"><title>IoT Firmware Security Assessment</title>
<style>
:root{--bg:#f6f8fb;--card:#fff;--text:#182230;--muted:#5f6b7a;--border:#dfe5ec;--critical:#8f1224;--high:#b42318;--medium:#b54708;--low:#175cd3;--info:#475467}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 Arial,sans-serif}.wrap{max-width:1180px;margin:28px auto;padding:0 22px 60px}.header,.card{background:var(--card);border:1px solid var(--border);border-radius:12px}.header{padding:26px 30px}.header h1{margin:0 0 8px;font-size:28px}.muted{color:var(--muted)}.risk{font-weight:800;font-size:20px}.CRITICAL{color:var(--critical)}.HIGH{color:var(--high)}.MEDIUM{color:var(--medium)}.LOW{color:var(--low)}.INFO{color:var(--info)}
.metrics{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin:16px 0}.metric{background:#fff;border:1px solid var(--border);border-radius:10px;padding:13px}.metric b{font-size:20px;display:block}.section-title{margin:30px 0 12px;font-size:20px}.case{margin:12px 0;padding:22px 24px}.case-head{display:flex;justify-content:space-between;gap:20px;align-items:flex-start}.case h2{font-size:19px;margin:0 0 4px}.badges span{display:inline-block;border:1px solid var(--border);border-radius:99px;padding:3px 9px;margin-left:6px;font-size:12px;font-weight:700}.asset{font-family:monospace;background:#f2f4f7;padding:6px 8px;border-radius:6px;display:inline-block;margin:7px 0}.cols{display:grid;grid-template-columns:1fr 1fr;gap:18px}.box{background:#fafbfc;border:1px solid var(--border);border-radius:8px;padding:13px 15px}.box h3{margin:0 0 7px;font-size:14px}.evidence li,.remediation li,.impact li{margin:4px 0}table{border-collapse:collapse;width:100%;background:#fff}th,td{border-bottom:1px solid var(--border);padding:9px;text-align:left;vertical-align:top}th{background:#f8fafc}details{background:#fff;border:1px solid var(--border);border-radius:9px;padding:12px 15px;margin:9px 0}summary{cursor:pointer;font-weight:700}code{white-space:pre-wrap;word-break:break-word}.priority{font-weight:800;margin-right:8px}@media(max-width:800px){.metrics{grid-template-columns:repeat(2,1fr)}.cols{grid-template-columns:1fr}.case-head{display:block}.badges span{margin:4px 5px 0 0}}
</style></head><body><div class="wrap">
HTML
jq -r '
"<div class=\"header\"><h1>IoT Firmware Security Assessment</h1><div class=\"muted\">Static firmware analysis · RootFS: <code>\(.rootfs|@html)</code></div><p>Overall Risk: <span class=\"risk \(.summary.overall_risk)\">\(.summary.overall_risk)</span></p><p class=\"muted\">Security cases are created by correlating multiple static-analysis observations. Raw tool output is retained as evidence and is not automatically treated as a confirmed vulnerability.</p></div>"+
"<div class=\"metrics\">"+
"<div class=\"metric\"><span>Critical</span><b class=\"CRITICAL\">\(.summary.critical_cases)</b></div>"+
"<div class=\"metric\"><span>High</span><b class=\"HIGH\">\(.summary.high_cases)</b></div>"+
"<div class=\"metric\"><span>Medium</span><b class=\"MEDIUM\">\(.summary.medium_cases)</b></div>"+
"<div class=\"metric\"><span>Security cases</span><b>\(.summary.security_cases)</b></div>"+
"<div class=\"metric\"><span>Assets</span><b>\(.summary.analyzed_assets)</b></div>"+
"<div class=\"metric\"><span>Raw evidence</span><b>\(.summary.raw_evidence)</b></div></div>"+
"<h2 class=\"section-title\">Priority Security Cases</h2>"+
(if (.security_cases|length)==0 then "<div class=\"card case\">No correlated priority cases were generated from the current evidence.</div>" else
([.security_cases|to_entries[]| .key as $i | .value |
"<section class=\"card case\"><div class=\"case-head\"><div><h2><span class=\"priority\">P\($i+1)</span>\(.title|@html)</h2><div class=\"asset\">\(.asset|@html)</div></div><div class=\"badges\"><span class=\"\(.severity)\">Risk: \(.severity)</span><span>Confidence: \(.confidence)</span></div></div>"+
"<div class=\"cols\"><div class=\"box\"><h3>Why this matters</h3><div>\(.analysis|@html)</div></div><div class=\"box\"><h3>Attack scenario</h3><div>\(.attack_scenario|@html)</div></div></div>"+
"<div class=\"cols\" style=\"margin-top:12px\"><div class=\"box\"><h3>Potential impact</h3><ul class=\"impact\">"+([.potential_impact[]|"<li>\(.|@html)</li>"]|join(""))+"</ul></div>"+
"<div class=\"box\"><h3>Recommended remediation</h3><ol class=\"remediation\">"+([.remediation[]|"<li>\(.|@html)</li>"]|join(""))+"</ol></div></div>"+
"<details><summary>Evidence chain</summary><ul class=\"evidence\">"+([.evidence[]|"<li>\(.|@html)</li>"]|join(""))+"</ul></details></section>"
]|join("")) end)+
"<h2 class=\"section-title\">Systemic Findings</h2>"+
(if (.systemic_findings|length)==0 then "<div class=\"card case muted\">No systemic finding met the reporting threshold.</div>" else ([.systemic_findings[]|"<section class=\"card case\"><div class=\"case-head\"><h2>\(.title|@html)</h2><div class=\"badges\"><span class=\"\(.severity)\">Risk: \(.severity)</span><span>Confidence: \(.confidence)</span></div></div><p>\(.analysis|@html)</p><h3>Recommended remediation</h3><ul>"+([.remediation[]|"<li>\(.|@html)</li>"]|join(""))+"</ul></section>"]|join("")) end)+
"<h2 class=\"section-title\">Informational</h2>"+([.informational[]|"<section class=\"card case\"><h2>\(.title|@html)</h2><p>\(.analysis|@html)</p></section>"]|join(""))+
"<h2 class=\"section-title\">Evidence Appendix</h2>"+
"<details><summary>Show raw evidence (\(.summary.raw_evidence))</summary><table><tr><th>Source</th><th>Type</th><th>Asset</th><th>Observation</th></tr>"+
([.raw_evidence[]|"<tr><td>\(.source|@html)</td><td>\(.type|@html)</td><td><code>\(.asset|tostring|@html)</code></td><td><code>\(.value|tojson|@html)</code></td></tr>"]|join(""))+"</table></details>"' "$OUTDIR/report.json"
echo '</div></body></html>'
} > "$OUTDIR/report.html"
