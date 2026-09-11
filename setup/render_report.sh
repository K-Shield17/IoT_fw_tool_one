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
# => 한국어 보고서 스타일로 교체 + 점검 일자는 시스템 시간 자동 사용
{
cat <<'HTML'
<!doctype html><html lang="ko"><head><meta charset="utf-8"><title>IoT 펌웨어 보안 점검 보고서</title><style>
body{font-family:'Malgun Gothic','Noto Sans KR',Arial,sans-serif;color:#172033;margin:0;background:#f4f6f8}
.page{max-width:980px;margin:24px auto;background:#fff;padding:44px 54px;box-shadow:0 2px 14px #0001}
h1{font-size:28px;margin:0 0 10px} h2{font-size:20px;margin-top:34px;border-bottom:2px solid #dbe3f6;padding-bottom:8px}
h3{font-size:15px;margin-top:24px}.muted{color:#667085}.badge{display:inline-block;padding:4px 9px;border-radius:999px;background:#eef2ff;color:#3730a3;font-weight:700}
table{width:100%;border-collapse:collapse;margin:12px 0 20px;font-size:13px}th,td{border:1px solid #e5e7eb;padding:9px;text-align:left;vertical-align:top}th{background:#f3f5f9}
.callout{background:#f8faff;border-left:4px solid #274690;padding:13px 15px;margin:14px 0}.warn{background:#fff8eb;border-left-color:#f79009}
.high{color:#b42318;font-weight:700}.medium{color:#b54708;font-weight:700}.low{color:#175cd3;font-weight:700}
code{font-family:Consolas,monospace}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}.card{border:1px solid #e5e7eb;border-radius:10px;padding:13px}
.small{font-size:12px}.footer{margin-top:35px;border-top:1px solid #e5e7eb;padding-top:10px;color:#667085;font-size:11px}
</style></head><body>
<div class="page">
<span class="badge">IoT_fw_tool 자동 생성 보고서</span>
<h1>IoT 펌웨어 보안 점검 보고서</h1>
<p class="muted">IoT_fw_tool · Firmware Security Checkup</p>
<div class="callout"><b>보고서 목적</b><br>펌웨어 정적 점검 결과를 점검 기준·Attack Vector·취약점 상세·조치방안·침해사고 대응 관점으로 구조화한 보고서입니다.</div>
HTML

jq -r \
  --arg inspection_date "$(date '+%Y-%m-%d')" '
def esc: @html;

def risk_class:
  if . == "CRITICAL" then "high"
  elif . == "HIGH" then "high"
  elif . == "MEDIUM" then "medium"
  elif . == "LOW" then "low"
  else "low" end;

"<h2>1. 점검 개요</h2>
<table>
<tr><th>점검 대상</th><td>\(.rootfs|esc)</td><th>점검 일자</th><td>\($inspection_date|esc)</td></tr>
<tr><th>점검 도구</th><td colspan=\"3\">IoT_fw_tool (binwalk / firmwalker / checksec 기반 wrapper)</td></tr>
<tr><th>수행 환경</th><td colspan=\"3\">Linux 분석 환경 · 입력: firmware.bin · 출력: HTML/PDF/CSV</td></tr>
</table>

<h2>2. 진단 결과 요약</h2>
<div class=\"grid\">
  <div class=\"card\"><b>Critical</b><br><span class=\"high\">\(.summary.critical_cases)건</span></div>
  <div class=\"card\"><b>High</b><br><span class=\"high\">\(.summary.high_cases)건</span></div>
  <div class=\"card\"><b>Medium</b><br><span class=\"medium\">\(.summary.medium_cases)건</span></div>
  <div class=\"card\"><b>Security cases</b><br>\(.summary.security_cases)건</div>
  <div class=\"card\"><b>Analyzed assets</b><br>\(.summary.analyzed_assets)건</div>
  <div class=\"card\"><b>Raw evidence</b><br>\(.summary.raw_evidence)건</div>
</div>

<h2>3. 우선순위 보안 케이스</h2>
" +
(if (.security_cases|length)==0 then
  "<div class=\"callout\">상관관계가 성립된 우선순위 보안 케이스가 없습니다.</div>"
else
  ([.security_cases|to_entries[] | .key as $i | .value |
    "<h3>P\($i+1) · \(.title|esc) <span class=\"\(.severity|risk_class)\">[\(.severity)]</span></h3>
<table>
<tr><th>자산</th><td><code>\(.asset|esc)</code></td><th>심각도</th><td>\(.severity|esc)</td></tr>
<tr><th>신뢰도</th><td>\(.confidence|esc)</td><th>분석</th><td>\(.analysis|esc)</td></tr>
<tr><th>공격 시나리오</th><td colspan=\"3\">\(.attack_scenario|esc)</td></tr>
<tr><th>잠재적 영향</th><td colspan=\"3\"><ul>\([.potential_impact[]|"<li>\(.|esc)</li>"]|join(""))</ul></td></tr>
<tr><th>권장 조치</th><td colspan=\"3\"><ol>\([.remediation[]|"<li>\(.|esc)</li>"]|join(""))</ol></td></tr>
<tr><th>증거 체인</th><td colspan=\"3\"><ul>\([.evidence[]|"<li>\(.|esc)</li>"]|join(""))</ul></td></tr>
</table>"
  ]|join(""))
end) +
"
<h2>4. Systemic Findings</h2>
" +
(if (.systemic_findings|length)==0 then
  "<div class=\"callout\">보고 기준을 만족하는 Systemic Finding 이 없습니다.</div>"
else
  ([.systemic_findings[]|
    "<h3>\(.title|esc) <span class=\"\(.severity|risk_class)\">[\(.severity)]</span></h3>
<table>
<tr><th>심각도</th><td>\(.severity|esc)</td><th>신뢰도</th><td>\(.confidence|esc)</td></tr>
<tr><th>분석</th><td colspan=\"3\">\(.analysis|esc)</td></tr>
<tr><th>권장 조치</th><td colspan=\"3\"><ul>\([.remediation[]|"<li>\(.|esc)</li>"]|join(""))</ul></td></tr>
</table>"
  ]|join(""))
end) +
"
<h2>5. Informational</h2>
" +
(if (.informational|length)==0 then
  "<div class=\"callout\">정보성 항목이 없습니다.</div>"
else
  ([.informational[]|
    "<h3>\(.title|esc)</h3>
<table><tr><th>분석</th><td>\(.analysis|esc)</td></tr></table>"
  ]|join(""))
end) +
"
<h2>6. Evidence Appendix</h2>
<details><summary>Raw evidence (\(.summary.raw_evidence)) 보기</summary>
<table>
<tr><th>Source</th><th>Type</th><th>Asset</th><th>Observation</th></tr>
" +
([.raw_evidence[]|
  "<tr><td>\(.source|esc)</td><td>\(.type|esc)</td><td><code>\(.asset|tostring|esc)</code></td><td><code>\(.value|tojson|esc)</code></td></tr>"
]|join("")) +
"
</table>
</details>

<div class=\"footer\">본 문서는 IoT_fw_tool 이 생성한 자동 보고서입니다. 자동 탐지 결과는 수동 검증이 필요합니다.</div>
</div>
</body></html>"
' "$OUTDIR/report.json"

} > "$OUTDIR/report.html"
