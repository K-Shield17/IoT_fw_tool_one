#!/usr/bin/env bash
set -euo pipefail

ROOTFS="$1"; CORRELATED="$2"; EVIDENCE="$3"; ASSETS="$4"; OUTDIR="$5"
mkdir -p "$OUTDIR" "$OUTDIR/raw"
SORTED="$OUTDIR/raw/correlated.sorted.json"; REPORT_JSON="$OUTDIR/report.json"; REPORT_HTML="$OUTDIR/report.html"; FINDINGS_CSV="$OUTDIR/findings.csv"
TARGET="$(basename "$OUTDIR")"; ROOTFS_NAME="$(basename "${ROOTFS%/}")"

jq '
def sev: if .=="CRITICAL" then 4 elif .=="HIGH" then 3 elif .=="MEDIUM" then 2 elif .=="LOW" then 1 else 0 end;
def conf: if .=="HIGH" then 3 elif .=="MEDIUM" then 2 elif .=="LOW" then 1 else 0 end;
.security_cases |= sort_by([-(.severity|sev),-(.confidence|conf),.rule_id,.asset])
' "$CORRELATED" > "$SORTED"

jq -n --arg tool "IoT_fw_tool" --arg target "$TARGET" --arg rootfs_name "$ROOTFS_NAME" \
--slurpfile c "$SORTED" --slurpfile ev "$EVIDENCE" --slurpfile as "$ASSETS" '

def sev: if .=="CRITICAL" then 4 elif .=="HIGH" then 3 elif .=="MEDIUM" then 2 elif .=="LOW" then 1 else 0 end;
def assets_for($t): [$ev[]? | select((.type//"")==$t) | (.asset//empty)] | map(select(.!="")) | unique;
def has_type($t): (assets_for($t)|length)>0;

def supp($type;$title;$result;$check;$rem):
  (assets_for($type)) as $a |
  if ($a|length)==0 then empty else {
    kind:"supplementary",rule_id:"",finding_status:"INFORMATIONAL",title:$title,severity:"INFO",confidence:"LOW",
    asset:(if ($a|length)==1 then $a[0] else $a[0]+" 외 "+((($a|length)-1)|tostring)+"개" end),
    category:$type,result:$result,basis:"관련 경로 "+(($a|length)|tostring)+"개에서 해당 유형의 정적 탐지 결과 확인",
    analysis:$result,additional_check:$check,impact:[],remediation:[$rem]
  } end;

($c[0]//{security_cases:[],systemic_findings:[],informational:[]}) as $r |

([$r.security_cases[]? | {
  kind:"security_case",rule_id:(.rule_id//""),finding_status:(.finding_status//"IDENTIFIED"),
  title:(.title//"Security Finding"),severity:((.severity//"INFO")|ascii_upcase),confidence:((.confidence//"LOW")|ascii_upcase),
  asset:(.asset//"-"),category:(.category//""),result:(.analysis//""),
  basis:(((.evidence//[])+(.confidence_basis//[])) | if length>0 then join("; ") else "여러 정적 분석 관찰값의 상관분석을 통해 보안 Finding으로 분류됨" end),
  analysis:(.analysis//""),additional_check:(.attack_scenario//""),impact:(.potential_impact//[]),remediation:(.remediation//[])
}]) as $security |

([$r.systemic_findings[]? | {
  kind:"systemic",rule_id:(.rule_id//"F-06"),finding_status:(.finding_status//"IDENTIFIED"),
  title:(.title//"Systemic Finding"),severity:((.severity//"INFO")|ascii_upcase),confidence:((.confidence//"HIGH")|ascii_upcase),
  asset:"Firmware-wide",category:(.category//"systemic"),result:(.analysis//""),
  basis:(if ((.analysis_scope//{})|length)>0 then
    "분석 ELF "+((.analysis_scope.analyzed_executables//0)|tostring)+"개 중 "+((.analysis_scope.affected_executables//0)|tostring)+"개 ("+((.analysis_scope.affected_percentage//0)|tostring)+"%)에서 반복 패턴 확인"
    else "다수 바이너리에서 반복되는 보안 설정 패턴 확인" end),
  analysis:(.analysis//""),additional_check:"펌웨어 빌드 정책 및 툴체인 Hardening 설정 확인",
  impact:["펌웨어 전반의 exploit resistance 저하 가능성"],remediation:(.remediation//[])
}]) as $systemic |

([
  supp("update";"Firmware Update Mechanism";"펌웨어 업데이트 또는 검증과 관련된 정적 흔적이 확인됨";"업데이트 무결성 및 서명 검증이 실제로 강제되는지 확인";"업데이트 서명 검증과 무결성 검사를 릴리스 절차에 포함"),
  supp("component";"Embedded Component Information";"오픈소스 또는 임베디드 구성요소 관련 정보가 확인됨";"정확한 버전과 알려진 취약점 존재 여부 확인";"구성요소 인벤토리를 관리하고 지원되는 안정 버전 사용"),
  supp("web_interface";"Web / API Interface";"Web, CGI 또는 API 관리 인터페이스 관련 정적 흔적이 확인됨";"인증, 세션 처리 및 입력 검증 로직 확인";"관리 인터페이스 접근통제와 입력 검증 강화"),
  supp("service";"Network Service Indicator";"네트워크 또는 원격 서비스 관련 실행파일 및 설정 흔적이 확인됨";"서비스의 실제 활성화 여부와 외부 노출 여부 확인";"불필요한 서비스를 비활성화하고 최소 노출 원칙 적용"),
  supp("crypto";"Crypto / Key Material";"암호화 알고리즘 또는 Key/Certificate 관련 정적 흔적이 확인됨";"키 권한, 고유성 및 실제 사용 서비스 확인";"안전한 키 관리 정책 적용"),
  supp("ssh";"SSH Material";"SSH 관련 Key 또는 설정 흔적이 확인됨";"장비별 고유 키 여부와 SSH 서비스 사용 정책 확인";"불필요한 SSH 접근 제한 및 키 수명주기 관리"),
  supp("credential";"Credential Indicator";"계정, 비밀번호 또는 인증정보 관련 후보가 확인됨";"실제 하드코딩 또는 기본 자격증명 여부 확인";"하드코딩 자격증명을 제거하고 장비별 고유 자격증명 사용"),
  supp("database";"Database / Stored Data";"Database 또는 저장 데이터 관련 파일이 확인됨";"민감정보 저장 여부 및 파일 접근 권한 확인";"민감정보 저장을 최소화하고 접근 권한 제한")
]) as $supp |

(($security+$systemic+$supp) | sort_by([-(.severity|sev),.title]) | to_entries |
  map(.value + {id:("FW-"+(if (.key+1)<10 then "00" elif (.key+1)<100 then "0" else "" end)+((.key+1)|tostring))})
) as $findings |

def ids($r): [$findings[]? | select(.rule_id==$r) | .id];
def ow($code;$cat;$summary;$ids;$status): {code:$code,category:$cat,summary:$summary,findings:(if ($ids|length)>0 then ($ids|join(", ")) else "-" end),status:$status};

([
  (ids("F-03") as $i | if ($i|length)>0 then ow("I1";"Weak, Guessable, or Hardcoded Passwords";"약한 Unix-MD5 비밀번호 해시 저장 Finding이 확인됨";$i;"Finding Identified")
    elif has_type("credential") then ow("I1";"Weak, Guessable, or Hardcoded Passwords";"Credential 관련 정적 흔적은 있으나 취약 Finding 조건은 충족하지 않음";[];"Related Evidence Only") else empty end),

  (ids("F-04") as $i | if ($i|length)>0 then ow("I2";"Insecure Network Services";"Legacy Telnet remote service 관련 Finding이 확인됨";$i;"Finding Identified")
    elif has_type("service") then ow("I2";"Insecure Network Services";"네트워크 서비스 관련 정적 흔적은 있으나 insecure service Finding 조건은 충족하지 않음";[];"Related Evidence Only") else empty end),

  (ids("F-05") as $i | if ($i|length)>0 then ow("I3";"Insecure Ecosystem Interfaces";"Web command-execution 관련 Potential Finding이 확인됨";$i;"Potential Finding")
    elif has_type("web_interface") then ow("I3";"Insecure Ecosystem Interfaces";"Web/API 관련 정적 흔적은 있으나 취약 Finding 조건은 충족하지 않음";[];"Related Evidence Only") else empty end),

  (if has_type("update") then ow("I4";"Lack of Secure Update Mechanisms";"Firmware Update 또는 검증 관련 흔적이 확인되었으나 Secure Update 여부는 확정하지 않음";[];"Related Evidence Only") else empty end),
  (if has_type("component") then ow("I5";"Use of Insecure or Outdated Components";"구성요소 또는 버전 관련 정보가 확인되었으나 알려진 취약 버전 여부는 확정하지 않음";[];"Related Evidence Only") else empty end),

  (ids("F-02") as $i | if ($i|length)>0 then ow("I7";"Insecure Data Transfer and Storage";"민감 Key Material의 과도한 읽기 권한 Finding이 확인됨";$i;"Finding Identified")
    elif (has_type("crypto") or has_type("ssh")) then ow("I7";"Insecure Data Transfer and Storage";"Crypto 또는 SSH 관련 정적 흔적은 있으나 취약 Finding 조건은 충족하지 않음";[];"Related Evidence Only") else empty end),

  (if has_type("config") then ow("I9";"Insecure Default Settings";"보안 관련 Configuration 흔적이 확인되어 기본 설정 검토가 필요함";[];"Related Evidence Only") else empty end)
]) as $owasp |

([
  if any($findings[]?;.rule_id=="F-03") then {finding:"Credential 관련 Finding",meaning:"약한 비밀번호 해시로 인한 오프라인 크래킹 가능성",check:"Credential store 접근 및 계정 악용 여부",artifacts:"인증 로그, 계정 설정, Credential store"} else empty end,
  if any($findings[]?;.rule_id=="F-02") then {finding:"Key / Crypto 관련 Finding",meaning:"키 유출 또는 인증 재사용 가능성",check:"장비별 고유 키 여부와 실제 사용 서비스",artifacts:"Key/Certificate metadata, TLS/SSH 설정"} else empty end,
  if any($findings[]?;(.rule_id=="F-01" or .rule_id=="F-04")) then {finding:"Network Service 관련 Finding",meaning:"원격 Attack Surface 또는 exploit resistance 저하",check:"서비스 활성화, 외부 노출, 비인가 세션",artifacts:"서비스 설정, init 설정, 네트워크 로그"} else empty end,
  if any($findings[]?;.rule_id=="F-05") then {finding:"Web Interface 관련 Finding",meaning:"관리 인터페이스 악용 가능성",check:"사용자 입력에서 명령 실행 sink까지의 흐름",artifacts:"Web/CGI source, Web log, Dynamic request result"} else empty end,
  if any($findings[]?;(.rule_id=="F-01" or .rule_id=="F-06")) then {finding:"Binary Hardening 관련 Finding",meaning:"취약점 존재 시 악용 난이도에 영향",check:"대상 ELF 우선 정적 분석",artifacts:"ELF metadata, Decompile result"} else empty end
]) as $cert |

([$findings[]? as $f | $f.remediation[]? | select(type=="string" and length>0) | {priority:$f.severity,recommendation:.}]
 | unique_by(.recommendation) | sort_by([-(.priority|sev),.recommendation])) as $rem |

([$findings[]? | select(.kind!="supplementary" and .finding_status=="IDENTIFIED" and (.confidence=="HIGH" or .confidence=="MEDIUM"))]) as $validated |
([$validated[]?|select(.severity=="CRITICAL")]|length) as $cv |
([$validated[]?|select(.severity=="HIGH")]|length) as $hv |
([$validated[]?|select(.severity=="MEDIUM")]|length) as $mv |
([$validated[]?|select(.category=="network_service_hardening" or .category=="legacy_remote_service")]|length) as $nv |
(if $cv>0 then "CRITICAL" elif $hv>0 then "HIGH" elif $mv>0 then "MEDIUM" else "LOW" end) as $base |
(if $base=="HIGH" and $hv>=2 and $nv>=1 then "CRITICAL" else $base end) as $risk |

{
  tool:$tool,target:$target,
  summary:{
    overall_risk:$risk,base_risk:$base,
    critical:([$findings[]?|select(.severity=="CRITICAL")]|length),
    high:([$findings[]?|select(.severity=="HIGH")]|length),
    medium:([$findings[]?|select(.severity=="MEDIUM")]|length),
    low:([$findings[]?|select(.severity=="LOW")]|length),
    info:([$findings[]?|select(.severity=="INFO")]|length),
    findings:($findings|length),
    analyzed_elf:([$ev[]?|select((.source//"")=="checksec" and (.property//"")=="hardening_profile")]|length),
    owasp_evidence:($owasp|length)
  },
  findings:$findings,owasp_iot_top10_mapping:$owasp,cert_dfir:$cert,remediation:$rem,
  metadata:{rootfs_name:$rootfs_name,asset_count:($as|length),extraction_status:"SUCCESS"},
  limitations:[
    "본 보고서는 펌웨어 파일 기반 정적 점검 결과를 대상으로 한다.",
    "Raw Evidence는 최종 보고서와 report.json에 포함하지 않는다.",
    "자동 탐지 결과는 취약점 후보를 포함하므로 최종 판정에는 추가 검증이 필요하다.",
    "Checksec 결과는 보호기법 적용 상태이며 실제 취약 코드 존재를 직접 의미하지 않는다.",
    "구성요소 버전 정보만으로 알려진 취약점 존재 여부를 확정하지 않는다.",
    "Firmware Update 관련 문자열만으로 Secure Update 동작의 안전성을 확정하지 않는다.",
    "실제 서비스 활성화·외부 노출·인증 우회 가능성은 동적 분석 또는 실제 장비 검증이 필요하다.",
    "Overall Risk는 MEDIUM/HIGH Confidence의 IDENTIFIED Finding을 기준으로 산정한다.",
    "INFO 및 LOW Confidence Potential Finding은 Overall Risk를 직접 결정하지 않는다.",
    "OWASP IoT Mapping은 현재 펌웨어에서 Finding 또는 관련 정적 Evidence가 확인된 항목만 표시한다."
  ]
}
' > "$REPORT_JSON"

{
  printf '\xEF\xBB\xBF'
  echo '"ID","Severity","Title","Location","Result","Additional Check"'
  jq -r '.findings[] | [.id,.severity,.title,(.asset//"-"),(.result//""),(.additional_check//"")] | @csv' "$REPORT_JSON"
} > "$FINDINGS_CSV"

cat > "$REPORT_HTML" <<'EOF'
<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IoT Firmware Security Assessment</title>
<style>
:root{--bg:#fff;--text:#172b4d;--muted:#5e6c84;--line:#cfd8e3;--head:#edf2f7;--critical:#7a0a0a;--high:#c21f1f;--med:#d4a017;--low:#2f5d8a}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:Arial,'Malgun Gothic','Noto Sans KR',sans-serif;line-height:1.55}
.wrap{max-width:1120px;margin:14px auto 40px;padding:0 14px}h1{font-size:28px;margin:0 0 8px}h2{font-size:21px;margin:30px 0 12px;border-bottom:2px solid #cfd5dd;padding-bottom:7px}h3{font-size:17px;margin:20px 0 9px}
.subtitle{color:var(--muted);font-size:13px;margin-bottom:20px}table{width:100%;border-collapse:collapse;margin:10px 0 20px;font-size:14px}th,td{border:1px solid var(--line);padding:10px 12px;text-align:left;vertical-align:top}th{background:var(--head)}
code{background:#f2f4f7;padding:1px 5px;border-radius:4px;font-family:Consolas,monospace;word-break:break-all}.summary-grid{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin:14px 0 18px}
.metric{border:1px solid var(--line);border-radius:10px;padding:13px}.metric .label{font-size:12px;color:#475467}.metric .value{font-size:23px;font-weight:700}.CRITICAL{color:var(--critical)}.HIGH{color:var(--high)}.MEDIUM{color:var(--med)}.LOW{color:var(--low)}
.risk{font-weight:800}.note{background:#f8fafc;border-left:4px solid #94a3b8;padding:11px 13px;font-size:13px;margin:12px 0 18px}.finding{border:1px solid var(--line);border-left:5px solid #98a2b3;border-radius:7px;padding:15px 16px 4px;margin:15px 0 22px}
.finding.high{border-left-color:var(--high)}.finding.medium{border-left-color:var(--med)}.badge{display:inline-block;padding:4px 9px;border-radius:999px;font-weight:700}.found{background:#fee4e2;color:#912018}.potential{background:#fef0c7;color:#93370d}.partial{background:#e0f2fe;color:#075985}
.footer{margin-top:35px;border-top:1px solid var(--line);padding-top:10px;color:var(--muted);font-size:12px}@media(max-width:900px){.summary-grid{grid-template-columns:repeat(3,1fr)}}@media print{.wrap{max-width:none;margin:0}.summary-grid{grid-template-columns:repeat(6,1fr)}table,.finding{break-inside:avoid}}
</style>
</head>
<body><div class="wrap">
EOF

jq -r '
def e: tostring|@html;
def td($x): "<td>"+($x|e)+"</td>";
def code($x): "<code>"+($x|e)+"</code>";
def metric($l;$v;$c): "<div class=\"metric\"><div class=\"label\">"+$l+"</div><div class=\"value "+$c+"\">"+($v|tostring)+"</div></div>";
def badge($s): (if $s=="Finding Identified" then "found" elif $s=="Potential Finding" then "potential" else "partial" end) as $c | "<span class=\"badge "+$c+"\">"+($s|e)+"</span>";

"<h1>IoT Firmware Security Assessment</h1>"+
"<div class=\"subtitle\">Static firmware analysis · IoT_fw_tool · Preventive Security Checkup</div>"+
"<table><tr><th style=\"width:22%\">구분</th><th>내용</th></tr>"+
"<tr>"+td("대상")+td(.target)+"</tr><tr>"+td("점검 방식")+td("펌웨어 파일 기반 정적 보안 점검")+"</tr>"+
"<tr>"+td("분석 도구")+td("IoT_fw_tool")+"</tr><tr>"+td("기반 모듈")+td("binwalk / firmwalker-lite / checksec-lite")+"</tr>"+
"<tr>"+td("분석 범위")+td("Firmware 구조, 주요 설정·서비스·Web/API·Update·Component·Crypto/Key, 주요 ELF Hardening")+"</tr>"+
"<tr>"+td("출력")+td("HTML / JSON / CSV")+"</tr></table>"+

"<h2>1. 요약</h2><p>Overall Risk: <span class=\"risk "+(.summary.overall_risk|e)+"\">"+(.summary.overall_risk|e)+"</span></p>"+
"<p class=\"subtitle\">주요 설정, 원격 서비스, Key/Certificate, Firmware Update, Component 정보와 주요 ELF 보호기법을 대상으로 예방적 정적 점검을 수행하였다. 자동 탐지 결과는 추가 검증이 필요한 보안 점검 후보를 포함한다.</p>"+
"<div class=\"summary-grid\">"+metric("Critical";.summary.critical;"CRITICAL")+metric("High";.summary.high;"HIGH")+metric("Medium";.summary.medium;"MEDIUM")+metric("Findings";.summary.findings;"")+metric("Analyzed ELF";.summary.analyzed_elf;"")+metric("OWASP Evidence";.summary.owasp_evidence;"")+"</div>"+
"<div class=\"note\">Raw Evidence는 보고서에 포함하지 않는다. 전체 grep/strings 출력, 원문 자격증명 값, Private Key 본문 및 raw JSONL/TSV는 최종 보고서에 표시하지 않는다.</div>"+

"<h2>2. 점검 개요</h2><table><tr><th>항목</th><th>내용</th></tr>"+
"<tr>"+td("점검 대상")+td(.target)+"</tr><tr>"+td("수행 환경")+td("Linux")+"</tr><tr>"+td("분석 방식")+td("Static Firmware Analysis")+"</tr>"+
"<tr>"+td("RootFS 식별명")+td(.metadata.rootfs_name)+"</tr><tr>"+td("점검 목적")+td("배포 전 주요 위험 요소 및 보안 설정 상태를 빠르게 확인하기 위한 예방적 점검")+"</tr></table>"+

"<h2>3. 대상 기기 및 펌웨어 정보</h2><table><tr><th>항목</th><th>내용</th></tr>"+
"<tr>"+td("분석 대상")+td(.target)+"</tr><tr>"+td("RootFS")+td(.metadata.rootfs_name)+"</tr><tr>"+td("추출 상태")+td(.metadata.extraction_status)+"</tr>"+
"<tr>"+td("분석 자산 수")+td(.metadata.asset_count)+"</tr><tr>"+td("주요 ELF 분석 대상")+td(.summary.analyzed_elf)+"</tr></table>"+

"<h2>4. 점검 항목 매핑</h2><table><tr><th>점검 영역</th><th>주요 점검 항목</th><th>확인 정보</th><th>도구</th></tr>"+
"<tr>"+td("Firmware Structure")+td("File system / compression / extraction")+td("펌웨어 구조 및 추출 가능 여부")+td("binwalk")+"</tr>"+
"<tr>"+td("Credential")+td("Password / secret / token / account")+td("하드코딩 인증정보 후보")+td("firmwalker-lite")+"</tr>"+
"<tr>"+td("Network Service")+td("Telnet / FTP / SSH / HTTP / UPnP")+td("서비스·설정·시작 흔적")+td("firmwalker-lite")+"</tr>"+
"<tr>"+td("Web Interface")+td("CGI / API / login / session")+td("Web 관리 인터페이스 흔적")+td("firmwalker-lite")+"</tr>"+
"<tr>"+td("Firmware Update")+td("upgrade / verify / signature / checksum")+td("업데이트·검증 관련 흔적")+td("firmwalker-lite")+"</tr>"+
"<tr>"+td("Component")+td("BusyBox / OpenSSL / Dropbear 등")+td("구성요소 및 version hint")+td("firmwalker-lite")+"</tr>"+
"<tr>"+td("Crypto / Key")+td("Legacy/modern crypto / certificate / key")+td("암호화 및 Key Material 후보")+td("firmwalker-lite")+"</tr>"+
"<tr>"+td("Binary Hardening")+td("RELRO / Canary / NX / PIE / Fortify / Separate Code / Stack Clash")+td("주요 ELF 보호기법 상태")+td("checksec-lite")+"</tr></table>"+

"<h2>5. 위험도 등급 기준</h2><table><tr><th>등급</th><th>기준</th></tr>"+
"<tr>"+td("Critical")+td("즉시 대응이 필요한 매우 높은 위험")+"</tr><tr>"+td("High")+td("직접적인 보안 영향이 크고 우선 대응 및 검증이 필요한 항목")+"</tr>"+
"<tr>"+td("Medium")+td("추가 조건이 필요하지만 공격 표면 또는 악용 난이도에 영향을 줄 수 있는 항목")+"</tr><tr>"+td("Low")+td("즉각적인 악용 가능성은 낮지만 개선이 필요한 항목")+"</tr>"+
"<tr>"+td("Info")+td("취약점으로 확정하지 않고 보안 상태 및 추가 분석 우선순위를 판단하기 위한 탐지 정보")+"</tr></table>"+

"<h2>6. 진단 결과 요약</h2><table><tr><th>ID</th><th>점검 항목</th><th>진단 결과</th><th>위험도</th><th>위치</th></tr>"+
(if (.findings|length)==0 then "<tr><td colspan=\"5\">보고 임계치를 충족한 Finding이 없습니다.</td></tr>"
else ([.findings[]|"<tr>"+td(.id)+td(.title)+td(.result)+"<td class=\""+(.severity|e)+"\">"+(.severity|e)+"</td><td>"+code(.asset)+"</td></tr>"]|join("")) end)+"</table>"+

"<h2>7. 진단 상세</h2><p class=\"subtitle\">6. 진단 결과 요약에 표시된 전체 Finding에 대해 위치·탐지 결과·확인 근거·보안 영향·추가 확인·조치 방안을 제공한다.</p>"+
(if (.findings|length)==0 then "<div class=\"note\">상세 분석 대상으로 분류된 Finding이 없습니다.</div>"
else ([.findings[] | (if (.severity=="CRITICAL" or .severity=="HIGH") then "high" elif .severity=="MEDIUM" then "medium" else "" end) as $c |
"<section class=\"finding "+$c+"\"><h3>"+(.id|e)+" · "+(.title|e)+" ["+(.severity|e)+"]</h3><table>"+
"<tr><th style=\"width:22%\">위치</th><td>"+code(.asset)+"</td></tr><tr><th>점검 결과</th>"+td(.result)+"</tr>"+
"<tr><th>확인 근거 요약</th>"+td(.basis)+"</tr><tr><th>보안 영향</th>"+td(if ((.impact//[])|length)>0 then (.impact|join("; ")) else (.analysis//"") end)+"</tr>"+
"<tr><th>추가 확인</th>"+td(.additional_check//"")+"</tr><tr><th>조치 방안</th>"+td((.remediation//[])|join("; "))+"</tr></table></section>"]|join("")) end)+

"<h2>8. CERT / DFIR 활용 관점</h2><table><tr><th>Finding</th><th>위협대응 의미</th><th>사고 발생 시 확인사항</th><th>권장 증적</th></tr>"+
(if (.cert_dfir|length)==0 then "<tr><td colspan=\"4\">현재 Finding에서 별도 CERT/DFIR 매핑 항목이 생성되지 않았습니다.</td></tr>"
else ([.cert_dfir[]|"<tr>"+td(.finding)+td(.meaning)+td(.check)+td(.artifacts)+"</tr>"]|join("")) end)+"</table>"+
"<div class=\"note\">정상 펌웨어에 존재하는 서비스·설정·Key 파일은 그 자체로 IOC가 아니다. 실제 침해 판단에는 정상 기준선, 서비스 상태, 인증 및 네트워크 로그 등 추가 증거가 필요하다.</div>"+

"<h2>9. OWASP IoT Top 10 증거 매핑</h2><p class=\"subtitle\">OWASP IoT Top 10 전체 항목이 아니라 현재 펌웨어에서 Security Finding 또는 관련 정적 Evidence가 확인된 항목만 표시한다.</p>"+
(if (.owasp_iot_top10_mapping|length)==0 then "<div class=\"note\">현재 분석 결과에서 직접 관련된 OWASP IoT Top 10 항목이 확인되지 않았습니다.</div>"
else "<table><tr><th>OWASP</th><th>Category</th><th>확인된 증거 요약</th><th>관련 Finding</th><th>상태</th></tr>"+
([.owasp_iot_top10_mapping[]|"<tr>"+td(.code)+td(.category)+td(.summary)+td(.findings)+"<td>"+badge(.status)+"</td></tr>"]|join(""))+"</table>" end)+
"<h3>상태 기준</h3><table><tr><th>상태</th><th>의미</th></tr><tr>"+td("Finding Identified")+td("정의된 Finding Rule 조건을 충족하여 보안 Finding으로 분류됨")+"</tr>"+
"<tr>"+td("Potential Finding")+td("보안 영향 가능성은 있으나 현재 정적 분석만으로 exploit path가 확정되지 않음")+"</tr>"+
"<tr>"+td("Related Evidence Only")+td("관련 정적 흔적은 있으나 Finding 조건을 충족하지 않음")+"</tr></table>"+

"<h2>10. 종합 조치 방안</h2><table><tr><th>우선순위</th><th>권고사항</th></tr>"+
(if (.remediation|length)==0 then "<tr>"+td("Info")+td("현재 보고 결과에 따른 별도 조치 항목이 없습니다.")+"</tr>"
else ([.remediation[]|"<tr>"+td(.priority)+td(.recommendation)+"</tr>"]|join("")) end)+"</table>"+

"<h2>11. 점검 범위 및 유의사항</h2><ul>"+([.limitations[]|"<li>"+(.|e)+"</li>"]|join(""))+"</ul>"+
"<div class=\"footer\">IoT_fw_tool · Firmware Security Checkup Report</div>"
' "$REPORT_JSON" >> "$REPORT_HTML"

cat >> "$REPORT_HTML" <<'EOF'
</div>
</body>
</html>
EOF

echo "[+] Report generated"
echo "    JSON : $REPORT_JSON"
echo "    CSV  : $FINDINGS_CSV"
echo "    HTML : $REPORT_HTML"
