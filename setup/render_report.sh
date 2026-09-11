#!/usr/bin/env bash
set -euo pipefail

ROOTFS="$1"
CORRELATED="$2"
EVIDENCE="$3"
ASSETS="$4"
OUTDIR="$5"

mkdir -p "$OUTDIR" "$OUTDIR/raw"

SORTED="$OUTDIR/raw/correlated.sorted.json"

# Security cases are still ordered by analyst priority.
jq '
  def sev:
    if .=="CRITICAL" then 4
    elif .=="HIGH" then 3
    elif .=="MEDIUM" then 2
    elif .=="LOW" then 1
    else 0 end;
  def conf:
    if .=="HIGH" then 3
    elif .=="MEDIUM" then 2
    else 1 end;
  .security_cases |= sort_by([-(.severity|sev),-(.confidence|conf),.asset,.title])
' "$CORRELATED" > "$SORTED"

TARGET="$(basename "$OUTDIR")"
ROOTFS_NAME="$(basename "${ROOTFS%/}")"

# Build a report-only JSON.
# Raw evidence values are deliberately not copied into report.json.
jq -n \
  --arg tool "IoT_fw_tool" \
  --arg target "$TARGET" \
  --arg rootfs_name "$ROOTFS_NAME" \
  --slurpfile c "$SORTED" \
  --slurpfile ev "$EVIDENCE" \
  --slurpfile as "$ASSETS" '
  def sev_rank:
    if .=="CRITICAL" then 4
    elif .=="HIGH" then 3
    elif .=="MEDIUM" then 2
    elif .=="LOW" then 1
    else 0 end;

  def has_type($t):
    any($ev[]?; (.type // "") == $t);

  def assets_for($t):
    [$ev[]? | select((.type // "") == $t) | (.asset // empty)]
    | map(select(. != null and . != ""))
    | unique;

  def supp($type;$title;$result;$check;$rem):
    (assets_for($type)) as $a |
    if ($a|length) == 0 then empty else
      {
        kind:"supplementary",
        title:$title,
        severity:"INFO",
        confidence:"LOW",
        asset:(if ($a|length)==1 then $a[0] else "\($a[0]) 외 \(($a|length)-1)개" end),
        category:$type,
        result:$result,
        basis:"관련 경로 \($a|length)개에서 해당 유형의 정적 탐지 결과 확인",
        analysis:$result,
        additional_check:$check,
        impact:[],
        remediation:[$rem]
      }
    end;

  ($c[0] // {security_cases:[],systemic_findings:[],informational:[]}) as $r |

  (
    [
      ($r.security_cases[]? |
        {
          kind:"security_case",
          title:(.title // "Security Finding"),
          severity:((.severity // "INFO")|ascii_upcase),
          confidence:(.confidence // ""),
          asset:(.asset // "-"),
          category:(.category // ""),
          result:(.analysis // "Static-analysis finding identified."),
          basis:"여러 정적 분석 관찰값의 상관분석을 통해 우선 검토 대상으로 분류됨",
          analysis:(.analysis // ""),
          additional_check:(.attack_scenario // ""),
          impact:(.potential_impact // []),
          remediation:(.remediation // [])
        }),
      ($r.systemic_findings[]? |
        {
          kind:"systemic",
          title:(.title // "Systemic Finding"),
          severity:((.severity // "INFO")|ascii_upcase),
          confidence:(.confidence // ""),
          asset:"Firmware-wide",
          category:"systemic_hardening",
          result:(.analysis // ""),
          basis:"다수 바이너리에서 반복되는 보호기법 패턴 확인",
          analysis:(.analysis // ""),
          additional_check:"빌드 정책 및 툴체인 설정을 확인",
          impact:[],
          remediation:(.remediation // [])
        }),
      supp("update";"Firmware Update Mechanism";
        "펌웨어 업데이트 또는 검증과 관련된 정적 흔적이 확인됨";
        "업데이트 무결성·서명 검증이 실제로 강제되는지 추가 확인";
        "업데이트 서명 검증과 무결성 검사를 릴리스 절차에 포함"),
      supp("component";"Embedded Component Information";
        "주요 오픈소스/임베디드 구성요소 또는 버전 힌트가 확인됨";
        "식별된 버전의 지원 상태와 알려진 취약점 여부 추가 확인";
        "지원되는 최신 안정 버전 사용 및 구성요소 인벤토리 관리"),
      supp("web_interface";"Web / API Interface";
        "Web/CGI/API 관리 인터페이스 관련 정적 흔적이 확인됨";
        "인증·세션·입력 검증 로직에 대한 추가 확인";
        "관리 인터페이스 접근통제 및 입력 검증 강화"),
      supp("service";"Network Service Indicator";
        "원격 또는 네트워크 서비스 관련 실행파일/설정 흔적이 확인됨";
        "실제 활성화 여부와 외부 노출 여부 추가 확인";
        "불필요한 서비스 비활성화 및 최소 노출 원칙 적용"),
      supp("crypto";"Crypto / Key Material";
        "암호화 알고리즘 또는 Key/Certificate 관련 정적 흔적이 확인됨";
        "키 고유성·권한·실사용 서비스 및 알고리즘 용도 추가 확인";
        "키 관리 정책 및 안전한 알고리즘 사용 여부 검토"),
      supp("ssh";"SSH Material";
        "SSH 관련 Key/설정 흔적이 확인됨";
        "장비별 고유 키 여부와 SSH 서비스 사용 정책 확인";
        "불필요한 SSH 접근 제한 및 키 수명주기 관리"),
      supp("credential";"Credential Indicator";
        "계정·비밀번호·인증정보 관련 후보가 확인됨";
        "실제 고정 자격증명 여부와 사용 서비스 추가 확인";
        "하드코딩 자격증명 제거 및 장비별 고유 자격증명 사용"),
      supp("database";"Database / Stored Data";
        "DB 또는 저장 데이터 관련 파일 후보가 확인됨";
        "민감정보 저장 여부 및 파일 권한 추가 확인";
        "민감정보 최소 저장 및 접근권한 제한")
    ]
    | sort_by([-(.severity|sev_rank), .title])
    | to_entries
    | map((.key+1|tostring) as $n | .value + {id:("FW-" + (("000"[0:(3-($n|length))]) + $n))})
  ) as $findings |

  def ids_for($re):
    [$findings[]? |
      select((((.category // "")+" "+(.title // ""))|ascii_downcase) | test($re))
      | .id][0:4] | if length==0 then "-" else join(", ") end;

  def ow($code;$cat;$summary;$ids;$status):
    {code:$code,category:$cat,summary:$summary,findings:$ids,status:$status};

  (
    [
      ow("I1";"Weak, Guessable, or Hardcoded Passwords";
        (if has_type("credential") then "Credential/Password 관련 정적 후보가 확인됨" else "직접 관련 증거가 제한적임" end);
        ids_for("credential|password");
        (if has_type("credential") then "Evidence Found" else "Limited" end)),
      ow("I2";"Insecure Network Services";
        (if has_type("service") then "네트워크/원격 서비스 실행파일 또는 설정 흔적이 확인됨" else "서비스 관련 정적 증거가 제한적임" end);
        ids_for("network_service|telnet|service");
        (if has_type("service") then "Evidence Found" else "Limited" end)),
      ow("I3";"Insecure Ecosystem Interfaces";
        (if has_type("web_interface") then "Web/CGI/API 인터페이스 관련 정적 흔적이 확인됨" else "인터페이스 보안을 정적 분석만으로 충분히 판단하기 어려움" end);
        ids_for("web|interface");
        (if has_type("web_interface") then "Potential Evidence" else "Limited" end)),
      ow("I4";"Lack of Secure Update Mechanisms";
        (if has_type("update") then "Firmware Update/검증 관련 정적 흔적이 확인됨" else "Secure Update 동작 여부를 현재 증거만으로 판단하기 어려움" end);
        ids_for("update");
        (if has_type("update") then "Partial Evidence" else "Limited" end)),
      ow("I5";"Use of Insecure or Outdated Components";
        (if has_type("component") then "구성요소 또는 버전 힌트가 확인됨" else "구성요소 버전 정보가 제한적임" end);
        ids_for("component|hardening");
        (if has_type("component") then "Potential Evidence" else "Limited" end)),
      ow("I6";"Insufficient Privacy Protection";
        (if (has_type("credential") or has_type("database") or has_type("sensitive_pattern")) then "Credential/DB/민감정보 관련 저장 후보가 확인됨" else "개인정보 처리 수준은 정적 펌웨어만으로 충분히 판단하기 어려움" end);
        ids_for("credential|database");
        (if (has_type("credential") or has_type("database") or has_type("sensitive_pattern")) then "Partial Evidence" else "Limited" end)),
      ow("I7";"Insecure Data Transfer and Storage";
        (if (has_type("crypto") or has_type("ssh")) then "Crypto/SSH/Key Material 관련 정적 흔적이 확인됨" else "전송·저장 보호 수준을 현재 증거만으로 충분히 판단하기 어려움" end);
        ids_for("key|crypto|ssh");
        (if (has_type("crypto") or has_type("ssh")) then "Evidence Found" else "Limited" end)),
      ow("I8";"Lack of Device Management";
        (if (has_type("service") or has_type("update") or has_type("ssh")) then "원격관리/업데이트/SSH 관련 일부 관리 기능 흔적이 확인됨" else "장치 수명주기 관리 수준은 정적 분석만으로 평가가 제한됨" end);
        ids_for("service|update|ssh");
        (if (has_type("service") or has_type("update") or has_type("ssh")) then "Partial Evidence" else "Limited" end)),
      ow("I9";"Insecure Default Settings";
        (if (has_type("credential") or has_type("service") or has_type("config")) then "Credential 또는 서비스 기본 설정 검토 대상이 확인됨" else "기본 설정 안전성 판단을 위한 정적 증거가 제한적임" end);
        ids_for("credential|service");
        (if (has_type("credential") or has_type("service") or has_type("config")) then "Potential Evidence" else "Limited" end)),
      ow("I10";"Lack of Physical Hardening";
        "펌웨어 파일 기반 정적 분석만으로 물리적 보호 수준을 판단하기 어려움";
        "-";
        "Not Assessed")
    ]
  ) as $owasp |

  (
    [
      (if any($findings[]?; ((.category // "")|test("credential"))) then
        {finding:"Credential 관련 Finding",meaning:"인증정보 악용 가능성",check:"비인가 로그인·관리 인터페이스 접근 여부",recommended_artifacts:"인증 로그, 관리 인터페이스 접근 기록"} else empty end),
      (if any($findings[]?; ((.category // "")|test("key|crypto|ssh"))) then
        {finding:"Key / Crypto 관련 Finding",meaning:"키 유출·인증 재사용 가능성",check:"장비별 고유 키 여부, 실제 사용 서비스",recommended_artifacts:"키/인증서 메타정보, TLS/SSH 설정"} else empty end),
      (if any($findings[]?; ((.category // "")|test("network_service|service"))) then
        {finding:"Network Service 관련 Finding",meaning:"원격 Attack Surface 증가 가능성",check:"서비스 활성화·외부 노출·비인가 세션",recommended_artifacts:"서비스 설정, init 설정, 네트워크 로그"} else empty end),
      (if any($findings[]?; ((.category // "")|test("web"))) then
        {finding:"Web Interface 관련 Finding",meaning:"관리 인터페이스 악용 가능성",check:"비인가 요청, 인증·세션 이상",recommended_artifacts:"웹/관리 인터페이스 로그"} else empty end),
      (if any($findings[]?; ((.category // "")|test("hardening"))) then
        {finding:"Binary Hardening 관련 Finding",meaning:"취약점 존재 시 악용 난이도에 영향",check:"대상 ELF 우선 정적분석",recommended_artifacts:"ELF 메타정보, 디컴파일 결과"} else empty end),
      (if any($findings[]?; (.category // "")=="update") then
        {finding:"Firmware Update 관련 Finding",meaning:"비정상 펌웨어 배포·변조 위험 검토",check:"업데이트 이력과 검증 실패 흔적",recommended_artifacts:"업데이트 로그, 서명/검증 설정"} else empty end)
    ]
  ) as $cert |

  (
    [$findings[]? as $f | ($f.remediation[]? // empty) |
      select(type=="string" and length>0) |
      {priority:$f.severity,recommendation:.}]
    | unique_by(.recommendation)
    | sort_by([-(.priority|sev_rank),.recommendation])
    | .[0:20]
  ) as $rem |

  ([$ev[]? | select((.source // "")=="checksec" and (.type // "")=="binary_hardening")] | length) as $elf_count |

  (
    if any($findings[]?; .severity=="CRITICAL") then "CRITICAL"
    elif any($findings[]?; .severity=="HIGH") then "HIGH"
    elif any($findings[]?; .severity=="MEDIUM") then "MEDIUM"
    elif any($findings[]?; .severity=="LOW") then "LOW"
    else "INFO" end
  ) as $risk |

  {
    tool:$tool,
    target:$target,
    summary:{
      overall_risk:$risk,
      critical:([$findings[]?|select(.severity=="CRITICAL")]|length),
      high:([$findings[]?|select(.severity=="HIGH")]|length),
      medium:([$findings[]?|select(.severity=="MEDIUM")]|length),
      low:([$findings[]?|select(.severity=="LOW")]|length),
      info:([$findings[]?|select(.severity=="INFO")]|length),
      findings:($findings|length),
      analyzed_elf:$elf_count,
      owasp_evidence:([$owasp[]|select(.status!="Limited" and .status!="Not Assessed")]|length)
    },
    findings:$findings,
    owasp_iot_top10_mapping:$owasp,
    cert_dfir:$cert,
    remediation:$rem,
    metadata:{
      rootfs_name:$rootfs_name,
      asset_count:($as|length),
      extraction_status:"SUCCESS"
    },
    limitations:[
      "본 보고서는 펌웨어 파일 기반 정적 점검 결과를 대상으로 한다.",
      "Raw Evidence는 최종 보고서와 report.json에 포함하지 않는다.",
      "자동 탐지 결과는 취약점 후보를 포함하므로 최종 판정에는 추가 검증이 필요하다.",
      "Checksec 결과는 보호기법 적용 상태이며 실제 취약 코드 존재를 직접 의미하지 않는다.",
      "구성요소 버전 힌트만으로 알려진 취약점 존재 여부를 확정하지 않는다.",
      "Firmware Update 관련 문자열만으로 Secure Update 동작의 안전성을 확정하지 않는다.",
      "실제 서비스 활성화·외부 노출·인증 우회 가능성은 동적 분석 또는 실제 장비 검증이 필요하다.",
      "OWASP I10 Physical Hardening은 펌웨어 정적 분석만으로 충분히 평가하기 어렵다."
    ]
  }
' > "$OUTDIR/report.json"

# Compact CSV for users who want a spreadsheet-friendly summary.
{
  printf '\xEF\xBB\xBF'
  echo '"ID","Severity","Title","Location","Result","Additional Check"'
  jq -r '.findings[] | [
      .id,.severity,.title,(.asset//"-"),(.result//""),(.additional_check//"")
    ] | @csv' "$OUTDIR/report.json"
} > "$OUTDIR/report.csv"

# Latest report layout, rendered entirely in shell + jq.
{
cat <<'HTML'
<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IoT 펌웨어 보안 점검 보고서</title>
<style>
:root{--bg:#f5f7fa;--card:#fff;--text:#1f2937;--muted:#667085;--line:#d9dee7;--head:#eef2f6;--critical:#7a0a0a;--high:#c73d3d; --med:#d4a017; --low:#2f5d8a}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:'Malgun Gothic','Noto Sans KR',Arial,sans-serif;line-height:1.55}
.wrap{max-width:1120px;margin:28px auto;padding:0 14px}
.card{background:#fff;border:1px solid var(--line);border-radius:12px;padding:24px;margin-bottom:14px}
h1{font-size:27px;margin:0 0 8px}
h2{font-size:21px;margin:30px 0 12px;border-bottom:2px solid #cfd5dd;padding-bottom:7px}
h3{font-size:17px;margin:20px 0 9px}
.muted{color:var(--muted);font-size:13px}
table{width:100%;border-collapse:collapse;margin:10px 0 20px;font-size:14px}
th,td{border:1px solid var(--line);padding:9px 11px;text-align:left;vertical-align:top}
th{background:var(--head)}
code{background:#f2f4f7;padding:1px 5px;border-radius:4px;font-family:Consolas,monospace;word-break:break-all}
.summary-grid{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin:14px 0 18px}
.metric{border:1px solid var(--line);border-radius:10px;padding:13px;background:#fff}
.metric .label{font-size:12px;color:#475467}
.metric .value{font-size:23px;font-weight:700}
.CRITICAL{color:var(--critical)} .HIGH{color:var(--high)} .MEDIUM{color:var(--med)} .LOW{color:var(--low)}
.risk{font-weight:800}
.note{background:#f8fafc;border-left:4px solid #94a3b8;padding:11px 13px;font-size:13px;margin:12px 0 18px}
.finding{border:1px solid var(--line);border-left:5px solid #98a2b3;border-radius:7px;padding:15px 16px 4px;margin:15px 0 22px}
.finding.high{border-left-color:var(--high)}
.finding.medium{border-left-color:var(--med)}
.badge{display:inline-block;padding:4px 9px;border-radius:999px;background:#eef2ff;color:#3730a3;font-weight:700}
.found{background:#fee4e2;color:#912018}
.potential{background:#fef0c7;color:#93370d}
.partial{background:#e0f2fe;color:#075985}
.limited{background:#eaecf0;color:#344054}
.callout{background:#f8faff;border-left:4px solid #274690;padding:13px 15px;margin:14px 0 18px}
ul{padding-left:20px}
.footer{margin-top:35px;border-top:1px solid var(--line);padding-top:10px;color:var(--muted);font-size:12px}
@media(max-width:900px){.summary-grid{grid-template-columns:repeat(3,1fr)}}
@media print{body{background:#fff}.wrap{max-width:none;margin:0}.card{border:none;padding:0}.summary-grid{grid-template-columns:repeat(6,1fr)}table,.finding{break-inside:avoid}}
</style>
</head>
<body>
<div class="wrap">
HTML

# 한국어 헤더 + jq 본문까지 하나의 카드 안에 담음
jq -r \
  --arg inspection_date "$(date '+%Y-%m-%d')" '
def e: tostring|@html;
def td($x): "<td>"+($x|e)+"</td>";
def code($x): "<code>"+($x|e)+"</code>";
def metric($label;$v;$cls):
  "<div class=\"metric\"><div class=\"label\">"+$label+"</div><div class=\"value "+$cls+"\">"+($v|tostring)+"</div></div>";
def badge($s):
  (if $s=="Evidence Found" then "found"
   elif $s=="Potential Evidence" then "potential"
   elif $s=="Partial Evidence" then "partial"
   else "limited" end) as $c |
  "<span class=\"badge "+$c+"\">"+($s|e)+"</span>";

"<div class=\"card\">"+
"<span class=\"badge\">IoT_fw_tool 자동 생성 보고서</span>"+
"<h1>IoT 펌웨어 보안 점검 보고서</h1>"+
"<p class=\"muted\">IoT_fw_tool · Firmware Security Checkup · 점검 일자: \($inspection_date|e)</p>"+
"<div class=\"callout\"><b>보고서 목적</b><br>펌웨어 정적 점검 결과를 점검 기준·Attack Vector·취약점 상세·조치방안·침해사고 대응 관점으로 구조화한 보고서입니다.</div>"+

"<h2>0. 보고서 개요</h2>"+
  "<p>Overall Risk: <span class=\"risk "+(.summary.overall_risk|e)+"\">"+(.summary.overall_risk|e)+"</span></p>"+
  "<table style=\"margin-top:18px\"><tr><th style=\"width:22%\">구분</th><th>내용</th></tr>"+
  "<tr>"+td("대상")+td(.target)+"</tr>"+
  "<tr>"+td("점검 방식")+td("펌웨어 파일 기반 정적 보안 점검")+"</tr>"+
  "<tr>"+td("분석 도구")+td("IoT_fw_tool")+"</tr>"+
  "<tr>"+td("기반 모듈")+td("binwalk / firmwalker-lite / checksec-lite")+"</tr>"+
  "<tr>"+td("분석 범위")+td("Firmware 구조, 주요 설정·서비스·Web/API·Update·Component·Crypto/Key, 주요 ELF Hardening")+"</tr>"+
  "<tr>"+td("출력")+td("HTML / JSON / CSV")+"</tr></table>"+

  "<h2>1. 요약</h2>"+
  "<p>Overall Risk: <span class=\"risk "+(.summary.overall_risk|e)+"\">"+(.summary.overall_risk|e)+"</span></p>"+
  "<p class=\"muted\">주요 설정, 원격 서비스, Key/Certificate, Firmware Update, Component 정보와 주요 ELF 보호기법을 대상으로 예방적 정적 점검을 수행하였다. 자동 탐지 결과는 추가 검증이 필요한 보안 점검 후보를 포함한다.</p>"+
  "<div class=\"summary-grid\">"+
    metric("Critical";.summary.critical;"CRITICAL")+
    metric("High";.summary.high;"HIGH")+
    metric("Medium";.summary.medium;"MEDIUM")+
    metric("Findings";.summary.findings;"")+
    metric("Analyzed ELF";.summary.analyzed_elf;"")+
    metric("OWASP Evidence";.summary.owasp_evidence;"")+
  "</div>"+
  "<div class=\"note\">Raw Evidence는 보고서에 포함하지 않는다. 전체 grep/strings 출력, 원문 자격증명 값, Private Key 본문 및 raw JSONL/TSV는 최종 보고서에 표시하지 않는다.</div></div>"+

  "<div class=\"card\"><h2>2. 점검 개요</h2>"+
  "<table><tr><th>항목</th><th>내용</th></tr>"+
  "<tr>"+td("점검 대상")+td(.target)+"</tr>"+
  "<tr>"+td("수행 환경")+td("Linux")+"</tr>"+
  "<tr>"+td("분석 방식")+td("Static Firmware Analysis")+"</tr>"+
  "<tr>"+td("RootFS 식별명")+td(.metadata.rootfs_name)+"</tr>"+
  "<tr>"+td("점검 목적")+td("배포 전 주요 위험 요소 및 보안 설정 상태를 빠르게 확인하기 위한 예방적 점검")+"</tr></table>"+

  "<h2>3. 대상 기기 및 펌웨어 정보</h2>"+
  "<table><tr><th>항목</th><th>내용</th></tr>"+
  "<tr>"+td("분석 대상")+td(.target)+"</tr>"+
  "<tr>"+td("RootFS")+td(.metadata.rootfs_name)+"</tr>"+
  "<tr>"+td("추출 상태")+td(.metadata.extraction_status)+"</tr>"+
  "<tr>"+td("분석 자산 수")+td(.metadata.asset_count)+"</tr>"+
  "<tr>"+td("주요 ELF 분석 대상")+td(.summary.analyzed_elf)+"</tr></table>"+

  "<h2>4. 점검 항목 매핑</h2>"+
  "<table><tr><th>점검 영역</th><th>주요 점검 항목</th><th>확인 정보</th><th>도구</th></tr>"+
  "<tr>"+td("Firmware Structure")+td("File system / compression / extraction")+td("펌웨어 구조 및 추출 가능 여부")+td("binwalk")+"</tr>"+
  "<tr>"+td("Credential")+td("Password / secret / token / account")+td("하드코딩 인증정보 후보")+td("firmwalker-lite")+"</tr>"+
  "<tr>"+td("Network Service")+td("Telnet / FTP / SSH / HTTP / UPnP")+td("서비스·설정·시작 흔적")+td("firmwalker-lite")+"</tr>"+
  "<tr>"+td("Web Interface")+td("CGI / API / login / session")+td("Web 관리 인터페이스 흔적")+td("firmwalker-lite")+"</tr>"+
  "<tr>"+td("Firmware Update")+td("upgrade / verify / signature / checksum")+td("업데이트·검증 관련 흔적")+td("firmwalker-lite")+"</tr>"+
  "<tr>"+td("Component")+td("BusyBox / OpenSSL / Dropbear 등")+td("구성요소 및 version hint")+td("firmwalker-lite")+"</tr>"+
  "<tr>"+td("Crypto / Key")+td("Legacy/modern crypto / certificate / key")+td("암호화 및 Key Material 후보")+td("firmwalker-lite")+"</tr>"+
  "<tr>"+td("Binary Hardening")+td("RELRO / Canary / NX / PIE / Fortify / Separate Code / CFI / Stack Clash")+td("주요 ELF 보호기법 상태")+td("checksec-lite")+"</tr></table>"+

  "<h2>5. 위험도 등급 기준</h2>"+
  "<table><tr><th>등급</th><th>기준</th></tr>"+
  "<tr>"+td("Critical")+td("즉시 대응이 필요한 매우 높은 위험")+"</tr>"+
  "<tr>"+td("High")+td("실제 악용 가능성과 직접 연결될 수 있어 우선 검증이 필요한 항목")+"</tr>"+
  "<tr>"+td("Medium")+td("추가 조건이 필요하지만 공격 표면 또는 악용 난이도에 영향을 줄 수 있는 항목")+"</tr>"+
  "<tr>"+td("Low")+td("즉각적인 악용 가능성은 낮지만 개선이 필요한 항목")+"</tr>"+
  "<tr>"+td("Info")+td("보안 상태 및 추가 분석 우선순위를 판단하기 위한 정보")+"</tr></table>"+

  "<h2>6. 진단 결과 요약</h2>"+
  "<table><tr><th>ID</th><th>점검 항목</th><th>진단 결과</th><th>위험도</th><th>위치</th></tr>"+
  (if (.findings|length)==0 then
    "<tr><td colspan=\"5\">보고 임계치를 충족한 Finding이 없습니다.</td></tr>"
   else
    ([.findings[] |
      "<tr>"+td(.id)+td(.title)+td(.result)+
      "<td class=\""+(.severity|e)+"\">"+(.severity|e)+"</td>"+
      "<td>"+code(.asset)+"</td></tr>"]|join(""))
   end)+
  "</table>"+

  "<h2>7. 진단 상세</h2>"+
  "<p class=\"muted\">Raw Evidence 원문은 삽입하지 않으며, 위치·탐지 결과·확인 근거·보안 영향·추가 확인·조치 방안을 요약하여 제공한다.</p>"+
  ([.findings[] |
    (if (.severity=="CRITICAL" or .severity=="HIGH") then "high" elif .severity=="MEDIUM" then "medium" else "" end) as $cls |
    "<section class=\"finding "+$cls+"\"><h3>"+(.id|e)+" · "+(.title|e)+" ["+(.severity|e)+"]</h3><table>"+
    "<tr><th style=\"width:22%\">위치</th><td>"+code(.asset)+"</td></tr>"+
    "<tr><th>점검 결과</th>"+td(.result)+"</tr>"+
    "<tr><th>확인 근거 요약</th>"+td(.basis)+"</tr>"+
    "<tr><th>보안 영향</th>"+td(if ((.impact//[])|length)>0 then (.impact|join("; ")) else (.analysis//"") end)+"</tr>"+
    "<tr><th>추가 확인</th>"+td(.additional_check//"")+"</tr>"+
    "<tr><th>조치 방안</th>"+td((.remediation//[])|join("; "))+"</tr></table></section>"
  ]|join(""))+

  "<h2>8. CERT / DFIR 활용 관점</h2>"+
  "<table><tr><th>Finding</th><th>위협대응 의미</th><th>사고 발생 시 확인사항</th><th>권장 증적</th></tr>"+
  (if (.cert_dfir|length)==0 then
    "<tr><td colspan=\"4\">현재 Finding에서 별도 CERT/DFIR 매핑 항목이 생성되지 않았습니다.</td></tr>"
   else
    ([.cert_dfir[] |
      "<tr>"+td(.finding)+td(.meaning)+td(.check)+td(.recommended_artifacts)+"</tr>"]|join(""))
   end)+
  "</table>"+
  "<div class=\"note\">정상 펌웨어에 존재하는 서비스·설정·Key 파일은 그 자체로 IOC가 아니다. 실제 침해 판단에는 정상 기준선, 서비스 상태, 인증·네트워크 로그 등 추가 증거가 필요하다.</div>"+

  "<h2>9. OWASP IoT Top 10 증거 매핑</h2>"+
  "<p class=\"muted\">OWASP 위반 여부를 자동 확정하는 표가 아니라, 정적 점검에서 확인된 결과가 각 위험 항목과 어떤 관련성을 가지는지 요약한다.</p>"+
  "<table><tr><th>OWASP</th><th>Category</th><th>확인된 증거 요약</th><th>관련 Finding</th><th>상태</th></tr>"+
  ([.owasp_iot_top10_mapping[] |
    "<tr>"+td(.code)+td(.category)+td(.summary)+td(.findings)+"<td>"+badge(.status)+"</td></tr>"]|join(""))+
  "</table>"+
  "<h3>상태 기준</h3>"+
  "<table><tr><th>상태</th><th>의미</th></tr>"+
  "<tr>"+td("Evidence Found")+td("현재 Finding/탐지 결과가 해당 항목과 비교적 직접적으로 연결됨")+"</tr>"+
  "<tr>"+td("Potential Evidence")+td("관련 흔적은 확인되었으나 취약 여부 판단에는 추가 검증이 필요함")+"</tr>"+
  "<tr>"+td("Partial Evidence")+td("정적 분석에서 일부 증거만 확인 가능함")+"</tr>"+
  "<tr>"+td("Limited / Not Assessed")+td("현재 도구와 정적 분석만으로 충분한 평가가 어려움")+"</tr></table>"+

  "<h2>10. 종합 조치 방안</h2>"+
  "<table><tr><th>우선순위</th><th>권고사항</th></tr>"+
  (if (.remediation|length)==0 then
    "<tr><td>Info</td><td>현재 보고 결과에 따른 별도 조치 항목이 없습니다.</td></tr>"
   else
    ([.remediation[] | "<tr>"+td(.priority)+td(.recommendation)+"</tr>"]|join(""))
   end)+
  "</table>"+

  "<h2>11. 점검 범위 및 유의사항</h2><ul>"+
  ([.limitations[] | "<li>"+(.|e)+"</li>"]|join(""))+
  "</ul><div class=\"footer\">IoT_fw_tool · Firmware Security Checkup Report</div></div></div>"
' "$OUTDIR/report.json"

echo '</body></html>'
} > "$OUTDIR/report.html"
