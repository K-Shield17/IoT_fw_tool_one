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
def conf: if .=="HIGH" then 3 elif .=="MEDIUM" then 2 elif .=="LOW" then 1 else 0 end;
def assets_for($t): [$ev[]? | select((.type//"")==$t) | (.asset//empty)] | map(select(.!="")) | unique;
def has_type($t): (assets_for($t)|length)>0;
def maxsev($a): ($a|map(.severity)|sort_by(sev)|last//"INFO");
def maxconf($a): ($a|map(.confidence)|sort_by(conf)|last//"LOW");
def loc($a): ($a|map(.asset)|map(select(.!="" and .!="-"))|unique) as $x |
  if ($x|length)==0 then "-"
  elif ($x|length)==1 then $x[0]
  else $x[0]+" 외 "+((($x|length)-1)|tostring)+"개" end;

def kt($r;$t):
  if $r=="F-01" then "네트워크 서비스 바이너리의 보호기법 미흡"
  elif $r=="F-02" then "민감 키 파일의 과도한 읽기 권한"
  elif $r=="F-03" then "취약한 Unix-MD5 비밀번호 해시 사용"
  elif $r=="F-04" then "레거시 원격 서비스 활성화"
  elif $r=="F-05" then "Web 인터페이스의 잠재적 명령 실행 경로"
  elif $r=="F-06" then "펌웨어 전반의 바이너리 보호기법 미흡"
  elif $r=="F-07" then "잠재적으로 안전하지 않은 펌웨어 업데이트"
  elif $r=="F-08" then "잠재적으로 취약한 구성요소 사용"
  else $t end;

def kr($r;$x):
  if $r=="F-01" then "네트워크 서비스로 분류된 ELF에서 복수의 주요 보호기법 미적용 상태가 확인됨."
  elif $r=="F-02" then "민감 키 파일이 group 또는 other 사용자에게 읽기 가능한 권한으로 확인됨."
  elif $r=="F-03" then "Credential store에서 취약한 Unix-MD5 비밀번호 해시가 확인됨."
  elif $r=="F-04" then "레거시 Telnet 원격 서비스가 시작 또는 서비스 설정에서 활성화된 흔적이 확인됨."
  elif $r=="F-05" then "Web 경로에서 명령 실행 관련 문자열이 확인되어 잠재적 명령 실행 경로로 분류됨."
  elif $r=="F-06" then "다수의 사용자 영역 ELF에서 바이너리 보호기법 미흡 패턴이 반복적으로 확인됨."
  elif $r=="F-07" then "업데이트 검증 관련 정적 분석 결과에서 Secure Update 보장 여부를 추가 확인해야 하는 조건이 확인됨."
  elif $r=="F-08" then "구성요소 또는 버전 정보에서 알려진 취약 버전 가능성을 추가 확인해야 하는 조건이 확인됨."
  else $x end;

def ki($r;$a):
  if $r=="F-01" then ["메모리 손상 취약점이 존재할 경우 적용되지 않은 보호기법으로 인해 공격 악용 저항성이 낮아질 수 있음"]
  elif $r=="F-02" then ["민감 키가 비인가 사용자 또는 프로세스에 노출될 경우 인증 우회·서비스 사칭·키 재사용 위험이 증가할 수 있음"]
  elif $r=="F-03" then ["Credential store 유출 시 비밀번호 해시의 오프라인 크래킹 위험이 증가할 수 있음"]
  elif $r=="F-04" then ["평문 기반 원격 관리 채널과 불필요한 원격 Attack Surface가 증가할 수 있음"]
  elif $r=="F-05" then ["입력값이 명령 실행 Sink까지 연결되는 경우 원격 명령 실행으로 이어질 수 있음"]
  elif $r=="F-06" then ["취약점 존재 시 펌웨어 전반에서 exploit resistance가 낮아질 수 있음"]
  elif $r=="F-07" then ["업데이트 검증이 충분하지 않을 경우 변조된 펌웨어 설치 위험으로 이어질 수 있음"]
  elif $r=="F-08" then ["실제 취약 버전일 경우 해당 구성요소의 알려진 취약점에 노출될 수 있음"]
  else $a end;

def kc($r;$x):
  if $r=="F-01" then "서비스의 실제 활성화·외부 노출 여부와 네트워크 입력 처리 코드의 메모리 안전성 취약점을 확인"
  elif $r=="F-02" then "키의 실제 사용 서비스, 장비별 고유성 및 접근 가능한 계정 범위를 확인"
  elif $r=="F-03" then "Credential store 접근 가능성, 계정 사용 여부 및 해당 계정의 권한을 확인"
  elif $r=="F-04" then "실제 장비에서 Telnet 활성화 여부, 외부 접근 가능 범위 및 인증 정책을 확인"
  elif $r=="F-05" then "사용자 입력이 system/exec/popen 등 명령 실행 지점까지 전달되는 Source-to-Sink 흐름을 확인"
  elif $r=="F-06" then "펌웨어 빌드 정책 및 Toolchain Hardening 설정을 확인"
  elif $r=="F-07" then "업데이트 파일의 서명·무결성 검증이 실제 업데이트 과정에서 강제되는지 확인"
  elif $r=="F-08" then "구성요소의 정확한 버전과 적용 가능한 CVE 및 실제 취약 코드 포함 여부를 확인"
  else $x end;

def krem($r;$a):
  if $r=="F-01" then ["네트워크 서비스 바이너리에 실제 누락된 Stack Canary, PIE, Full RELRO, NX 등의 보호기법 적용"]
  elif $r=="F-02" then ["민감 키 파일은 실제 사용하는 서비스 계정만 접근할 수 있도록 파일 권한 최소화"]
  elif $r=="F-03" then ["Unix-MD5 기반 비밀번호 저장 방식을 안전한 비밀번호 해시 방식으로 변경하고 영향받는 Credential 교체"]
  elif $r=="F-04" then ["Telnet 원격 서비스를 비활성화하고 필요한 원격 관리 기능은 SSH 등 암호화된 프로토콜로 전환"]
  elif $r=="F-05" then ["외부 입력과 명령 실행 함수 사이의 Source-to-Sink 흐름을 검토하고 안전한 API 및 입력 검증 적용"]
  elif $r=="F-06" then ["반복적인 Hardening 미흡을 방지하도록 Firmware Toolchain 및 릴리스 빌드에 공통 Hardening 정책 적용"]
  elif $r=="F-07" then ["업데이트 패키지에 전자서명 기반 출처 검증과 무결성 검사를 적용하고 검증 실패 시 설치 차단"]
  elif $r=="F-08" then ["구성요소 버전을 식별·관리하고 알려진 취약점이 없는 지원 버전으로 업데이트"]
  else $a end;

def ev_has($e;$p): any($e[]?;tostring|test($p;"i"));

def role_from($e):
  ([$e[]? | tostring | select(test("^Role:")) | sub("^Role:[ ]*";"")] | first) // "Network Service";

def startup_from($e):
  if ev_has($e;"Startup/config reference:[ ]*true") then "확인"
  elif ev_has($e;"Startup/config reference:[ ]*false") then "미확인"
  else "정보 없음" end;

def f01_problem($e):
  [
    if ev_has($e;"No Canary") then "Stack Canary 미적용" else empty end,
    if ev_has($e;"PIE Disabled") then "PIE Disabled" else empty end,
    if ev_has($e;"No RELRO") then "No RELRO"
    elif ev_has($e;"Partial RELRO") then "Partial RELRO" else empty end,
    if ev_has($e;"NX disabled|NX Disabled") then "NX Disabled" else empty end,
    if ev_has($e;"RPATH.*(unsafe|enabled)") then "Unsafe RPATH" else empty end,
    if ev_has($e;"RUNPATH.*(unsafe|enabled)") then "Unsafe RUNPATH" else empty end
  ];

def f01_normal($e):
  [
    if ev_has($e;"NX enabled|NX Enabled") then "NX Enabled" else empty end,
    if ev_has($e;"Full RELRO") then "Full RELRO" else empty end,
    if ev_has($e;"Canary.*(found|enabled|yes)") and (ev_has($e;"No Canary")|not) then "Stack Canary 적용" else empty end,
    if ev_has($e;"PIE Enabled") then "PIE Enabled" else empty end
  ];

def f01_rem($e):
  [
    if ev_has($e;"No Canary") then "Stack Canary 적용" else empty end,
    if ev_has($e;"PIE Disabled") then "PIE 적용" else empty end,
    if ev_has($e;"No RELRO|Partial RELRO") then "Full RELRO 적용" else empty end,
    if ev_has($e;"NX disabled|NX Disabled") then "NX 활성화" else empty end,
    if ev_has($e;"RPATH.*(unsafe|enabled)|RUNPATH.*(unsafe|enabled)") then "불필요하거나 안전하지 않은 RPATH/RUNPATH 제거" else empty end
  ] | unique;

def f01_judgment($e):
  (f01_problem($e)) as $p |
  (role_from($e)) as $role |
  (startup_from($e)) as $st |
  ($role+" 실행파일에서 "+(($p|length)|tostring)+"개의 주요 보호기법 미흡이 확인됨. "+
   (if (f01_normal($e)|length)>0 then "현재 정상 적용된 항목은 "+(f01_normal($e)|join(", "))+"임. " else "" end)+
   (if $st=="확인" then "Startup/Config 참조가 확인되어 실제 서비스 구성에 포함된 정황이 있음."
    elif $st=="미확인" then "Startup/Config 참조는 확인되지 않아 실제 실행 여부에 대한 추가 확인이 필요함."
    else "실제 서비스 활성화 여부는 추가 확인이 필요함." end));

def f01_check($e):
  if startup_from($e)=="미확인" then
    "해당 바이너리의 실제 실행 여부와 서비스 활성화 여부를 우선 확인하고, 사용 중인 경우 외부 접근 가능성과 네트워크 입력 처리 코드의 메모리 안전성을 확인"
  else
    "해당 서비스의 실제 활성화·외부 접근 가능 여부와 네트워크 입력 처리 코드의 메모리 안전성을 확인"
  end;

def detail($r;$asset;$e;$analysis;$impact;$rem):
  if $r=="F-01" then {
    asset:$asset,
    role:role_from($e),
    problems:f01_problem($e),
    normal:f01_normal($e),
    context:((role_from($e))+" / Startup·Config Reference "+(startup_from($e))),
    judgment:f01_judgment($e),
    impact:ki($r;$impact),
    additional_check:f01_check($e),
    remediation:f01_rem($e)
  }
  elif $r=="F-02" then {
    asset:$asset,role:"Sensitive Key Material",
    problems:["민감 키 파일의 읽기 권한 범위가 필요 이상으로 넓음"],normal:[],
    context:"Key/SSH Material 및 파일 권한 정보 확인",
    judgment:"민감 키 자료와 파일 권한을 함께 분석한 결과 group 또는 other 사용자에게 읽기 권한이 허용된 상태가 확인됨.",
    impact:ki($r;$impact),additional_check:kc($r;""),remediation:krem($r;$rem)
  }
  elif $r=="F-03" then {
    asset:$asset,role:"Credential Store",
    problems:["Unix-MD5($1$) 비밀번호 해시 사용"],normal:[],
    context:"Credential 관련 정적 Evidence 확인",
    judgment:"Credential 관련 데이터에서 Unix-MD5($1$) 형식의 비밀번호 해시가 확인됨. Credential store가 노출될 경우 현대적인 비밀번호 해시보다 오프라인 크래킹 저항성이 낮을 수 있음.",
    impact:ki($r;$impact),additional_check:kc($r;""),remediation:krem($r;$rem)
  }
  elif $r=="F-04" then {
    asset:$asset,role:"Telnet Service",
    problems:["Telnet 원격 서비스 구성요소 활성화 정황"],normal:[],
    context:"Telnet 구성요소 및 Startup/Config Reference 확인",
    judgment:"Telnet 서비스 구성요소와 시작 또는 서비스 설정 참조가 함께 확인되어 실제 원격 관리 서비스로 사용될 가능성이 높은 상태임.",
    impact:ki($r;$impact),additional_check:kc($r;""),remediation:krem($r;$rem)
  }
  elif $r=="F-05" then {
    asset:$asset,role:"Web Interface",
    problems:["Web 경로에서 명령 실행 관련 문자열 확인"],normal:[],
    context:"Web 서비스 구성요소 및 Sensitive Pattern 확인",
    judgment:"Web 인터페이스 영역에서 명령 실행 관련 문자열이 확인됨. 다만 현재 정적 분석만으로 사용자 입력이 실제 명령 실행 Sink까지 연결된 것은 확인되지 않음.",
    impact:ki($r;$impact),additional_check:kc($r;""),remediation:krem($r;$rem)
  }
  elif $r=="F-07" then {
    asset:$asset,role:"Firmware Update",
    problems:["Secure Update 검증 여부 추가 확인 필요"],normal:[],
    context:"Firmware Update 관련 정적 Evidence 확인",
    judgment:kr($r;$analysis),impact:ki($r;$impact),additional_check:kc($r;""),remediation:krem($r;$rem)
  }
  elif $r=="F-08" then {
    asset:$asset,role:"Embedded Component",
    problems:["구성요소의 알려진 취약 버전 여부 추가 확인 필요"],normal:[],
    context:"Component 및 Version 관련 정적 Evidence 확인",
    judgment:kr($r;$analysis),impact:ki($r;$impact),additional_check:kc($r;""),remediation:krem($r;$rem)
  }
  else {
    asset:$asset,role:"Security Asset",problems:[],normal:[],context:"정적 분석 결과",
    judgment:kr($r;$analysis),impact:ki($r;$impact),additional_check:kc($r;""),remediation:krem($r;$rem)
  } end;

def detail_key:
  [(.problems//[]|sort|join("|")),(.normal//[]|sort|join("|")),
   (.impact//[]|sort|join("|")),(.additional_check//""),(.remediation//[]|sort|join("|"))] | join("###");

def supp($type;$title;$result;$check;$rem):
  (assets_for($type)) as $a |
  if ($a|length)==0 then empty else {
    kind:"supplementary",rule_id:"",finding_status:"INFORMATIONAL",title:$title,severity:"INFO",confidence:"LOW",
    asset:(if ($a|length)==1 then $a[0] else $a[0]+" 외 "+((($a|length)-1)|tostring)+"개" end),
    locations:$a,category:$type,result:$result,basis:"관련 경로 "+(($a|length)|tostring)+"개에서 해당 유형의 정적 탐지 결과 확인",
    analysis:$result,additional_check:$check,impact:[],remediation:[$rem],detail_groups:[]
  } end;

($c[0]//{security_cases:[],systemic_findings:[],informational:[]}) as $r |

([$r.security_cases[]? |
  ((.evidence//[])+(.confidence_basis//[])|map(tostring)) as $e |
  detail((.rule_id//"");(.asset//"-");$e;(.analysis//"");(.potential_impact//[]);(.remediation//[])) as $d |
  {
    kind:"security_case",rule_id:(.rule_id//""),finding_status:(.finding_status//"IDENTIFIED"),
    title:kt((.rule_id//"");(.title//"Security Finding")),
    severity:((.severity//"INFO")|ascii_upcase),confidence:((.confidence//"LOW")|ascii_upcase),
    asset:(.asset//"-"),category:(.category//""),result:kr((.rule_id//"");(.analysis//"")),
    detail:$d
  }
]) as $security_cases |

($security_cases | sort_by(.rule_id) | group_by(.rule_id) | map(
  . as $g |
  ($g|map(.detail + {severity:.severity})|sort_by(detail_key)|group_by(detail_key)|map(
    . as $d | {
      asset_roles:($d|map({asset:.asset,role:.role})|unique_by([.asset,.role])),
      assets:($d|map(.asset)|unique),
      role:$d[0].role,
      problems:$d[0].problems,
      normal:$d[0].normal,
      context:($d[0].context|sub("^.* / ";"")),
      judgment:(
        if ($d|length)>1 then
          "해당 실행파일들에서 "+(($d[0].problems|length)|tostring)+"개의 주요 보호기법 미흡이 동일하게 확인됨. "+
          (if ($d[0].normal|length)>0 then "현재 정상 적용된 항목은 "+($d[0].normal|join(", "))+"임. " else "" end)+
          (if ($d[0].context|test("Reference 확인$")) then "Startup/Config 참조가 확인되어 실제 서비스 구성에 포함된 정황이 있음."
           elif ($d[0].context|test("Reference 미확인$")) then "Startup/Config 참조는 확인되지 않아 실제 실행 여부에 대한 추가 확인이 필요함."
           else "실제 서비스 활성화 여부는 추가 확인이 필요함." end)
        else $d[0].judgment end),
      impact:$d[0].impact,
      additional_check:$d[0].additional_check,
      remediation:$d[0].remediation
    }
  )) as $dg |
  {
    kind:"security_group",rule_id:$g[0].rule_id,
    finding_status:(if any($g[];.finding_status=="IDENTIFIED") then "IDENTIFIED" elif any($g[];.finding_status=="POTENTIAL") then "POTENTIAL" else $g[0].finding_status end),
    title:$g[0].title,severity:maxsev($g),confidence:maxconf($g),
    asset:loc($g),locations:($g|map(.asset)|unique),category:$g[0].category,
    result:(if ($g|length)>1 then $g[0].result+" 영향 위치 "+(($g|length)|tostring)+"개가 확인됨." else $g[0].result end),
    analysis:$g[0].result,impact:($dg|map(.impact[])|unique),
    additional_check:kc($g[0].rule_id;""),
    remediation:krem($g[0].rule_id;[]),
    detail_groups:$dg,
    case_count:($g|length)
  }
)) as $security |

([$r.systemic_findings[]? | {
  kind:"systemic",rule_id:(.rule_id//"F-06"),finding_status:(.finding_status//"IDENTIFIED"),
  title:kt((.rule_id//"F-06");(.title//"Systemic Finding")),
  severity:((.severity//"INFO")|ascii_upcase),confidence:((.confidence//"HIGH")|ascii_upcase),
  asset:"Firmware-wide",locations:["Firmware-wide"],category:(.category//"systemic"),
  result:kr((.rule_id//"F-06");(.analysis//"")),
  analysis:kr((.rule_id//"F-06");(.analysis//"")),
  impact:ki((.rule_id//"F-06");(.potential_impact//[])),
  additional_check:kc((.rule_id//"F-06");""),
  remediation:krem((.rule_id//"F-06");(.remediation//[])),
  detail_groups:[{
    assets:["Firmware-wide"],role:"Firmware Build / Toolchain",
    problems:["다수 사용자 영역 ELF에서 Binary Hardening 미흡 반복"],
    normal:[],
    context:((.analysis_scope//{}) as $x |
      ($x.analyzed_executables//$x.total_executables//$x.exec_total//null) as $total |
      ($x.affected_executables//$x.weak_executables//$x.weak_count//null) as $affected |
      ($x.affected_percentage//$x.weak_percentage//$x.weak_percent//null) as $pct |
      if ($total!=null and $affected!=null) then
        "분석 ELF "+($total|tostring)+"개 중 "+($affected|tostring)+"개"+(if $pct!=null then " ("+($pct|tostring)+"%)" else "" end)+"에서 반복 패턴 확인"
      else "다수 바이너리에서 반복되는 Hardening 미흡 패턴 확인" end),
    judgment:"여러 사용자 영역 ELF에서 유사한 Hardening 미흡이 반복되어 개별 바이너리뿐 아니라 공통 Toolchain 또는 빌드 정책 수준의 문제 가능성이 있음.",
    impact:ki((.rule_id//"F-06");(.potential_impact//[])),
    additional_check:kc((.rule_id//"F-06");""),
    remediation:krem((.rule_id//"F-06");(.remediation//[]))
  }],
  case_count:1
}]) as $systemic |

([
  supp("update";"펌웨어 업데이트 관련 정보";"펌웨어 업데이트 또는 검증과 관련된 정적 흔적이 확인됨";"업데이트 무결성 및 서명 검증이 실제로 강제되는지 확인";"업데이트 서명 검증과 무결성 검사를 릴리스 절차에 포함"),
  supp("component";"임베디드 구성요소 정보";"오픈소스 또는 임베디드 구성요소 관련 정보가 확인됨";"정확한 버전과 알려진 취약점 존재 여부 확인";"구성요소 인벤토리를 관리하고 지원되는 안정 버전 사용"),
  supp("web_interface";"Web/API 인터페이스 정보";"Web, CGI 또는 API 관리 인터페이스 관련 정적 흔적이 확인됨";"인증, 세션 처리 및 입력 검증 로직 확인";"관리 인터페이스 접근통제와 입력 검증 강화"),
  supp("service";"네트워크 서비스 탐지 정보";"네트워크 또는 원격 서비스 관련 실행파일 및 설정 흔적이 확인됨";"서비스의 실제 활성화 여부와 외부 노출 여부 확인";"불필요한 서비스를 비활성화하고 최소 노출 원칙 적용"),
  supp("crypto";"암호화/키 자료 탐지 정보";"암호화 알고리즘 또는 Key/Certificate 관련 정적 흔적이 확인됨";"Key 권한, 고유성 및 실제 사용 서비스 확인";"안전한 Key 관리 정책 적용"),
  supp("ssh";"SSH 관련 자료 탐지 정보";"SSH 관련 Key 또는 설정 흔적이 확인됨";"장비별 고유 Key 여부와 SSH 서비스 사용 정책 확인";"불필요한 SSH 접근 제한 및 Key 수명주기 관리"),
  supp("credential";"인증정보 탐지 정보";"계정, 비밀번호 또는 인증정보 관련 후보가 확인됨";"실제 하드코딩 또는 기본 Credential 여부 확인";"하드코딩 Credential을 제거하고 장비별 고유 Credential 사용"),
  supp("database";"데이터베이스/저장 데이터 정보";"Database 또는 저장 데이터 관련 파일이 확인됨";"민감정보 저장 여부 및 파일 접근 권한 확인";"민감정보 저장을 최소화하고 접근 권한 제한")
]) as $supp |

(($security+$systemic+$supp) | sort_by([-(.severity|sev),.title]) | to_entries |
  map(.value + {id:("FW-"+(if (.key+1)<10 then "00" elif (.key+1)<100 then "0" else "" end)+((.key+1)|tostring))})
) as $findings |

def ids($r): [$findings[]? | select(.rule_id==$r) | .id];
def rule_status($r):
  [$findings[]? | select(.rule_id==$r) | (.finding_status//"IDENTIFIED")] as $s |
  if any($s[]?;.=="POTENTIAL") then "Potential Finding" else "Finding Identified" end;
def ow($code;$cat;$summary;$ids;$status):
  {code:$code,category:$cat,summary:$summary,findings:(if ($ids|length)>0 then ($ids|join(", ")) else "-" end),status:$status};

([
  (ids("F-03") as $i | if ($i|length)>0 then ow("I1";"Weak, Guessable, or Hardcoded Passwords";"약한 Unix-MD5 비밀번호 해시 저장 Finding이 확인됨";$i;rule_status("F-03"))
   elif has_type("credential") then ow("I1";"Weak, Guessable, or Hardcoded Passwords";"Credential 관련 정적 흔적은 있으나 취약 Finding 조건은 충족하지 않음";[];"Related Evidence Only") else empty end),
  (ids("F-04") as $i | if ($i|length)>0 then ow("I2";"Insecure Network Services";"Telnet 원격 서비스 관련 Finding이 확인됨";$i;rule_status("F-04"))
   elif has_type("service") then ow("I2";"Insecure Network Services";"네트워크 서비스 관련 정적 흔적은 있으나 insecure service Finding 조건은 충족하지 않음";[];"Related Evidence Only") else empty end),
  (ids("F-05") as $i | if ($i|length)>0 then ow("I3";"Insecure Ecosystem Interfaces";"Web 명령 실행 관련 Finding이 확인됨";$i;rule_status("F-05"))
   elif has_type("web_interface") then ow("I3";"Insecure Ecosystem Interfaces";"Web/API 관련 정적 흔적은 있으나 취약 Finding 조건은 충족하지 않음";[];"Related Evidence Only") else empty end),
  (ids("F-07") as $i | if ($i|length)>0 then ow("I4";"Lack of Secure Update Mechanisms";"Firmware Update 보안 관련 Finding이 확인됨";$i;rule_status("F-07"))
   elif has_type("update") then ow("I4";"Lack of Secure Update Mechanisms";"Firmware Update 또는 검증 관련 흔적이 확인되었으나 Secure Update 여부는 확정하지 않음";[];"Related Evidence Only") else empty end),
  (ids("F-08") as $i | if ($i|length)>0 then ow("I5";"Use of Insecure or Outdated Components";"취약한 구성요소 사용 관련 Finding이 확인됨";$i;rule_status("F-08"))
   elif has_type("component") then ow("I5";"Use of Insecure or Outdated Components";"구성요소 또는 버전 관련 정보가 확인되었으나 알려진 취약 버전 여부는 확정하지 않음";[];"Related Evidence Only") else empty end),
  (ids("F-02") as $i | if ($i|length)>0 then ow("I7";"Insecure Data Transfer and Storage";"민감 Key Material의 과도한 읽기 권한 Finding이 확인됨";$i;rule_status("F-02"))
   elif (has_type("crypto") or has_type("ssh")) then ow("I7";"Insecure Data Transfer and Storage";"Crypto 또는 SSH 관련 정적 흔적은 있으나 취약 Finding 조건은 충족하지 않음";[];"Related Evidence Only") else empty end),
  (if has_type("config") then ow("I9";"Insecure Default Settings";"보안 관련 Configuration 흔적이 확인되어 기본 설정 검토가 필요함";[];"Related Evidence Only") else empty end)
]) as $owasp |

def cert($r;$finding;$meaning;$check;$artifacts):
  if any($findings[]?;.rule_id==$r) then
    {rule_id:$r,finding:$finding,meaning:$meaning,check:$check,artifacts:$artifacts}
  else empty end;

([
  cert("F-01";"네트워크 서비스 바이너리 보호기법 미흡";"침해 발생 시 해당 네트워크 서비스가 초기 진입점 또는 취약점 악용 대상이었는지 확인";"서비스 실행·외부 노출·Crash·비정상 입력 및 해당 프로세스의 행위를 확인";"서비스 설정, 네트워크 로그, Process 정보, Core dump, 대상 ELF"),
  cert("F-02";"민감 Key 노출";"공격자가 노출된 Key Material을 획득하거나 인증에 재사용했는지 확인";"해당 Key 사용 서비스, Key 접근 범위, 동일 Key 공유 여부와 비정상 인증을 확인";"Key/Certificate metadata, SSH/TLS 설정, 인증 로그"),
  cert("F-03";"취약한 Credential 저장";"Credential store 탈취 및 오프라인 크래킹 이후 계정 악용 여부 확인";"Credential store 접근, 비정상 로그인, 영향 계정과 권한을 확인";"passwd/shadow, 인증 로그, 계정 설정"),
  cert("F-04";"Telnet 원격 서비스";"Telnet 관리 채널을 통한 비인가 원격 접근 여부 확인";"Telnet 활성화 시점, 접속 출발지, 로그인 계정 및 세션 이후 행위를 확인";"인증 로그, Telnet 관련 설정, 네트워크 로그, Process 정보"),
  cert("F-05";"Web 명령 실행 가능성";"Web 인터페이스가 명령 실행 또는 초기 침투 경로로 악용되었는지 확인";"의심 요청, 입력값, 실행된 명령 및 Web 프로세스의 자식 프로세스를 확인";"Web/CGI 파일, HTTP 로그, Process tree, 네트워크 로그"),
  cert("F-06";"펌웨어 전반의 Hardening 미흡";"침해된 프로세스와 동일한 빌드 정책을 사용하는 다른 ELF의 공격 노출 범위를 확인";"침해 대상 ELF와 동일 Toolchain으로 빌드된 실행파일의 보호기법 상태를 확인";"ELF metadata, Build/Toolchain 설정, Decompile 결과"),
  cert("F-07";"Firmware Update 보안";"변조되거나 비인가된 Firmware가 설치되었는지 확인";"Firmware hash, Update 시각, Signature 검증 결과 및 Version 변경을 확인";"Firmware image, Update log, Hash, Signature metadata"),
  cert("F-08";"취약 구성요소";"알려진 취약 구성요소가 실제 침해 경로로 사용되었는지 확인";"구성요소 Version, 관련 CVE, 해당 취약 기능의 사용 여부 및 공격 흔적을 확인";"Component metadata, Version 정보, 관련 로그, 대상 Binary")
]) as $cert |

def hasrule($r): any($findings[]?;.rule_id==$r);
def hassupp($t): any($findings[]?;.kind=="supplementary" and .category==$t);
def remgroup($severity;$items): ($items|map(select(.!=null))|unique) as $x |
  if ($x|length)>0 then {severity:$severity,recommendations:$x} else empty end;

([
  remgroup("HIGH";[
    if hasrule("F-02") then "민감 Key 파일의 접근 권한을 최소화하고 공유 Key 사용 시 장비별 고유 Key로 교체" else null end,
    if hasrule("F-03") then "취약한 Unix-MD5 비밀번호 저장 방식을 안전한 해시 방식으로 변경하고 영향받는 Credential 교체" else null end,
    if hasrule("F-04") then "Telnet 서비스를 비활성화하고 SSH 등 인증·암호화가 적용된 안전한 관리 프로토콜 사용" else null end
  ]),
  remgroup("MEDIUM";[
    if (hasrule("F-01") or hasrule("F-06")) then "Firmware Toolchain 및 릴리스 빌드에 Stack Canary, PIE, Full RELRO, NX 등 공통 Binary Hardening 정책 적용" else null end,
    if hasrule("F-05") then "Web/관리 인터페이스의 외부 입력 검증을 강화하고 명령 실행 경로에 안전한 API 적용" else null end,
    if hasrule("F-07") then "Firmware Update에 전자서명 기반 출처 검증과 무결성 검사를 적용하고 검증 실패 시 설치 차단" else null end,
    if hasrule("F-08") then "구성요소 및 Version을 관리하고 알려진 취약점이 있거나 지원 종료된 구성요소를 안전한 Version으로 업데이트" else null end,
    if (hassupp("service") or hassupp("web_interface")) then "불필요한 네트워크 서비스와 외부 노출을 최소화하고 관리 인터페이스의 접근 범위를 제한" else null end
  ]),
  remgroup("INFO";[
    if (hassupp("ssh") or hassupp("crypto")) then "SSH Key 및 인증정보의 장비별 고유성·수명주기를 관리하고 불필요한 Key를 제거" else null end,
    if (hassupp("credential") or hassupp("database")) then "민감정보 저장을 최소화하고 관련 파일 및 데이터의 접근 권한을 제한" else null end
  ])
] | sort_by(-(.severity|sev))) as $rem |

([$findings[]? | select(.kind!="supplementary" and .finding_status=="IDENTIFIED" and (.confidence=="HIGH" or .confidence=="MEDIUM"))]) as $validated |

def svscore: if .=="CRITICAL" then 100 elif .=="HIGH" then 75 elif .=="MEDIUM" then 50 elif .=="LOW" then 25 else 0 end;
def cfscore: if .=="HIGH" then 100 elif .=="MEDIUM" then 70 elif .=="LOW" then 40 else 0 end;
def exposed: (.category=="network_service_hardening" or .category=="legacy_remote_service" or .rule_id=="F-04" or .rule_id=="F-05");
def systemic: (.kind=="systemic" or .rule_id=="F-06");
def casecount: (.case_count//1);

(if ($validated|length)==0 then 0 else (($validated|map(.severity|svscore)|add)/($validated|length)) end) as $severity_score |
(if ($validated|length)==0 then 0 else (($validated|map(.confidence|cfscore)|add)/($validated|length)) end) as $confidence_score |
(if ($validated|length)==0 then 0 else
  (([$validated[]|select(exposed)]|length)/($validated|length)*70 +
   (if any($validated[];exposed and (casecount>=2)) then 30 else 0 end))
 end) as $exposure_score |
(if ($validated|length)==0 then 0 else
  ((if any($validated[];systemic) then 60 else 0 end) +
   (if any($validated[];casecount>=3) then 40 else 0 end))
 end) as $prevalence_score |

((($severity_score*0.45)+($confidence_score*0.20)+($exposure_score*0.20)+($prevalence_score*0.15))|round) as $risk_score |
(if $risk_score>=90 then "CRITICAL" elif $risk_score>=65 then "HIGH" elif $risk_score>=35 then "MEDIUM" else "LOW" end) as $risk |

{
  tool:$tool,target:$target,
  summary:{
    overall_risk:$risk,risk_score:$risk_score,
    risk_components:{
      severity:($severity_score|round),
      confidence:($confidence_score|round),
      exposure:($exposure_score|round),
      prevalence:($prevalence_score|round)
    },
    critical:([$findings[]?|select(.severity=="CRITICAL")]|length),
    high:([$findings[]?|select(.severity=="HIGH")]|length),
    medium:([$findings[]?|select(.severity=="MEDIUM")]|length),
    low:([$findings[]?|select(.severity=="LOW")]|length),
    info:([$findings[]?|select(.severity=="INFO")]|length),
    findings:($findings|length),
    analyzed_elf:([$ev[]?|select((.source//"")=="checksec" and (.property//"")=="hardening_profile")]|length),
    owasp_evidence:($owasp|length)
  },
  findings:$findings,
  owasp_iot_top10_mapping:$owasp,
  cert_dfir:$cert,
  remediation:$rem,
  metadata:{rootfs_name:$rootfs_name,asset_count:($as|length),extraction_status:"SUCCESS"},
  limitations:[
    "본 보고서는 펌웨어 파일 기반 정적 점검 결과를 대상으로 한다.",
    "Raw Evidence는 최종 보고서와 report.json에 포함하지 않는다.",
    "자동 탐지 결과는 취약점 후보를 포함하므로 최종 판정에는 추가 검증이 필요하다.",
    "Checksec 결과는 보호기법 적용 상태이며 실제 취약 코드 존재를 직접 의미하지 않는다.",
    "구성요소 버전 정보만으로 알려진 취약점 존재 여부를 확정하지 않는다.",
    "Firmware Update 관련 문자열만으로 Secure Update 동작의 안전성을 확정하지 않는다.",
    "실제 서비스 활성화·외부 노출·인증 우회 가능성은 동적 분석 또는 실제 장비 검증이 필요하다.",
    "Overall Risk는 Finding Rule 단위의 Severity, Confidence, 공격 표면 및 발생 범위를 종합한 내부 Firmware Risk Score를 기준으로 산정한다.",
    "동일 Finding Rule이 여러 위치에서 확인된 경우 개별 Finding으로 중복 가산하지 않고 발생 범위로 반영한다.",
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
.wrap{max-width:1120px;margin:14px auto 40px;padding:0 14px}h1{font-size:28px;margin:0 0 8px}h2{font-size:21px;margin:30px 0 12px;border-bottom:2px solid #cfd5dd;padding-bottom:7px}h3{font-size:17px;margin:20px 0 9px}h4{font-size:15px;margin:18px 0 8px}
.subtitle{color:var(--muted);font-size:13px;margin-bottom:20px}table{width:100%;border-collapse:collapse;margin:10px 0 20px;font-size:14px}th,td{border:1px solid var(--line);padding:10px 12px;text-align:left;vertical-align:top}th{background:var(--head)}
code{background:#f2f4f7;padding:1px 5px;border-radius:4px;font-family:Consolas,monospace;word-break:break-all}.paths code{display:block;margin:3px 0}.summary-grid{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin:14px 0 18px}
.metric{border:1px solid var(--line);border-radius:10px;padding:13px}.metric .label{font-size:12px;color:#475467}.metric .value{font-size:23px;font-weight:700}.CRITICAL{color:var(--critical)}.HIGH{color:var(--high)}.MEDIUM{color:var(--med)}.LOW{color:var(--low)}
.risk{font-weight:800}.note{background:#f8fafc;border-left:4px solid #94a3b8;padding:11px 13px;font-size:13px;margin:12px 0 18px}.finding{border:1px solid var(--line);border-left:5px solid #98a2b3;border-radius:7px;padding:15px 16px 4px;margin:15px 0 22px}
.finding.high{border-left-color:var(--high)}.finding.medium{border-left-color:var(--med)}.detail{border-top:1px solid #dbe2ea;margin-top:14px;padding-top:5px}.badge{display:inline-block;padding:4px 9px;border-radius:999px;font-weight:700}.found{background:#fee4e2;color:#912018}.potential{background:#fef0c7;color:#93370d}.partial{background:#e0f2fe;color:#075985}
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
def bullets($a): if (($a//[])|length)==0 then "-" else "<ul>"+([$a[]|"<li>"+(.|e)+"</li>"]|join(""))+"</ul>" end;
def paths($a): "<div class=\"paths\">"+([$a[]|code(.)]|join(""))+"</div>";
def assetroles($a): "<div class=\"paths\">"+([$a[]|code(.asset)+" — "+(.role|e)]|join(""))+"</div>";

def details($f):
  if (($f.detail_groups//[])|length)==0 then
    "<table><tr><th style=\"width:22%\">위치</th><td>"+code($f.asset)+"</td></tr>"+
    "<tr><th>점검 결과</th>"+td($f.result)+"</tr>"+
    "<tr><th>보안 영향</th><td>"+bullets($f.impact//[])+"</td></tr>"+
    "<tr><th>추가 확인</th>"+td($f.additional_check//"")+"</tr>"+
    "<tr><th>조치 방안</th><td>"+bullets($f.remediation//[])+"</td></tr></table>"
  else
    ([$f.detail_groups[] |
      "<div class=\"detail\"><table>"+
      "<tr><th style=\"width:22%\">위치 / 자산 역할</th><td>"+assetroles(.asset_roles//[.assets[]|{asset:.,role:(.role//"-")}])+"</td></tr>"+
      "<tr><th>확인된 문제</th><td>"+bullets(.problems//[])+"</td></tr>"+
      "<tr><th>정상 적용</th><td>"+bullets(.normal//[])+"</td></tr>"+
      "<tr><th>Context</th>"+td(.context//"-")+"</tr>"+
      "<tr><th>판단</th>"+td(.judgment//"-")+"</tr>"+
      "<tr><th>보안 영향</th><td>"+bullets(.impact//[])+"</td></tr>"+
      "<tr><th>추가 확인</th>"+td(.additional_check//"-")+"</tr>"+
      "<tr><th>조치 방안</th><td>"+bullets(.remediation//[])+"</td></tr>"+
      "</table></div>"
    ]|join(""))
  end;

"<h1>IoT Firmware Security Assessment</h1>"+
"<div class=\"subtitle\">Static firmware analysis · IoT_fw_tool · Preventive Security Checkup</div>"+
"<table><tr><th style=\"width:22%\">구분</th><th>내용</th></tr>"+
"<tr>"+td("대상")+td(.target)+"</tr><tr>"+td("점검 방식")+td("펌웨어 파일 기반 정적 보안 점검")+"</tr>"+
"<tr>"+td("분석 도구")+td("IoT_fw_tool")+"</tr><tr>"+td("기반 모듈")+td("binwalk-lite / firmwalker-lite / checksec-lite")+"</tr>"+
"<tr>"+td("분석 범위")+td("Firmware 구조, 주요 설정·서비스·Web/API·Update·Component·Crypto/Key, 주요 ELF Hardening")+"</tr>"+
"<tr>"+td("출력")+td("HTML / JSON / CSV")+"</tr></table>"+

"<h2>1. 요약</h2><p>Overall Risk: <span class=\"risk "+(.summary.overall_risk|e)+"\">"+(.summary.overall_risk|e)+"</span> <span class=\"subtitle\">(Firmware Risk Score "+(.summary.risk_score|tostring)+"/100)</span></p>"+
"<p class=\"subtitle\">Overall Risk는 개별 Finding의 최고 위험도를 그대로 사용하지 않고 Finding의 심각도, 탐지 신뢰도, 공격 표면 및 펌웨어 내 발생 범위를 종합하여 산정한다.</p>"+
"<div class=\"summary-grid\">"+metric("Critical";.summary.critical;"CRITICAL")+metric("High";.summary.high;"HIGH")+metric("Medium";.summary.medium;"MEDIUM")+metric("Findings";.summary.findings;"")+metric("Analyzed ELF";.summary.analyzed_elf;"")+metric("OWASP Evidence";.summary.owasp_evidence;"")+"</div>"+
"<div class=\"note\">Risk Components · Severity "+(.summary.risk_components.severity|tostring)+" / Confidence "+(.summary.risk_components.confidence|tostring)+" / Exposure "+(.summary.risk_components.exposure|tostring)+" / Prevalence "+(.summary.risk_components.prevalence|tostring)+"</div>"+
"<div class=\"note\">Raw Evidence는 보고서에 포함하지 않는다. 전체 grep/strings 출력, 원문 Credential 값, Private Key 본문 및 raw JSONL/TSV는 최종 보고서에 표시하지 않는다.</div>"+

"<h2>2. 점검 개요</h2><table><tr><th>항목</th><th>내용</th></tr>"+
"<tr>"+td("점검 대상")+td(.target)+"</tr><tr>"+td("수행 환경")+td("Linux")+"</tr><tr>"+td("분석 방식")+td("Static Firmware Analysis")+"</tr>"+
"<tr>"+td("RootFS 식별명")+td(.metadata.rootfs_name)+"</tr><tr>"+td("점검 목적")+td("배포 전 주요 위험 요소 및 보안 설정 상태를 빠르게 확인하기 위한 예방적 점검")+"</tr></table>"+

"<h2>3. 대상 기기 및 펌웨어 정보</h2><table><tr><th>항목</th><th>내용</th></tr>"+
"<tr>"+td("분석 대상")+td(.target)+"</tr><tr>"+td("RootFS")+td(.metadata.rootfs_name)+"</tr><tr>"+td("추출 상태")+td(.metadata.extraction_status)+"</tr>"+
"<tr>"+td("분석 자산 수")+td(.metadata.asset_count)+"</tr><tr>"+td("주요 ELF 분석 대상")+td(.summary.analyzed_elf)+"</tr></table>"+

"<h2>4. 점검 항목 매핑</h2><table><tr><th>점검 영역</th><th>주요 점검 항목</th><th>확인 정보</th><th>도구</th></tr>"+
"<tr>"+td("Firmware Structure")+td("File system / compression / extraction")+td("펌웨어 구조 및 추출 가능 여부")+td("binwalk-lite")+"</tr>"+
"<tr>"+td("Credential")+td("Password / secret / token / account")+td("하드코딩 인증정보 후보")+td("firmwalker-lite")+"</tr>"+
"<tr>"+td("Network Service")+td("Telnet / FTP / SSH / HTTP / UPnP")+td("서비스·설정·시작 흔적")+td("firmwalker-lite")+"</tr>"+
"<tr>"+td("Web Interface")+td("CGI / API / login / session")+td("Web 관리 인터페이스 흔적")+td("firmwalker-lite")+"</tr>"+
"<tr>"+td("Firmware Update")+td("upgrade / verify / signature / checksum")+td("업데이트·검증 관련 흔적")+td("firmwalker-lite")+"</tr>"+
"<tr>"+td("Component")+td("BusyBox / OpenSSL / Dropbear 등")+td("구성요소 및 version hint")+td("firmwalker-lite")+"</tr>"+
"<tr>"+td("Crypto / Key")+td("Legacy/modern crypto / certificate / key")+td("암호화 및 Key Material 후보")+td("firmwalker-lite")+"</tr>"+
"<tr>"+td("Binary Hardening")+td("RELRO / Canary / NX / PIE / Fortify / Separate Code / Stack Clash")+td("주요 ELF 보호기법 상태")+td("checksec-lite")+"</tr></table>"+

"<h2>5. 위험도 등급 기준</h2><table><tr><th>등급</th><th>기준</th></tr>"+
"<tr>"+td("Critical")+td("펌웨어 전반에서 매우 높은 수준의 위험이 확인되어 즉각적인 대응이 필요한 상태")+"</tr>"+
"<tr>"+td("High")+td("직접적인 보안 영향이 크고 우선 대응 및 검증이 필요한 상태")+"</tr>"+
"<tr>"+td("Medium")+td("추가 조건이 필요하지만 공격 표면 또는 악용 난이도에 영향을 줄 수 있는 상태")+"</tr>"+
"<tr>"+td("Low")+td("즉각적인 악용 가능성은 낮지만 개선이 필요한 상태")+"</tr>"+
"<tr>"+td("Info")+td("취약점으로 확정하지 않고 보안 상태 및 추가 분석 우선순위를 판단하기 위한 탐지 정보")+"</tr></table>"+

"<h2>6. 진단 결과 요약</h2><table><tr><th>ID</th><th>점검 항목</th><th>진단 결과</th><th>위험도</th><th>위치</th></tr>"+
(if (.findings|length)==0 then "<tr><td colspan=\"5\">보고 임계치를 충족한 Finding이 없습니다.</td></tr>"
else ([.findings[]|"<tr>"+td(.id)+td(.title)+td(.result)+"<td class=\""+(.severity|e)+"\">"+(.severity|e)+"</td><td>"+code(.asset)+"</td></tr>"]|join("")) end)+"</table>"+

"<h2>7. 진단 상세</h2><p class=\"subtitle\">동일 Finding에서 실제 보안 상태와 분석 결과가 동일한 대상은 하나의 상세 항목으로 통합하고, 해당하는 모든 경로를 표시한다. 상태 또는 Context가 다른 대상은 별도로 구분한다.</p>"+
(if (.findings|length)==0 then "<div class=\"note\">상세 분석 대상으로 분류된 Finding이 없습니다.</div>"
else ([.findings[] |
  (if (.severity=="CRITICAL" or .severity=="HIGH") then "high" elif .severity=="MEDIUM" then "medium" else "" end) as $c |
  "<section class=\"finding "+$c+"\"><h3>"+(.id|e)+" · "+(.title|e)+" ["+(.severity|e)+"]</h3>"+details(.)+"</section>"
]|join("")) end)+

"<h2>8. CERT / DFIR 활용 관점</h2><table><tr><th>관련 Finding</th><th>사고 대응 관점</th><th>사고 발생 시 확인사항</th><th>권장 증적</th></tr>"+
(if (.cert_dfir|length)==0 then "<tr><td colspan=\"4\">현재 Finding에서 별도 CERT/DFIR 매핑 항목이 생성되지 않았습니다.</td></tr>"
else ([.cert_dfir[]|"<tr>"+td(.rule_id+" · "+.finding)+td(.meaning)+td(.check)+td(.artifacts)+"</tr>"]|join("")) end)+"</table>"+
"<div class=\"note\">CERT / DFIR 항목은 실제 발생한 Finding Rule에 따라 생성된다. 정상 펌웨어에 존재하는 서비스·설정·Key 파일은 그 자체로 IOC가 아니며 실제 침해 판단에는 로그, 서비스 상태 및 네트워크 행위 등 추가 증거가 필요하다.</div>"+

"<h2>9. OWASP IoT Top 10 증거 매핑</h2><p class=\"subtitle\">OWASP IoT Top 10 전체 항목이 아니라 현재 펌웨어에서 Security Finding 또는 관련 정적 Evidence가 확인된 항목만 표시한다.</p>"+
(if (.owasp_iot_top10_mapping|length)==0 then "<div class=\"note\">현재 분석 결과에서 직접 관련된 OWASP IoT Top 10 항목이 확인되지 않았습니다.</div>"
else "<table><tr><th>OWASP</th><th>Category</th><th>확인된 증거 요약</th><th>관련 Finding</th><th>상태</th></tr>"+
([.owasp_iot_top10_mapping[]|"<tr>"+td(.code)+td(.category)+td(.summary)+td(.findings)+"<td>"+badge(.status)+"</td></tr>"]|join(""))+"</table>" end)+
"<h3>상태 기준</h3><table><tr><th>상태</th><th>의미</th></tr>"+
"<tr>"+td("Finding Identified")+td("정의된 Finding Rule 조건을 충족하여 보안 Finding으로 분류됨")+"</tr>"+
"<tr>"+td("Potential Finding")+td("보안 영향 가능성은 있으나 현재 정적 분석만으로 exploit path가 확정되지 않음")+"</tr>"+
"<tr>"+td("Related Evidence Only")+td("관련 정적 흔적은 있으나 Finding 조건을 충족하지 않음")+"</tr></table>"+

"<h2>10. 종합 조치 방안</h2><p class=\"subtitle\">진단 상세에서 제시된 개별 조치 중 동일하거나 중복되는 내용을 통합하여 주요 권고사항만 표시한다.</p>"+
"<table><tr><th style=\"width:18%\">관련 위험도</th><th>권고사항</th></tr>"+
(if (.remediation|length)==0 then "<tr>"+td("INFO")+td("현재 보고 결과에 따른 별도 조치 항목이 없습니다.")+"</tr>"
else ([.remediation[]|"<tr><td class=\""+(.severity|e)+"\">"+(.severity|e)+"</td><td>"+bullets(.recommendations//[])+"</td></tr>"]|join("")) end)+"</table>"+

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
