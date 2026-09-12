#!/usr/bin/env bash
set -euo pipefail
ROOTFS="$1"; CORRELATED="$2"; EVIDENCE="$3"; ASSETS="$4"; OUTDIR="$5"
mkdir -p "$OUTDIR" "$OUTDIR/raw"
SORTED="$OUTDIR/raw/correlated.sorted.json"; REPORT_JSON="$OUTDIR/report.json"; REPORT_HTML="$OUTDIR/report.html"; FINDINGS_CSV="$OUTDIR/findings.csv"

# Security Findings 우선순위 정렬
jq '
  def sev: if .=="CRITICAL" then 4 elif .=="HIGH" then 3 elif .=="MEDIUM" then 2 elif .=="LOW" then 1 else 0 end;
  def conf: if .=="HIGH" then 3 elif .=="MEDIUM" then 2 elif .=="LOW" then 1 else 0 end;
  .security_cases |= sort_by([-(.severity|sev),-(.confidence|conf),.rule_id,.asset])
' "$CORRELATED" > "$SORTED"

TARGET="$(basename "$OUTDIR")"; ROOTFS_NAME="$(basename "${ROOTFS%/}")"

# report.json
jq -n --arg tool "IoT_fw_tool" --arg target "$TARGET" --arg rootfs_name "$ROOTFS_NAME" \
  --slurpfile c "$SORTED" --slurpfile ev "$EVIDENCE" --slurpfile as "$ASSETS" '

  def assets_for($type):
    [$ev[]? | select((.type // "")==$type) | (.asset // empty)] | map(select(.!="")) | unique;

  def detected($type;$title;$description;$next_check):
    (assets_for($type)) as $a |
    if ($a|length)==0 then empty else
      {type:$type,title:$title,count:($a|length),assets:$a,description:$description,next_check:$next_check}
    end;

  ($c[0] // {security_cases:[],systemic_findings:[],informational:[]}) as $r |

  ([
    $r.security_cases[]? | {
      id:(.id//""),rule_id:(.rule_id//""),finding_status:(.finding_status//"IDENTIFIED"),
      title:(.title//"Security Finding"),severity:((.severity//"INFO")|ascii_upcase),
      confidence:((.confidence//"LOW")|ascii_upcase),asset:(.asset//"-"),category:(.category//""),
      analysis:(.analysis//""),attack_scenario:(.attack_scenario//""),potential_impact:(.potential_impact//[]),
      remediation:(.remediation//[]),evidence:(.evidence//[]),severity_basis:(.severity_basis//{}),
      confidence_basis:(.confidence_basis//[])
    }
  ]) as $security_findings |

  ([
    $r.systemic_findings[]? | {
      rule_id:(.rule_id//""),finding_status:(.finding_status//"IDENTIFIED"),title:(.title//"Systemic Finding"),
      severity:((.severity//"INFO")|ascii_upcase),confidence:((.confidence//"LOW")|ascii_upcase),
      category:(.category//"systemic"),analysis:(.analysis//""),analysis_scope:(.analysis_scope//{}),
      threshold_basis:(.threshold_basis//{}),remediation:(.remediation//[])
    }
  ]) as $systemic_findings |

  # 탐지 정보: 존재 자체를 취약점으로 판단하지 않음
  ([
    detected("service";"Network Service Indicators";"Network or remote-service related binaries/configuration were detected.";"Confirm whether each service is active, reachable and securely configured."),
    detected("ssh";"SSH Material";"SSH-related keys or configuration artifacts were detected.";"Review key uniqueness, permissions and SSH service policy."),
    detected("crypto";"Cryptographic / Key Material";"Cryptographic algorithms, keys or certificate-related artifacts were detected.";"Review key permissions, key uniqueness and actual cryptographic usage."),
    detected("credential";"Credential Indicators";"Account, password or authentication-related artifacts were detected.";"Determine whether credentials are hardcoded, default or otherwise weak."),
    detected("update";"Firmware Update Mechanism";"Firmware update or verification-related artifacts were detected.";"Verify whether authenticity and integrity checks are actually enforced."),
    detected("component";"Embedded Component Information";"Embedded/open-source component or version-related information was detected.";"Identify exact versions and correlate them with maintained vulnerability data."),
    detected("web_interface";"Web / API Interface";"Web, CGI or API-related interface artifacts were detected.";"Review authentication, session handling and input validation."),
    detected("database";"Database / Stored Data";"Database or stored-data related files were detected.";"Review stored information, permissions and protection of sensitive data."),
    detected("config";"Configuration Files";"Security-relevant configuration files were detected.";"Review default settings and service configuration.")
  ]) as $detected_information |

  # OWASP는 raw evidence가 아닌 실제 Finding Rule을 기준으로 연결
  def findings_for_rule($rule): [$security_findings[]? | select(.rule_id==$rule) | .id];
  def ow($code;$category;$rules;$fallback):
    ([$rules[] as $rule | findings_for_rule($rule)[]] | unique) as $ids |
    {code:$code,category:$category,status:(if ($ids|length)>0 then "Finding Identified" else $fallback end),findings:$ids};

  ([
    ow("I1";"Weak, Guessable, or Hardcoded Passwords";["F-03"];"No Finding Identified"),
    ow("I2";"Insecure Network Services";["F-04"];"No Finding Identified"),
    ow("I3";"Insecure Ecosystem Interfaces";["F-05"];"No Finding Identified"),
    ow("I4";"Lack of Secure Update Mechanisms";[];(if (assets_for("update")|length)>0 then "Related Evidence Only" else "Not Assessed" end)),
    ow("I5";"Use of Insecure or Outdated Components";[];(if (assets_for("component")|length)>0 then "Related Evidence Only" else "Not Assessed" end)),
    ow("I6";"Insufficient Privacy Protection";[];"Not Assessed"),
    ow("I7";"Insecure Data Transfer and Storage";["F-02"];"No Finding Identified"),
    ow("I8";"Lack of Device Management";[];"Not Assessed"),
    ow("I9";"Insecure Default Settings";[];"Not Assessed"),
    ow("I10";"Lack of Physical Hardening";[];"Not Assessed")
  ]) as $owasp |

  # Overall Risk
  ([$security_findings[]? | select(.finding_status=="IDENTIFIED" and (.confidence=="HIGH" or .confidence=="MEDIUM"))]) as $validated |
  ([$validated[]? | select(.severity=="CRITICAL")]|length) as $critical |
  ([$validated[]? | select(.severity=="HIGH")]|length) as $high |
  ([$validated[]? | select(.severity=="MEDIUM")]|length) as $medium |
  ([$security_findings[]? | select(.finding_status=="POTENTIAL")]|length) as $potential |
  ([$validated[]? | select(.category=="network_service_hardening" or .category=="legacy_remote_service" or .category=="web_command_execution_review")]|length) as $network |
  ($systemic_findings|length) as $systemic |

  (if $critical>0 then "CRITICAL" elif $high>0 then "HIGH" elif $medium>0 then "MEDIUM" else "LOW" end) as $base_risk |

  # 제한적 escalation. 내부 Risk Policy이며 외부 표준 점수가 아님.
  (if $base_risk=="HIGH" and $high>=2 and $network>=1 then "CRITICAL" else $base_risk end) as $overall_risk |

  {
    tool:$tool,
    target:{name:$target,rootfs:$rootfs_name},
    risk_summary:{
      overall_risk:$overall_risk,
      base_risk:$base_risk,
      basis:{
        critical_findings:$critical,
        high_findings:$high,
        medium_findings:$medium,
        potential_findings:$potential,
        network_related_findings:$network,
        systemic_findings:$systemic
      },
      methodology:"Overall risk is based on identified findings with MEDIUM or HIGH confidence. Detected artifacts and LOW-confidence potential findings do not directly determine overall risk."
    },
    security_findings:$security_findings,
    systemic_findings:$systemic_findings,
    detected_information:$detected_information,
    owasp_iot_mapping:$owasp,
    informational:($r.informational//[])
  }
' > "$REPORT_JSON"

# CSV
jq -r '
  ["ID","Rule","Status","Severity","Confidence","Title","Asset","Category"],
  (.security_findings[] | [.id,.rule_id,.finding_status,.severity,.confidence,.title,.asset,.category]) | @csv
' "$REPORT_JSON" > "$FINDINGS_CSV"

# HTML
overall_risk="$(jq -r '.risk_summary.overall_risk' "$REPORT_JSON")"; base_risk="$(jq -r '.risk_summary.base_risk' "$REPORT_JSON")"
critical_count="$(jq -r '.risk_summary.basis.critical_findings' "$REPORT_JSON")"; high_count="$(jq -r '.risk_summary.basis.high_findings' "$REPORT_JSON")"
medium_count="$(jq -r '.risk_summary.basis.medium_findings' "$REPORT_JSON")"; potential_count="$(jq -r '.risk_summary.basis.potential_findings' "$REPORT_JSON")"
network_count="$(jq -r '.risk_summary.basis.network_related_findings' "$REPORT_JSON")"; systemic_count="$(jq -r '.risk_summary.basis.systemic_findings' "$REPORT_JSON")"

cat > "$REPORT_HTML" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>IoT Firmware Security Report</title>
<style>
body{font-family:Arial,sans-serif;margin:40px;background:#f5f6f8;color:#202124}
.container{max-width:1200px;margin:auto}
.card{background:white;border-radius:8px;padding:22px;margin-bottom:20px;box-shadow:0 1px 4px rgba(0,0,0,.12)}
h1{margin-bottom:5px} h2{margin-top:0}
table{width:100%;border-collapse:collapse}
th,td{padding:10px;border-bottom:1px solid #ddd;text-align:left;vertical-align:top}
th{background:#f1f3f4}
.badge{display:inline-block;padding:4px 8px;border-radius:5px;font-weight:bold;background:#eceff1}
pre{white-space:pre-wrap;word-break:break-word;background:#f7f7f7;padding:12px;border-radius:6px}
.small{color:#666;font-size:13px}
</style>
</head>
<body>
<div class="container">

<div class="card">
<h1>IoT Firmware Security Report</h1>
<p>Target: <strong>$TARGET</strong></p>
<p>RootFS: <strong>$ROOTFS_NAME</strong></p>
</div>

<div class="card">
<h2>Overall Risk</h2>
<h1><span class="badge">$overall_risk</span></h1>
<p>Base Risk: <strong>$base_risk</strong></p>
<table>
<tr><th>Metric</th><th>Count</th></tr>
<tr><td>Critical Findings</td><td>$critical_count</td></tr>
<tr><td>High Findings</td><td>$high_count</td></tr>
<tr><td>Medium Findings</td><td>$medium_count</td></tr>
<tr><td>Potential Findings</td><td>$potential_count</td></tr>
<tr><td>Network-related Findings</td><td>$network_count</td></tr>
<tr><td>Systemic Findings</td><td>$systemic_count</td></tr>
</table>
<p class="small">Detected artifacts and LOW-confidence potential findings do not directly determine firmware-wide risk.</p>
</div>

<div class="card">
<h2>Security Findings</h2>
<table>
<tr><th>ID</th><th>Rule</th><th>Status</th><th>Severity</th><th>Confidence</th><th>Finding</th><th>Asset</th></tr>
EOF

jq -r '.security_findings[] |
  "<tr><td>"+(.id//"")+"</td><td>"+(.rule_id//"")+"</td><td>"+(.finding_status//"")+"</td><td>"+(.severity//"")+
  "</td><td>"+(.confidence//"")+"</td><td>"+(.title//"")+"</td><td><code>"+(.asset//"")+"</code></td></tr>"
' "$REPORT_JSON" >> "$REPORT_HTML"

cat >> "$REPORT_HTML" <<'EOF'
</table>
</div>

<div class="card">
<h2>Systemic Findings</h2>
<table>
<tr><th>Rule</th><th>Severity</th><th>Confidence</th><th>Finding</th><th>Analysis</th></tr>
EOF

jq -r '.systemic_findings[] |
  "<tr><td>"+(.rule_id//"")+"</td><td>"+(.severity//"")+"</td><td>"+(.confidence//"")+"</td><td>"+(.title//"")+"</td><td>"+(.analysis//"")+"</td></tr>"
' "$REPORT_JSON" >> "$REPORT_HTML"

cat >> "$REPORT_HTML" <<'EOF'
</table>
</div>

<div class="card">
<h2>Detected Information</h2>
<p class="small">These items were detected during static analysis. Their presence alone does not mean that a vulnerability exists.</p>
<table>
<tr><th>Type</th><th>Count</th><th>Description</th><th>Next Check</th></tr>
EOF

jq -r '.detected_information[] |
  "<tr><td>"+(.title//"")+"</td><td>"+((.count//0)|tostring)+"</td><td>"+(.description//"")+"</td><td>"+(.next_check//"")+"</td></tr>"
' "$REPORT_JSON" >> "$REPORT_HTML"

cat >> "$REPORT_HTML" <<'EOF'
</table>
</div>

<div class="card">
<h2>OWASP IoT Mapping</h2>
<table>
<tr><th>Code</th><th>Category</th><th>Status</th><th>Mapped Findings</th></tr>
EOF

jq -r '.owasp_iot_mapping[] |
  "<tr><td>"+(.code//"")+"</td><td>"+(.category//"")+"</td><td>"+(.status//"")+"</td><td>"+
  (if (.findings|length)==0 then "-" else (.findings|join(", ")) end)+"</td></tr>"
' "$REPORT_JSON" >> "$REPORT_HTML"

cat >> "$REPORT_HTML" <<'EOF'
</table>
</div>

<div class="card">
<h2>Finding Details</h2>
EOF

jq -r '.security_findings[] |
  "<h3>"+(.id//"")+" — "+(.title//"")+"</h3>"+
  "<p><strong>Rule:</strong> "+(.rule_id//"")+"</p>"+
  "<p><strong>Status:</strong> "+(.finding_status//"")+"</p>"+
  "<p><strong>Severity:</strong> "+(.severity//"")+" / <strong>Confidence:</strong> "+(.confidence//"")+"</p>"+
  "<p><strong>Asset:</strong> <code>"+(.asset//"")+"</code></p>"+
  "<h4>Analysis</h4><pre>"+(.analysis//"")+"</pre>"+
  "<h4>Evidence</h4><pre>"+((.evidence//[])|join("\n"))+"</pre>"+
  "<h4>Severity Basis</h4><pre>"+((.severity_basis//{})|tojson)+"</pre>"+
  "<h4>Confidence Basis</h4><pre>"+((.confidence_basis//[])|join("\n"))+"</pre>"+
  "<h4>Potential Impact</h4><pre>"+((.potential_impact//[])|join("\n"))+"</pre>"+
  "<h4>Remediation</h4><pre>"+((.remediation//[])|join("\n"))+"</pre>"
' "$REPORT_JSON" >> "$REPORT_HTML"

cat >> "$REPORT_HTML" <<'EOF'
</div>
</div>
</body>
</html>
EOF

echo "[+] Report generated"
echo "    JSON : $REPORT_JSON"
echo "    CSV  : $FINDINGS_CSV"
echo "    HTML : $REPORT_HTML"
