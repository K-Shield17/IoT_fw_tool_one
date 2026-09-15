#!/usr/bin/env bash
set -euo pipefail
ROOTFS="$1"; EVIDENCE="$2"; ASSETS="$3"; OUT="$4"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
CASES="$TMP/cases.jsonl"; SYSTEMIC="$TMP/systemic.jsonl"; INFO="$TMP/info.jsonl"
: > "$CASES"; : > "$SYSTEMIC"; : > "$INFO"

emit_case() {
  local id="$1" rule_id="$2" status="$3" title="$4" sev="$5" conf="$6" asset="$7" category="$8" analysis="$9"
  local attack="${10}" impact_json="${11}" remediation_json="${12}" evidence_json="${13}" severity_basis_json="${14}" confidence_basis_json="${15}"
  jq -cn --arg id "$id" --arg rule_id "$rule_id" --arg finding_status "$status" --arg title "$title" --arg severity "$sev" --arg confidence "$conf" \
    --arg asset "$asset" --arg category "$category" --arg analysis "$analysis" --arg attack_scenario "$attack" \
    --argjson impact "$impact_json" --argjson remediation "$remediation_json" --argjson evidence "$evidence_json" \
    --argjson severity_basis "$severity_basis_json" --argjson confidence_basis "$confidence_basis_json" \
    '{id:$id,rule_id:$rule_id,finding_status:$finding_status,title:$title,severity:$severity,confidence:$confidence,asset:$asset,category:$category,analysis:$analysis,attack_scenario:$attack_scenario,potential_impact:$impact,remediation:$remediation,evidence:$evidence,severity_basis:$severity_basis,confidence_basis:$confidence_basis}' >> "$CASES"
}

case_id=0
while IFS= read -r asset_line; do
  [[ -z "$asset_line" ]] && continue
  asset="$(jq -r '.asset' <<<"$asset_line")"; role="$(jq -r '.role' <<<"$asset_line")"; exposure="$(jq -r '.exposure' <<<"$asset_line")"
  startup="$(jq -r '.startup_reference' <<<"$asset_line")"; mode="$(jq -r '.mode' <<<"$asset_line")"
  profile="$(jq -c --arg a "$asset" 'select(.source=="checksec" and .asset==$a and .property=="hardening_profile") | .value' "$EVIDENCE" | head -n1 || true)"

  # F-01: Network Service with Weak Exploit Mitigations
  if [[ "$exposure" == "network_service" && -n "$profile" ]]; then
    relro="$(jq -r '.relro // "Unknown"' <<<"$profile")"; canary="$(jq -r '.canary // "Unknown"' <<<"$profile")"; nx="$(jq -r '.nx // "Unknown"' <<<"$profile")"
    pie="$(jq -r '.pie // "Unknown"' <<<"$profile")"; rps="$(jq -r '.rpath_status // "Unknown"' <<<"$profile")"; runps="$(jq -r '.runpath_status // "Unknown"' <<<"$profile")"; fort="$(jq -r '.fortify // "Unknown"' <<<"$profile")"
    weak=0; [[ "$canary" == "No Canary Found" ]] && weak=$((weak+1)); [[ "$nx" == "NX disabled" ]] && weak=$((weak+1)); [[ "$pie" == "PIE Disabled" ]] && weak=$((weak+1))
    [[ "$relro" == "No RELRO" || "$relro" == "Partial RELRO" ]] && weak=$((weak+1)); [[ "$rps" == "red" || "$runps" == "red" ]] && weak=$((weak+1))

    if (( weak >= 1 )); then
      if (( weak >= 3 )) && [[ "$startup" == "true" ]]; then sev="MEDIUM"; elif (( weak >= 2 )); then sev="LOW"; else sev="INFO"; fi
      conf="MEDIUM"; [[ "$startup" == "true" ]] && conf="HIGH"
      case "$role" in
        web_server) title="Embedded web service with weak exploit mitigations"; role_desc="web management/service component" ;;
        ssh_server) title="SSH service with weak exploit mitigations"; role_desc="SSH service component" ;;
        ppp_service) title="PPP service with weak exploit mitigations"; role_desc="PPP network service component" ;;
        dns_dhcp_service) title="DNS/DHCP service with weak exploit mitigations"; role_desc="DNS/DHCP service component" ;;
        upnp_service) title="UPnP service with weak exploit mitigations"; role_desc="UPnP network service component" ;;
        rpc_service) title="RPC service with weak exploit mitigations"; role_desc="RPC service component" ;;
        telnet_service) title="Telnet service with weak exploit mitigations"; role_desc="legacy remote-access component" ;;
        tftp_service) title="TFTP service with weak exploit mitigations"; role_desc="TFTP network component" ;;
        *) title="Network service with weak exploit mitigations"; role_desc="network service component" ;;
      esac
      analysis="The firmware contains $asset, identified as a $role_desc. One or more exploit mitigations are absent or incomplete. These observations do not prove an exploitable memory-corruption vulnerability; they indicate reduced exploit resistance if such a vulnerability exists."
      attack="Network or protocol input reaches the service → a memory-safety flaw is triggered, if present → missing mitigations reduce exploit resistance → service compromise may become more feasible."
      impact='["Reduced resistance to exploitation","Potential service compromise if an underlying vulnerability exists","Potential code execution if a memory-safety vulnerability exists"]'
      remediation='["Enable stack protector where supported","Enable PIE","Enable Full RELRO","Ensure NX is enabled","Remove unsafe RPATH/RUNPATH settings","Restrict unnecessary network exposure","Review network-facing input-processing code"]'
      evidence_json="$(jq -cn --arg role "$role" --arg startup "$startup" --arg relro "$relro" --arg canary "$canary" --arg nx "$nx" --arg pie "$pie" --arg fortify "$fort" --arg weak "$weak" \
        '["Role: "+$role,"Startup/config reference: "+$startup,"Weak mitigation count: "+$weak,"RELRO: "+$relro,"Stack Canary: "+$canary,"NX: "+$nx,"PIE: "+$pie,"FORTIFY: "+$fortify]')"
      severity_basis="$(jq -cn --arg sev "$sev" --arg weak "$weak" --arg startup "$startup" \
        '{attack_exposure:"NETWORK",exploit_preconditions:"UNDERLYING_VULNERABILITY_REQUIRED",potential_impact:"HIGH_IF_EXPLOITABLE",reason:("Severity "+$sev+" based on "+$weak+" weak mitigation(s) and startup/config reference="+$startup+".") }')"
      confidence_basis="$(jq -cn --arg startup "$startup" '["Checksec hardening profile directly observed","Asset classified as network service","Startup/config reference: "+$startup]')"
      case_id=$((case_id+1)); emit_case "CASE-$(printf '%03d' "$case_id")" "F-01" "IDENTIFIED" "$title" "$sev" "$conf" "$asset" "network_service_hardening" "$analysis" "$attack" "$impact" "$remediation" "$evidence_json" "$severity_basis" "$confidence_basis"
    fi
  fi

  # F-02: Sensitive Key Material with Broad Read Permission
  key_hits="$(jq -r --arg a "$asset" 'select(.source=="firmwalker" and .asset==$a and ((.type=="crypto" and (.value|ascii_downcase|contains("key"))) or .type=="ssh")) | 1' "$EVIDENCE" | wc -l | tr -d ' ')"
  if (( key_hits > 0 )) && [[ "$mode" =~ ^[0-7][0-7][0-7]$ ]]; then
    g=$(((10#$mode / 10) % 10)); o=$((10#$mode % 10))
    if (( (g & 4) != 0 || (o & 4) != 0 )); then
      if (( (o & 4) != 0 )); then sev="HIGH"; else sev="MEDIUM"; fi
      case_id=$((case_id+1))
      evidence_json="$(jq -cn --arg mode "$mode" --arg sev "$sev" '["Sensitive key material detected","Filesystem mode: "+$mode,"Assigned severity: "+$sev]')"
      severity_basis="$(jq -cn --arg sev "$sev" '{attack_exposure:"LOCAL_OR_COMPROMISED_PROCESS",exploit_preconditions:"READ_ACCESS",potential_impact:"HIGH",reason:(if $sev=="HIGH" then "Sensitive key material is readable by other users." else "Sensitive key material is readable by group users." end)}')"
      confidence_basis='["Sensitive key material directly detected","Filesystem permission directly inspected","Broad read permission confirmed"]'
      emit_case "CASE-$(printf '%03d' "$case_id")" "F-02" "IDENTIFIED" "Sensitive key material is broadly readable" "$sev" "HIGH" "$asset" "key_exposure" \
        "Sensitive SSH/TLS key material is present and the extracted filesystem mode ($mode) permits broader read access than expected." \
        "A local or compromised process reads the key → key material is copied → the attacker may impersonate the device/service or reuse authentication material." \
        '["Private key disclosure","Service or device impersonation","Unauthorized authentication depending on key usage"]' \
        '["Restrict key permissions to the owning account","Rotate exposed keys","Avoid shared private keys across devices","Use device-unique key provisioning"]' \
        "$evidence_json" "$severity_basis" "$confidence_basis"
    fi
  fi

  # F-04: Insecure Legacy Remote Service
  if [[ "$role" == "telnet_service" ]]; then
    if [[ "$startup" == "true" ]]; then sev="HIGH"; conf="HIGH"; status="IDENTIFIED"; else sev="MEDIUM"; conf="MEDIUM"; status="POTENTIAL"; fi
    case_id=$((case_id+1))
    evidence_json="$(jq -cn --arg asset "$asset" --arg startup "$startup" '["Telnet service component identified: "+$asset,"Startup/config reference: "+$startup]')"
    severity_basis="$(jq -cn --arg sev "$sev" --arg startup "$startup" '{attack_exposure:"NETWORK",exploit_preconditions:(if $startup=="true" then "SERVICE_ACTIVE_OR_CONFIGURED" else "SERVICE_PRESENCE_CONFIRMED_ACTIVITY_UNCONFIRMED" end),potential_impact:"HIGH",reason:("Telnet component detected; startup/config reference="+$startup+", severity="+$sev+".")}')"
    confidence_basis="$(jq -cn --arg startup "$startup" '["Telnet service binary directly identified","Asset classified as network service","Startup/config reference: "+$startup]')"
    emit_case "CASE-$(printf '%03d' "$case_id")" "F-04" "$status" "Legacy Telnet remote-access service detected" "$sev" "$conf" "$asset" "legacy_remote_service" \
      "A Telnet service component is present in the firmware. Startup/configuration evidence determines whether it is treated as configured or requires additional activation verification." \
      "An attacker able to observe or access the management network may intercept or abuse plaintext Telnet authentication and management traffic if the service is active." \
      '["Credential disclosure","Unauthorized remote administration","Exposure of management traffic"]' \
      '["Disable Telnet","Use SSH or another authenticated encrypted management protocol","Restrict remote management interfaces to trusted networks"]' \
      "$evidence_json" "$severity_basis" "$confidence_basis"
  fi
done < "$ASSETS"

# F-03: Weak Unix-MD5 Password Hash
md5_assets="$(jq -r 'select(.source=="firmwalker" and (.value|contains("Unix-MD5 password hash"))) | .asset' "$EVIDENCE" | sort -u)"
if [[ -n "$md5_assets" ]]; then
  md5_assets_json="$(printf '%s\n' "$md5_assets" | jq -Rsc 'split("\n")|map(select(length>0))')"; count="$(printf '%s\n' "$md5_assets" | grep -c . || true)"
  primary_asset="$(printf '%s\n' "$md5_assets" | head -n1)"
  if printf '%s\n' "$md5_assets" | grep -Eq '(^|/)(etc/)?shadow$|/etc/shadow'; then sev="HIGH"
  elif printf '%s\n' "$md5_assets" | grep -Eqi 'shadow|passwd|credential|account|user|auth'; then sev="MEDIUM"
  else sev="LOW"; fi
  evidence_json="$(jq -cn --argjson assets "$md5_assets_json" --arg sev "$sev" '["Unix-MD5 ($1$) password hash format detected","Affected files: "+($assets|join(", ")),"Assigned severity: "+$sev]')"
  severity_basis="$(jq -cn --arg sev "$sev" '{attack_exposure:"OFFLINE_AFTER_FILE_ACCESS",exploit_preconditions:"AFFECTED_FILE_ACCESS_REQUIRED",potential_impact:"HIGH_IF_ACTIVE_CREDENTIAL",reason:("Severity "+$sev+" based on the context/location of files containing Unix-MD5 password hashes.")}')"
  confidence_basis='["Unix-MD5 password hash format directly detected","Affected firmware file paths directly identified"]'
  case_id=$((case_id+1))
  emit_case "CASE-$(printf '%03d' "$case_id")" "F-03" "IDENTIFIED" "Weak Unix-MD5 password hashes present" "$sev" "HIGH" "$primary_asset" "credential_storage" \
    "Unix-MD5 (\$1\$) password hashes were identified in $count firmware file(s). The format provides weaker password-cracking resistance than modern password hashing schemes." \
    "An attacker obtains an affected firmware file → extracts password hashes → performs offline cracking → recovered active credentials may enable unauthorized access." \
    '["Offline credential cracking","Unauthorized account access if active credentials are recovered","Credential reuse risk"]' \
    '["Replace MD5-crypt with a modern password hashing scheme","Use unique high-entropy credentials","Remove unnecessary embedded/default accounts","Rotate affected credentials"]' \
    "$evidence_json" "$severity_basis" "$confidence_basis"
fi

# F-05: Potential Web Command Execution
web_server_count="$(jq -r 'select(.role=="web_server") | 1' "$ASSETS" | wc -l | tr -d ' ')"
cmd_evidence="$(jq -c 'select(.source=="firmwalker" and .type=="sensitive_pattern" and (.value|test("matched pattern: (cmd=|exec=|command=|execute=)";"i")) and (.asset|test("^/(www|htdocs|cgi-bin|usr/lib/lua/luci)/")))' "$EVIDENCE" || true)"
if (( web_server_count > 0 )) && [[ -n "$cmd_evidence" ]]; then
  count="$(printf '%s\n' "$cmd_evidence" | grep -c . || true)"; affected_assets="$(printf '%s\n' "$cmd_evidence" | jq -s '[.[].asset] | unique')"; primary_asset="$(jq -r '.[0] // "-"' <<<"$affected_assets")"
  evidence_json="$(jq -cn --argjson assets "$affected_assets" --arg count "$count" '["Web server component detected","Command/exec-related indicators: "+$count,"Affected web paths: "+($assets|join(", "))]')"
  severity_basis='{"attack_exposure":"POTENTIALLY_NETWORK","exploit_preconditions":"SOURCE_TO_SINK_PATH_NOT_CONFIRMED","potential_impact":"HIGH_IF_CONFIRMED","reason":"Web-path command/exec indicators are present, but static string evidence does not establish a user-controlled source-to-command-execution sink."}'
  confidence_basis='["Web server component identified","Command/exec-related string detected in web path","No confirmed user-input-to-command-execution data flow"]'
  case_id=$((case_id+1))
  emit_case "CASE-$(printf '%03d' "$case_id")" "F-05" "POTENTIAL" "Potential web command-execution path" "LOW" "LOW" "$primary_asset" "web_command_execution_review" \
    "Command/exec-related strings were found in web-interface content while a web server component is present. Static string matches alone do not establish command injection." \
    "HTTP-controlled input may reach command-execution logic if the matched indicators are connected to user-controlled parameters. That relationship has not been proven." \
    '["Potential command injection if a user-controlled source reaches an execution sink","Potential web-service compromise if exploitability is confirmed"]' \
    '["Inspect the listed web files for source-to-sink data flow","Review system/exec/popen-style calls","Use structured APIs instead of shell command construction","Validate with targeted dynamic testing"]' \
    "$evidence_json" "$severity_basis" "$confidence_basis"
fi

# F-06: Firmware-wide Weak Binary Hardening Policy
profiles="$(jq -c 'select(.source=="checksec" and .property=="hardening_profile")' "$EVIDENCE")"
exec_total=0; exec_weak=0; no_canary_count=0; pie_disabled_count=0; weak_relro_count=0; weak_assets="$TMP/f06_assets.txt"; : > "$weak_assets"
while IFS= read -r p; do
  [[ -z "$p" ]] && continue
  a="$(jq -r '.asset' <<<"$p")"; role="$(jq -r --arg a "$a" 'select(.asset==$a)|.role' "$ASSETS" | head -n1)"
  [[ "$role" == "library" || "$role" == "kernel_module" || "$role" == "configuration" || "$role" == "web_content" || "$role" == "other" ]] && continue
  exec_total=$((exec_total+1)); can="$(jq -r '.value.canary // "Unknown"' <<<"$p")"; pie="$(jq -r '.value.pie // "Unknown"' <<<"$p")"; rel="$(jq -r '.value.relro // "Unknown"' <<<"$p")"; w=0
  if [[ "$can" == "No Canary Found" ]]; then w=$((w+1)); no_canary_count=$((no_canary_count+1)); fi
  if [[ "$pie" == "PIE Disabled" ]]; then w=$((w+1)); pie_disabled_count=$((pie_disabled_count+1)); fi
  if [[ "$rel" == "No RELRO" || "$rel" == "Partial RELRO" ]]; then w=$((w+1)); weak_relro_count=$((weak_relro_count+1)); fi
  if (( w >= 2 )); then exec_weak=$((exec_weak+1)); printf '%s\n' "$a" >> "$weak_assets"; fi
done <<< "$profiles"

if (( exec_total >= 10 )); then
  pct=$((exec_weak * 100 / exec_total))
  if (( pct >= 50 )); then sev="MEDIUM"; elif (( pct >= 20 )); then sev="LOW"; else sev="INFO"; fi
  if (( exec_weak > 0 )); then
    affected_assets="$(sort -u "$weak_assets" | jq -Rsc 'split("\n")|map(select(length>0))')"; primary_asset="$(sort -u "$weak_assets" | head -n1)"
  else affected_assets='[]'; primary_asset="-"; fi
  jq -cn --arg rule_id "F-06" --arg title "Firmware-wide weak binary hardening policy" --arg severity "$sev" --arg confidence "HIGH" --arg asset "$primary_asset" \
    --arg total "$exec_total" --arg affected "$exec_weak" --arg pct "$pct" --arg canary "$no_canary_count" --arg pie "$pie_disabled_count" --arg relro "$weak_relro_count" --argjson assets "$affected_assets" \
    --arg analysis "$exec_weak of $exec_total analyzed userspace executables ($pct%) have at least two common hardening weaknesses. This indicates the prevalence of a firmware build-policy/toolchain pattern rather than an isolated binary issue." \
    --argjson remediation '["Enable hardening flags globally in the firmware build system","Prioritize network-facing executables","Add hardening validation to CI/CD or release checks"]' \
    '{rule_id:$rule_id,finding_status:(if $severity=="INFO" then "INFORMATIONAL" else "IDENTIFIED" end),title:$title,severity:$severity,confidence:$confidence,asset:$asset,category:"systemic_hardening",analysis:$analysis,affected_assets:$assets,analysis_scope:{scope:"Firmware-wide",analyzed_executables:($total|tonumber),affected_executables:($affected|tonumber),affected_percentage:($pct|tonumber),no_canary:($canary|tonumber),pie_disabled:($pie|tonumber),weak_relro:($relro|tonumber)},threshold_basis:{minimum_executables:10,medium_percentage:50,low_percentage:20,note:"Internal systemic-pattern threshold; not an external vulnerability standard."},remediation:$remediation}' >> "$SYSTEMIC"
fi

# F-07: Hard-coded / Default Credentials
default_cred_evidence="$(jq -c 'select(.source=="firmwalker" and .type=="credential_default")' "$EVIDENCE" || true)"
if [[ -n "$default_cred_evidence" ]]; then
  count="$(printf '%s\n' "$default_cred_evidence" | grep -c . || true)"; affected_assets="$(printf '%s\n' "$default_cred_evidence" | jq -s '[.[].asset] | unique')"; primary_asset="$(jq -r '.[0] // "-"' <<<"$affected_assets")"
  evidence_json="$(jq -cn --argjson assets "$affected_assets" --arg count "$count" '["Default/hard-coded credential indicators: "+$count,"Affected files: "+($assets|join(", "))]')"
  severity_basis='{"attack_exposure":"AUTHENTICATION_INTERFACE_DEPENDENT","exploit_preconditions":"DEFAULT_OR_HARDCODED_CREDENTIAL_REMAINS_ACTIVE","potential_impact":"HIGH","reason":"A known default/hard-coded credential pattern was directly identified in firmware content."}'
  confidence_basis='["Known default credential pattern directly detected in firmware content","Affected firmware file paths directly identified"]'
  case_id=$((case_id+1))
  emit_case "CASE-$(printf '%03d' "$case_id")" "F-07" "IDENTIFIED" "Hard-coded or default credentials detected" "HIGH" "HIGH" "$primary_asset" "hardcoded_default_credentials" \
    "Known default or hard-coded credential patterns were identified in firmware content. Generic credential-assignment indicators alone are not sufficient to generate this finding." \
    "An attacker discovers or knows the embedded/default credential → the credential remains active on a reachable authentication interface → unauthorized access may be obtained." \
    '["Unauthorized authentication","Administrative access if privileged credentials remain active","Credential reuse across devices if shared defaults are used"]' \
    '["Remove hard-coded/default credentials","Require unique per-device credentials","Force credential change during provisioning or first use","Do not embed reusable administrative secrets in firmware"]' \
    "$evidence_json" "$severity_basis" "$confidence_basis"
fi

# F-08: Weak / Deprecated Cryptography
weak_crypto_evidence="$(jq -c 'select(.source=="firmwalker" and .type=="crypto_weak_applied")' "$EVIDENCE" || true)"
if [[ -n "$weak_crypto_evidence" ]]; then
  filtered_crypto="$TMP/f08_crypto.jsonl"; : > "$filtered_crypto"
  while IFS= read -r crypto_line; do
    [[ -z "$crypto_line" ]] && continue
    crypto_asset="$(jq -r '.asset' <<<"$crypto_line")"
    if ! jq -e --arg a "$crypto_asset" 'select(.source=="firmwalker" and .asset==$a and (.value|contains("Unix-MD5 password hash")))' "$EVIDENCE" >/dev/null 2>&1; then printf '%s\n' "$crypto_line" >> "$filtered_crypto"; fi
  done <<< "$weak_crypto_evidence"
  if [[ -s "$filtered_crypto" ]]; then
    count="$(grep -c . "$filtered_crypto" || true)"; affected_assets="$(jq -s '[.[].asset] | unique' "$filtered_crypto")"; primary_asset="$(jq -r '.[0] // "-"' <<<"$affected_assets")"
    evidence_json="$(jq -cn --argjson assets "$affected_assets" --arg count "$count" '["Weak/deprecated cryptographic algorithm with nearby security context: "+$count,"Affected files: "+($assets|join(", "))]')"
    severity_basis='{"attack_exposure":"CONTEXT_DEPENDENT","exploit_preconditions":"WEAK_ALGORITHM_USED_IN_SECURITY_RELEVANT_OPERATION","potential_impact":"MEDIUM_TO_HIGH_DEPENDING_ON_USE","reason":"A weak/deprecated cryptographic indicator was observed near security-relevant context; direct runtime data flow is not established by this static evidence."}'
    confidence_basis='["Weak/deprecated cryptographic algorithm indicator directly detected","Security-relevant context detected within the configured proximity window","Runtime cryptographic data flow not directly observed"]'
    case_id=$((case_id+1))
    emit_case "CASE-$(printf '%03d' "$case_id")" "F-08" "IDENTIFIED" "Weak or deprecated cryptography detected in security-relevant context" "MEDIUM" "MEDIUM" "$primary_asset" "weak_cryptography" \
      "Weak or deprecated cryptographic algorithm indicators were found near security-relevant context in firmware content. Algorithm-name occurrences without such context do not generate this finding." \
      "A security-sensitive operation relies on a weak or deprecated algorithm → an attacker targets the weakened confidentiality, integrity, authentication, or verification property → protected data or trust decisions may be compromised depending on actual use." \
      '["Reduced cryptographic assurance","Potential compromise of confidentiality or integrity depending on algorithm use","Potential weakening of authentication or verification mechanisms"]' \
      '["Replace deprecated algorithms with currently recommended cryptographic primitives","Review the affected code/configuration to confirm actual algorithm use","Use modern password hashing for credentials","Use modern authenticated encryption and signature/hash algorithms appropriate to the security function"]' \
      "$evidence_json" "$severity_basis" "$confidence_basis"
  fi
fi

# Kernel modules: informational only
ko_count="$(jq -r 'select(.source=="checksec" and (.asset|endswith(".ko"))) | .asset' "$EVIDENCE" | sort -u | wc -l | tr -d ' ')"
if (( ko_count > 0 )); then
  jq -cn --arg title "Kernel-module hardening observations" --arg count "$ko_count" \
    '{title:$title,severity:"INFO",category:"kernel_module_hardening",analysis:("Hardening profiles were collected for "+$count+" kernel modules. They are retained as detected information and are not evaluated using ordinary userspace hardening rules.")}' >> "$INFO"
fi

jq -n --slurpfile cases "$CASES" --slurpfile systemic "$SYSTEMIC" --slurpfile info "$INFO" \
  '{security_cases:$cases,systemic_findings:$systemic,informational:$info}' > "$OUT"
