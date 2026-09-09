#!/usr/bin/env bash
set -euo pipefail
ROOTFS="$1"; EVIDENCE="$2"; ASSETS="$3"; OUT="$4"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
CASES="$TMP/cases.jsonl"; SYSTEMIC="$TMP/systemic.jsonl"; INFO="$TMP/info.jsonl"
: > "$CASES"; : > "$SYSTEMIC"; : > "$INFO"

emit_case() {
  local id="$1" title="$2" sev="$3" conf="$4" asset="$5" category="$6" analysis="$7" attack="$8" impact_json="$9" remediation_json="${10}" evidence_json="${11}"
  jq -cn --arg id "$id" --arg title "$title" --arg severity "$sev" --arg confidence "$conf" \
    --arg asset "$asset" --arg category "$category" --arg analysis "$analysis" --arg attack_scenario "$attack" \
    --argjson impact "$impact_json" --argjson remediation "$remediation_json" --argjson evidence "$evidence_json" \
    '{id:$id,title:$title,severity:$severity,confidence:$confidence,asset:$asset,category:$category,analysis:$analysis,attack_scenario:$attack_scenario,potential_impact:$impact,remediation:$remediation,evidence:$evidence}' >> "$CASES"
}

case_id=0
while IFS= read -r asset_line; do
  asset="$(jq -r '.asset' <<<"$asset_line")"
  role="$(jq -r '.role' <<<"$asset_line")"
  exposure="$(jq -r '.exposure' <<<"$asset_line")"
  startup="$(jq -r '.startup_reference' <<<"$asset_line")"
  mode="$(jq -r '.mode' <<<"$asset_line")"

  profile="$(jq -c --arg a "$asset" 'select(.source=="checksec" and .asset==$a and .property=="hardening_profile") | .value' "$EVIDENCE" | head -n1 || true)"

  # Network/service + hardening correlation. A hardening weakness alone is never called a confirmed vulnerability.
  if [[ "$exposure" == "network_service" && -n "$profile" ]]; then
    relro="$(jq -r '.relro' <<<"$profile")"; canary="$(jq -r '.canary' <<<"$profile")"; nx="$(jq -r '.nx' <<<"$profile")"; pie="$(jq -r '.pie' <<<"$profile")"
    rps="$(jq -r '.rpath_status' <<<"$profile")"; runps="$(jq -r '.runpath_status' <<<"$profile")"; fort="$(jq -r '.fortify' <<<"$profile")"
    score=0; weak=0
    [[ "$canary" == "No Canary Found" ]] && { score=$((score+2)); weak=$((weak+1)); }
    [[ "$nx" == "NX disabled" ]] && { score=$((score+3)); weak=$((weak+1)); }
    [[ "$pie" == "PIE Disabled" ]] && { score=$((score+1)); weak=$((weak+1)); }
    [[ "$relro" == "No RELRO" ]] && { score=$((score+2)); weak=$((weak+1)); }
    [[ "$relro" == "Partial RELRO" ]] && { score=$((score+1)); weak=$((weak+1)); }
    [[ "$rps" == "red" || "$runps" == "red" ]] && { score=$((score+2)); weak=$((weak+1)); }

    if (( weak >= 2 )); then
      sev="MEDIUM"
      (( score >= 5 )) && sev="HIGH"
      # An explicit startup/config reference increases confidence that the component is intended to be active.
      conf="MEDIUM"; [[ "$startup" == "true" ]] && conf="HIGH"
      case "$role" in
        web_server) title="Embedded web service with weak exploit mitigations"; role_desc="web management/service component" ;;
        ssh_server) title="SSH service with weak exploit mitigations"; role_desc="SSH service component" ;;
        ppp_service) title="PPP service with weak exploit mitigations"; role_desc="PPP network service component" ;;
        dns_dhcp_service) title="DNS/DHCP service with weak exploit mitigations"; role_desc="DNS/DHCP service component" ;;
        upnp_service) title="UPnP service with weak exploit mitigations"; role_desc="UPnP network service component" ;;
        rpc_service) title="RPC service with weak exploit mitigations"; role_desc="RPC service component" ;;
        telnet_service) title="Telnet service binary with weak exploit mitigations"; role_desc="legacy remote-access component" ;;
        tftp_service) title="TFTP service binary with weak exploit mitigations"; role_desc="TFTP network component" ;;
        *) title="Network service with weak exploit mitigations"; role_desc="network service component" ;;
      esac
      analysis="The firmware contains $asset, identified as a $role_desc. Multiple exploit mitigations are absent or incomplete. These observations do not by themselves prove an exploitable memory-corruption vulnerability; they indicate that exploitation may be easier if such a flaw exists."
      attack="Network or protocol input reaches the service → a memory-safety flaw is triggered (if present) → missing mitigations reduce exploit resistance → service compromise or code execution may become more feasible."
      impact='["Potential service compromise","Potential arbitrary code execution if a memory-safety vulnerability exists","Possible foothold for further system compromise"]'
      remediation='["Update the affected service to a maintained version","Enable stack protector where supported","Enable PIE","Enable Full RELRO","Ensure NX is enabled","Restrict unnecessary network exposure","Review externally reachable input-processing code"]'
      evidence_json="$(jq -cn --arg role "$role" --arg startup "$startup" --arg relro "$relro" --arg canary "$canary" --arg nx "$nx" --arg pie "$pie" --arg fortify "$fort" '["Role: "+$role,"Startup/config reference: "+$startup,"RELRO: "+$relro,"Stack Canary: "+$canary,"NX: "+$nx,"PIE: "+$pie,"FORTIFY: "+$fortify]')"
      case_id=$((case_id+1)); emit_case "CASE-$(printf '%03d' "$case_id")" "$title" "$sev" "$conf" "$asset" "network_service_hardening" "$analysis" "$attack" "$impact" "$remediation" "$evidence_json"
    fi
  fi

  # Private/SSH key material is only escalated when permissions are broadly readable.
  key_hits="$(jq -r --arg a "$asset" 'select(.source=="firmwalker" and .asset==$a and ((.type=="crypto" and (.value|ascii_downcase|contains("key"))) or .type=="ssh")) | 1' "$EVIDENCE" | wc -l | tr -d ' ')"
  if (( key_hits > 0 )) && [[ "$mode" =~ ^[0-7][0-7][0-7]$ ]]; then
    g=$(( (10#$mode / 10) % 10 )); o=$((10#$mode % 10))
    if (( (g & 4) != 0 || (o & 4) != 0 )); then
      case_id=$((case_id+1))
      emit_case "CASE-$(printf '%03d' "$case_id")" "Sensitive key material is broadly readable" "HIGH" "HIGH" "$asset" "key_exposure" \
        "Sensitive SSH/TLS key material is present and the extracted filesystem mode ($mode) allows group or other users to read it. This can expose cryptographic identity or authentication material to unintended local principals." \
        "Local or compromised process reads the key file → key material is copied → attacker may impersonate the device/service or reuse authentication material depending on the key purpose." \
        '["Private key disclosure","Service/device impersonation","Unauthorized authentication depending on key usage"]' \
        '["Restrict key permissions to the owning service/account","Rotate exposed keys","Avoid shipping shared private keys across devices","Use device-unique key provisioning where possible"]' \
        "$(jq -cn --arg mode "$mode" '["Sensitive key material detected","Filesystem mode: "+$mode]')"
    fi
  fi

done < "$ASSETS"

# Aggregate weak Unix-MD5 credential evidence into one analyst case rather than one case per file.
md5_assets="$(jq -r 'select(.source=="firmwalker" and (.value|contains("Unix-MD5 password hash"))) | .asset' "$EVIDENCE" | sort -u)"
if [[ -n "$md5_assets" ]]; then
  md5_assets_json="$(printf '%s\n' "$md5_assets" | jq -Rsc 'split("\n")|map(select(length>0))')"
  count="$(printf '%s\n' "$md5_assets" | grep -c . || true)"
  case_id=$((case_id+1))
  emit_case "CASE-$(printf '%03d' "$case_id")" "Weak Unix-MD5 password hashes present" "HIGH" "HIGH" "Credential stores" "credential_storage" \
    "Unix-MD5 (\$1\$) password hashes were identified in $count firmware file(s). MD5-crypt provides substantially weaker password-hash resistance than modern password hashing schemes and increases offline cracking risk if the credential store is obtained." \
    "Attacker obtains the firmware or credential store → extracts MD5-crypt hashes → performs offline password cracking → recovered credentials may enable device access where the corresponding accounts are active." \
    '["Offline credential cracking","Unauthorized account access if a password is recovered","Credential reuse risk"]' \
    '["Replace MD5-crypt with a modern password hashing scheme supported by the platform","Use unique high-entropy credentials","Remove default or embedded accounts where unnecessary","Rotate credentials after remediation"]' \
    "$(jq -cn --argjson assets "$md5_assets_json" '["Unix-MD5 ($1$) hash format detected","Affected files: "+($assets|join(", "))]')"
fi


# Web command-execution indicators are triage findings only unless a real source-to-sink path is established.
web_server_count="$(jq -r 'select(.role=="web_server") | 1' "$ASSETS" | wc -l | tr -d ' ')"
cmd_evidence="$(jq -c 'select(.source=="firmwalker" and .type=="sensitive_pattern" and (.value|test("matched pattern: (cmd=|exec=|command=|execute=)";"i")) and (.asset|test("^/(www|htdocs|cgi-bin|usr/lib/lua/luci)/")))' "$EVIDENCE" || true)"
if (( web_server_count > 0 )) && [[ -n "$cmd_evidence" ]]; then
  count="$(printf '%s\n' "$cmd_evidence" | grep -c . || true)"
  assets="$(printf '%s\n' "$cmd_evidence" | jq -s '[.[].asset] | unique')"
  case_id=$((case_id+1))
  emit_case "CASE-$(printf '%03d' "$case_id")" "Web interface contains command-execution-related indicators" "MEDIUM" "LOW" "Web interface" "web_command_execution_review" \
    "Command/exec-related strings were found in web-interface content while a web server component is present. Static string matches alone do not establish command injection; this case is raised for focused source-to-sink review." \
    "HTTP-controlled input may reach command-execution logic if the matched indicators are connected to user-controlled parameters. That data-flow relationship has not been proven by the current static checks." \
    '["Potential command injection if a user-controlled source reaches an execution sink","Possible web-service compromise"]' \
    '["Inspect the listed web files for user-input flow into system/exec/popen-style sinks","Use allowlists and structured APIs instead of shell command construction","Apply strict input validation and escaping","Confirm findings with targeted dynamic testing"]' \
    "$(jq -cn --argjson assets "$assets" --arg count "$count" '["Web server component detected","Command/exec-related indicators: "+$count,"Affected web paths: "+($assets|join(", "))]')"
fi

# Systemic hardening pattern: summarize widespread build-policy weakness rather than hundreds of duplicate cases.
profiles="$(jq -c 'select(.source=="checksec" and .property=="hardening_profile")' "$EVIDENCE")"
exec_total=0; exec_weak=0
while IFS= read -r p; do
  [[ -z "$p" ]] && continue
  a="$(jq -r '.asset' <<<"$p")"
  role="$(jq -r --arg a "$a" 'select(.asset==$a)|.role' "$ASSETS" | head -n1)"
  [[ "$role" == "library" || "$role" == "kernel_module" || "$role" == "configuration" || "$role" == "web_content" || "$role" == "other" ]] && continue
  exec_total=$((exec_total+1))
  can="$(jq -r '.value.canary' <<<"$p")"; pie="$(jq -r '.value.pie' <<<"$p")"; rel="$(jq -r '.value.relro' <<<"$p")"
  w=0; [[ "$can" == "No Canary Found" ]] && w=$((w+1)); [[ "$pie" == "PIE Disabled" ]] && w=$((w+1)); [[ "$rel" == "No RELRO" || "$rel" == "Partial RELRO" ]] && w=$((w+1))
  (( w >= 2 )) && exec_weak=$((exec_weak+1))
done <<< "$profiles"
if (( exec_total >= 10 && exec_weak * 100 / exec_total >= 50 )); then
  pct=$((exec_weak * 100 / exec_total))
  jq -cn --arg title "Firmware-wide weak binary hardening policy" --arg severity "MEDIUM" --arg confidence "HIGH" \
    --arg analysis "$exec_weak of $exec_total analyzed userspace executables ($pct%) share at least two common hardening weaknesses. This pattern is more consistent with a firmware build-policy/toolchain configuration issue than with isolated per-binary defects." \
    --argjson remediation '["Enable hardening flags globally in the firmware build system","Prioritize rebuilding network-facing services first","Add hardening checks to CI/CD or release validation"]' \
    '{title:$title,severity:$severity,confidence:$confidence,analysis:$analysis,remediation:$remediation}' >> "$SYSTEMIC"
fi

# Kernel modules are kept as informational evidence, not promoted as ordinary userspace hardening vulnerabilities.
ko_count="$(jq -r 'select(.source=="checksec" and (.asset|endswith(".ko"))) | .asset' "$EVIDENCE" | sort -u | wc -l | tr -d ' ')"
if (( ko_count > 0 )); then
  jq -cn --arg title "Kernel-module hardening observations" --arg count "$ko_count" \
    '{title:$title,severity:"INFO",analysis:("Hardening profiles were collected for "+$count+" kernel modules. These are retained in raw evidence and are not scored using the same criteria as ordinary userspace executables.")}' >> "$INFO"
fi

jq -n \
  --slurpfile cases "$CASES" --slurpfile systemic "$SYSTEMIC" --slurpfile info "$INFO" \
  '{security_cases:$cases,systemic_findings:$systemic,informational:$info}' > "$OUT"
