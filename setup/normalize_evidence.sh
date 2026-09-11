#!/usr/bin/env bash
set -euo pipefail
ROOTFS="$1"; FW_TSV="$2"; CS_JSONL="$3"; OUT="$4"
: > "$OUT"

# Firmwalker observations are preserved as evidence, not treated as confirmed vulnerabilities.
while IFS=$'\t' read -r category severity path evidence; do
  [[ -z "${category:-}" ]] && continue
  property="$category"
  value="$evidence"
  case "$category" in
    service) property="service_indicator" ;;
    credential) property="credential_indicator" ;;
    crypto) property="crypto_material" ;;
    ssh) property="ssh_material" ;;
    sensitive_pattern) property="sensitive_pattern" ;;
    config) property="configuration_file" ;;
    database) property="database_file" ;;
    network) property="network_indicator" ;;
    web_interface) property="web_interface_indicator" ;;
    update) property="update_indicator" ;;
    component) property="component_indicator" ;;
    encoding) property="encoding_indicator" ;;
  esac
  jq -cn \
    --arg source "firmwalker" \
    --arg type "$category" \
    --arg asset "$path" \
    --arg property "$property" \
    --arg value "$value" \
    --arg severity_hint "$severity" \
    '{source:$source,type:$type,asset:$asset,property:$property,value:$value,severity_hint:$severity_hint}' >> "$OUT"
done < "$FW_TSV"

# Keep one complete hardening profile per ELF instead of exploding every flag into a vulnerability.
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  f=$(jq -r '.file // empty' <<<"$line")
  [[ -z "$f" ]] && continue
  relp="/${f#"$ROOTFS"/}"
  jq -c --arg asset "$relp" '
    {
      source:"checksec",
      type:"binary_hardening",
      asset:$asset,
      property:"hardening_profile",
      value:{
        relro:(.relro.value // "Unknown"),
        canary:(.canary.value // "Unknown"),
        nx:(.nx.value // "Unknown"),
        pie:(.pie.value // "Unknown"),
        rpath:(.rpath.value // "Unknown"),
        rpath_status:(.rpath.status // "unknown"),
        runpath:(.runpath.value // "Unknown"),
        runpath_status:(.runpath.status // "unknown"),
        fortify:(.fortify.output // "Unknown"),
        separate_code:(.separate_code.value // "Unknown"),
        separate_code_status:(.separate_code.status // "unknown"),
        cfi:(.cfi.value // "Unknown"),
        cfi_status:(.cfi.status // "unknown"),
        stack_clash:(.stack_clash.value // "Unknown"),
        stack_clash_status:(.stack_clash.status // "unknown")
      }
    }' <<<"$line" >> "$OUT"
done < "$CS_JSONL"
