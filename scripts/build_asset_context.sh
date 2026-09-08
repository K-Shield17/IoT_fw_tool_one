#!/usr/bin/env bash
set -euo pipefail
ROOTFS="$1"; EVIDENCE="$2"; OUT="$3"
: > "$OUT"

classify_role() {
  local p="$1" b
  b="$(basename "$p")"
  case "$b" in
    uhttpd|httpd|lighttpd|apache|alphapd) echo web_server ;;
    dropbear|sshd) echo ssh_server ;;
    pppd|pppoe|pppoe-server) echo ppp_service ;;
    dnsmasq) echo dns_dhcp_service ;;
    miniupnpd|upnpd) echo upnp_service ;;
    rpcd) echo rpc_service ;;
    telnetd|telnet) echo telnet_service ;;
    tftpd|tftp) echo tftp_service ;;
    *)
      case "$p" in
        /lib/modules/*.ko|/lib/modules/*/*.ko|*.ko) echo kernel_module ;;
        *.so|*.so.*|/lib/*.so*|/usr/lib/*.so*) echo library ;;
        /www/*|/htdocs/*|/cgi-bin/*|/usr/lib/lua/luci/*) echo web_content ;;
        /etc/*) echo configuration ;;
        /bin/*|/sbin/*|/usr/bin/*|/usr/sbin/*) echo executable ;;
        *) echo other ;;
      esac
      ;;
  esac
}

# Emit unique assets from evidence.
jq -r 'select(.asset != null and .asset != "" and .asset != "-") | .asset' "$EVIDENCE" | sort -u | while IFS= read -r asset; do
  [[ -z "$asset" ]] && continue
  role="$(classify_role "$asset")"
  exposure="unknown"
  case "$role" in web_server|ssh_server|ppp_service|dns_dhcp_service|upnp_service|rpc_service|telnet_service|tftp_service) exposure="network_service";; esac

  rel="${asset#/}"
  real="$ROOTFS/$rel"
  mode="unknown"; owner="unknown"; group="unknown"
  if [[ -e "$real" ]]; then
    mode="$(stat -c '%a' "$real" 2>/dev/null || echo unknown)"
    owner="$(stat -c '%U' "$real" 2>/dev/null || echo unknown)"
    group="$(stat -c '%G' "$real" 2>/dev/null || echo unknown)"
  fi

  # Static evidence that a service is referenced from startup/configuration material.
  startup_ref=false
  if [[ "$exposure" == "network_service" ]]; then
    base="$(basename "$asset")"
    if grep -RIlF --exclude-dir=dev --exclude-dir=proc --exclude-dir=sys -- "$base" \
      "$ROOTFS/etc/init.d" "$ROOTFS/etc/rc.d" "$ROOTFS/etc/rc.local" "$ROOTFS/etc/config" 2>/dev/null | grep -q .; then
      startup_ref=true
    fi
  fi

  jq -cn \
    --arg asset "$asset" --arg role "$role" --arg exposure "$exposure" \
    --arg mode "$mode" --arg owner "$owner" --arg group "$group" \
    --argjson startup_ref "$startup_ref" \
    '{asset:$asset,role:$role,exposure:$exposure,mode:$mode,owner:$owner,group:$group,startup_reference:$startup_ref}' >> "$OUT"
done
