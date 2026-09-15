#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="$SCRIPT_DIR/data"

usage() { echo "Usage: $0 <rootfs> <raw-output> <tsv-output>"; exit 1; }
[[ $# -eq 3 ]] || usage
FIRMDIR="${1%/}"
FILE="$2"
TSV="$3"
: > "$FILE"
: > "$TSV"

msg() { echo "$1" | tee -a "$FILE" >/dev/null; }
relpath() { local p="$1"; printf '/%s' "${p#"$FIRMDIR"/}"; }
emit() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$TSV"; }

# High-value firmware paths only.
CONFIG_DIRS=(/etc /etc/config /etc/default /etc/init.d /etc/rc.d /usr/etc /usr/local/etc /var /var/etc /var/lib /root /home)
WEB_DIRS=(/www /htdocs /var/www /cgi-bin /usr/lib/lua/luci)
EXEC_DIRS=(/bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /www/cgi-bin /htdocs/cgi-bin /cgi-bin)
KEY_DIRS=(/etc/ssl /etc/ssh /etc/dropbear /etc/certs /etc/pki /root/.ssh /home)
UPDATE_DIRS=(/sbin /usr/sbin /bin /usr/bin /etc/init.d /etc/config /www /htdocs /cgi-bin)

existing_dirs() {
  local d
  for d in "$@"; do
    [[ -d "$FIRMDIR$d" ]] && printf '%s\n' "$FIRMDIR$d"
  done
}

# Candidate text/configuration files.
TEXT_CANDIDATES="$(mktemp)"
trap 'rm -f "$TEXT_CANDIDATES"' EXIT
while IFS= read -r d; do
  find "$d" -type f \
    \( -name '*.conf' -o -name '*.cfg' -o -name '*.ini' -o -name '*.json' -o -name '*.xml' \
       -o -name '*.sh' -o -name '*.lua' -o -name '*.cgi' -o -name '*.php' -o -name '*.js' \
       -o -name '*.html' -o -name '*.htm' -o -name '*.txt' -o -name '*.log' \
       -o -name 'passwd' -o -name 'shadow' -o -name 'group' -o -name 'services' \
       -o -name 'inetd.conf' -o -name 'rc.local' \) -print 2>/dev/null
done < <(existing_dirs "${CONFIG_DIRS[@]}" "${WEB_DIRS[@]}") | sort -u > "$TEXT_CANDIDATES"

msg "***Firmware Directory***"; msg "$FIRMDIR"
msg "***Search scope: high-value configuration, web, service and executable paths only***"

# ---------------------------------------------------------------------------
# Credentials / default settings
# ---------------------------------------------------------------------------
msg "***Credential and default-account indicators***"
for rel in /etc/passwd /etc/shadow /etc/group /etc/.htpasswd /www/.htpasswd /htdocs/.htpasswd; do
  p="$FIRMDIR$rel"; [[ -f "$p" ]] || continue
  echo "$rel" >> "$FILE"
  sev=MEDIUM; [[ "$rel" == */passwd || "$rel" == */shadow || "$rel" == */.htpasswd ]] && sev=HIGH
  emit credential "$sev" "$rel" "credential/account file present: $(basename "$rel")"
done

# Unix MD5 password hashes.
while IFS= read -r p; do
  [[ -f "$p" ]] || continue
  if grep -aEq '\$1\$[[:alnum:]./]{1,16}\$[[:alnum:]./]{20,}' "$p" 2>/dev/null; then
    r="$(relpath "$p")"; echo "Unix-MD5 -> $r" >> "$FILE"
    emit credential HIGH "$r" "Unix-MD5 password hash detected"
  fi
done < "$TEXT_CANDIDATES"

DEFAULT_CREDENTIAL_PATTERNS=('admin:admin' 'admin:password' 'root:root' 'guest:guest')
CREDENTIAL_ASSIGNMENT_PATTERNS=('password=' 'passwd=' 'pwd=' 'secret=' 'token=' 'api_key=' 'apikey=' 'client_secret=')

for pattern in "${DEFAULT_CREDENTIAL_PATTERNS[@]}"; do
  while IFS= read -r p; do
    [[ -f "$p" ]] || continue
    if grep -aIqiF -- "$pattern" "$p" 2>/dev/null; then
      r="$(relpath "$p")"; echo "$pattern -> $r" >> "$FILE"
      emit credential_default HIGH "$r" "default credential indicator: $pattern"
    fi
  done < "$TEXT_CANDIDATES"
done

for pattern in "${CREDENTIAL_ASSIGNMENT_PATTERNS[@]}"; do
  while IFS= read -r p; do
    [[ -f "$p" ]] || continue
    if grep -aIqiF -- "$pattern" "$p" 2>/dev/null; then
      r="$(relpath "$p")"; echo "$pattern -> $r" >> "$FILE"
      emit credential_assignment MEDIUM "$r" "credential assignment indicator: $pattern"
    fi
  done < "$TEXT_CANDIDATES"
done

# ---------------------------------------------------------------------------
# TLS/SSH key and certificate material
# ---------------------------------------------------------------------------
msg "***TLS/SSH key and certificate material***"
while IFS= read -r d; do
  while IFS= read -r -d '' p; do
    r="$(relpath "$p")"; b="$(basename "$p")"
    case "$b" in
      *.key|id_rsa|id_dsa|id_ecdsa|id_ed25519|ssh_host_*_key|dropbear_*_host_key) sev=HIGH; kind="private/key material" ;;
      authorized_keys|known_hosts) sev=MEDIUM; kind="SSH trust material" ;;
      *.pem|*.crt|*.cer|*.p12|*.pfx) sev=MEDIUM; kind="certificate/TLS material" ;;
      *) continue ;;
    esac
    echo "$r" >> "$FILE"
    emit crypto "$sev" "$r" "$kind: $b"
    [[ "$b" == id_* || "$b" == ssh_host_* || "$b" == dropbear_* || "$b" == authorized_keys || "$b" == known_hosts ]] && emit ssh "$sev" "$r" "SSH key/material: $b"
  done < <(find "$d" -type f \( -name '*.pem' -o -name '*.crt' -o -name '*.cer' -o -name '*.key' -o -name '*.p12' -o -name '*.pfx' \
    -o -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' -o -name 'authorized_keys' -o -name 'known_hosts' \
    -o -name 'ssh_host_*_key' -o -name 'dropbear_*_host_key' \) -print0 2>/dev/null)
done < <(existing_dirs "${KEY_DIRS[@]}")

# ---------------------------------------------------------------------------
# Configuration / data stores
# ---------------------------------------------------------------------------
msg "***Selected configuration and data-store files***"
while IFS= read -r p; do
  [[ -f "$p" ]] || continue; r="$(relpath "$p")"
  case "$p" in
    *.db|*.sqlite|*.sqlite3) emit database MEDIUM "$r" "database file: $(basename "$p")" ;;
    *) emit config INFO "$r" "configuration/web text file: $(basename "$p")" ;;
  esac
done < "$TEXT_CANDIDATES"

while IFS= read -r d; do
  while IFS= read -r -d '' p; do
    r="$(relpath "$p")"; echo "$r" >> "$FILE"
    emit database MEDIUM "$r" "database file: $(basename "$p")"
  done < <(find "$d" -type f \( -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' \) -print0 2>/dev/null)
done < <(existing_dirs /etc /var /www /htdocs /root /home)

# ---------------------------------------------------------------------------
# Network services
# ---------------------------------------------------------------------------
msg "***Network service binaries***"
SERVICE_NAMES=(telnet telnetd ftp ftpd tftp tftpd dropbear ssh sshd httpd uhttpd lighttpd nginx boa apache apache2 dnsmasq upnpd miniupnpd rpcd pppd pppoe pppoe-server)

for name in "${SERVICE_NAMES[@]}"; do
  while IFS= read -r d; do
    p="$d/$name"; [[ -f "$p" ]] || continue
    r="$(relpath "$p")"; sev=MEDIUM
    case "$name" in telnet|telnetd|ftp|ftpd|tftp|tftpd) sev=HIGH ;; esac
    echo "$r" >> "$FILE"; emit service "$sev" "$r" "network service binary: $name"
  done < <(existing_dirs "${EXEC_DIRS[@]}")
done

msg "***Service startup/configuration references***"
STARTUP_CANDIDATES="$(mktemp)"
trap 'rm -f "$TEXT_CANDIDATES" "$STARTUP_CANDIDATES"' EXIT
while IFS= read -r d; do
  find "$d" -maxdepth 3 -type f -print 2>/dev/null
done < <(existing_dirs /etc/init.d /etc/rc.d /etc/config /etc/default) | sort -u > "$STARTUP_CANDIDATES"

for name in "${SERVICE_NAMES[@]}"; do
  while IFS= read -r p; do
    [[ -f "$p" ]] || continue
    if grep -aIqiE "(^|[/[:space:]])${name}([[:space:]]|$|[;&])" "$p" 2>/dev/null; then
      emit service INFO "$(relpath "$p")" "startup/config reference to service: $name"
    fi
  done < "$STARTUP_CANDIDATES"
done

# ---------------------------------------------------------------------------
# Web/API interface indicators
# Only strong path or content evidence becomes web_interface.
# ---------------------------------------------------------------------------
msg "***Web/API interface indicators***"
WEB_INTERFACE_PATTERNS=('login' 'logout' 'authentication' 'session' 'username' 'password' '<form')
WEB_ENDPOINT_PATTERNS=('/cgi-bin/' '/api/' 'controller' 'route')

while IFS= read -r d; do
  while IFS= read -r -d '' p; do
    r="$(relpath "$p")"; web_related=false; web_reason=""

    case "$r" in
      /cgi-bin/*|/www/cgi-bin/*|/htdocs/cgi-bin/*) web_related=true; web_reason="CGI/request-handler path" ;;
    esac

    if [[ "$web_related" == false ]]; then
      for pattern in "${WEB_INTERFACE_PATTERNS[@]}"; do
        if grep -aIqiF -- "$pattern" "$p" 2>/dev/null; then web_related=true; web_reason="interface indicator: $pattern"; break; fi
      done
    fi

    if [[ "$web_related" == false ]]; then
      for pattern in "${WEB_ENDPOINT_PATTERNS[@]}"; do
        if grep -aIqiF -- "$pattern" "$p" 2>/dev/null; then web_related=true; web_reason="API/request-handler indicator: $pattern"; break; fi
      done
    fi

    [[ "$web_related" == true ]] && emit web_interface INFO "$r" "web/API interface evidence: $web_reason"

    for pattern in 'cmd=' 'exec=' 'command=' 'execute='; do
      if grep -aIqiF -- "$pattern" "$p" 2>/dev/null; then emit sensitive_pattern MEDIUM "$r" "matched pattern: $pattern"; fi
    done
  done < <(find "$d" -type f \( -name '*.cgi' -o -name '*.php' -o -name '*.lua' -o -name '*.js' -o -name '*.html' -o -name '*.htm' \) -print0 2>/dev/null)
done < <(existing_dirs "${WEB_DIRS[@]}")

# ---------------------------------------------------------------------------
# Firmware update mechanisms
# ---------------------------------------------------------------------------
msg "***Firmware update mechanism indicators***"
UPDATE_PATTERNS=('sysupgrade' 'fw_upgrade' 'firmware upgrade' 'firmware update' 'upgrade' 'mtd write' 'flash' 'signature' 'verify' 'checksum')
UPDATE_SECURITY_PATTERNS=('SHA256' 'SHA512' 'RSA' 'ECDSA' 'signature' 'verify' 'certificate' 'public key')

while IFS= read -r d; do
  while IFS= read -r -d '' p; do
    size=$(stat -c '%s' "$p" 2>/dev/null || echo 0); (( size <= 4194304 )) || continue
    matched=false
    for pattern in "${UPDATE_PATTERNS[@]}"; do
      if grep -aIqiF -- "$pattern" "$p" 2>/dev/null; then emit update INFO "$(relpath "$p")" "firmware-update indicator: $pattern"; matched=true; fi
    done
    if [[ "$matched" == true ]]; then
      for pattern in "${UPDATE_SECURITY_PATTERNS[@]}"; do
        if grep -aIqiF -- "$pattern" "$p" 2>/dev/null; then emit update INFO "$(relpath "$p")" "update verification/crypto indicator: $pattern"; fi
      done
    fi
  done < <(find "$d" -maxdepth 4 -type f \( -perm /111 -o -name '*.sh' -o -name '*.cgi' -o -name '*.lua' -o -name '*.conf' -o -name '*.cfg' \) -print0 2>/dev/null)
done < <(existing_dirs "${UPDATE_DIRS[@]}")

# ---------------------------------------------------------------------------
# Components / version hints
# ---------------------------------------------------------------------------
msg "***Important component/version hints***"
COMPONENTS=(busybox openssl dropbear ssh sshd dnsmasq lighttpd nginx httpd uhttpd curl wget)

for name in "${COMPONENTS[@]}"; do
  while IFS= read -r d; do
    p="$d/$name"; [[ -f "$p" ]] || continue
    r="$(relpath "$p")"; ver=""
    if command -v strings >/dev/null 2>&1; then
      ver="$(strings -a "$p" 2>/dev/null | grep -Eim1 '(BusyBox v|OpenSSL [0-9]|Dropbear_[0-9]|dropbear [0-9]|OpenSSH[_ ]|dnsmasq[- ]?[0-9]|lighttpd[/ ]|nginx[/ ]|curl [0-9]|Wget[/ ]|uClibc|GLIBC_[0-9])' || true)"
      ver="${ver//$'\t'/ }"; ver="${ver//$'\n'/ }"
    fi
    if [[ -n "$ver" ]]; then emit component INFO "$r" "component: $name; version hint: $ver"; else emit component INFO "$r" "component present: $name"; fi
  done < <(existing_dirs "${EXEC_DIRS[@]}")
done

for glob in "$FIRMDIR"/lib/libc.so.* "$FIRMDIR"/lib/libssl.so.* "$FIRMDIR"/usr/lib/libssl.so.*; do
  [[ -f "$glob" ]] || continue
  emit component INFO "$(relpath "$glob")" "shared component present: $(basename "$glob")"
done

# ---------------------------------------------------------------------------
# Crypto indicators
#
# Level 1: weak algorithm string              -> crypto_weak_indicator / INFO
# Level 2: weak algorithm + security context  -> crypto_weak_context   / INFO
# Level 3: actual weak configuration value    -> crypto_weak_applied   / MEDIUM
# ---------------------------------------------------------------------------
msg "***Cryptographic algorithm and encoding indicators***"
WEAK_CRYPTO=('MD5' 'SHA1' 'SHA-1' 'DES' '3DES' 'RC4' 'ECB')
MODERN_CRYPTO=('AES' 'SHA256' 'SHA-256' 'SHA512' 'SHA-512' 'RSA' 'ECDSA' 'TLS')
ENCODING_PATTERNS=('base64' 'xor')

# Level 1 + Level 2
for pattern in "${WEAK_CRYPTO[@]}"; do
  while IFS= read -r p; do
    [[ -f "$p" ]] || continue
    matches="$(grep -aIniF -- "$pattern" "$p" 2>/dev/null || true)"; [[ -n "$matches" ]] || continue
    r="$(relpath "$p")"
    emit crypto_weak_indicator INFO "$r" "legacy/weak crypto indicator: $pattern"

    while IFS=: read -r lineno _; do
      [[ "$lineno" =~ ^[0-9]+$ ]] || continue
      start=$((lineno > 2 ? lineno - 2 : 1)); end=$((lineno + 2))
      snippet="$(sed -n "${start},${end}p" "$p" 2>/dev/null)"; context=""

      case "$pattern" in
        MD5|SHA1|SHA-1)
          for ctx in 'password' 'passwd' 'signature' 'signed' 'verify' 'verification' 'certificate' 'digest' 'hash algorithm'; do
            if grep -aIqiF -- "$ctx" <<< "$snippet"; then context="$ctx"; break; fi
          done
          ;;
        DES|3DES|RC4|ECB)
          for ctx in 'encrypt' 'encryption' 'decrypt' 'decryption' 'cipher' 'secret key' 'session key'; do
            if grep -aIqiF -- "$ctx" <<< "$snippet"; then context="$ctx"; break; fi
          done
          ;;
      esac

      if [[ -n "$context" ]]; then
        emit crypto_weak_context INFO "$r" "weak crypto reference with security-relevant context: $pattern; context: $context"
        break
      fi
    done <<< "$matches"
  done < "$TEXT_CANDIDATES"
done

# Level 3: actual weak/deprecated settings.
# Restrict to configuration-like files so implementation/support code does not
# become a confirmed FW-005 candidate.
msg "***Applied weak/deprecated cryptographic settings***"
while IFS= read -r p; do
  [[ -f "$p" ]] || continue
  r="$(relpath "$p")"

  case "$p" in
    *.conf|*.cfg|*.ini|*/etc/config/*|*/etc/default/*) ;;
    *) continue ;;
  esac

  # Wireless WEP configuration.
  if grep -aEqi "^[[:space:]]*(option[[:space:]]+encryption[[:space:]]+|encryption[[:space:]]*=[[:space:]]*)['\"]?(wep|wep-open|wep-shared)['\"]?([[:space:]]|$)" "$p" 2>/dev/null; then
    emit crypto_weak_applied MEDIUM "$r" "weak cryptographic setting applied: WEP"
  fi

  # Explicit weak hash/signature algorithm configuration.
  if grep -aEqi "^[[:space:]]*(option[[:space:]]+)?(hash|digest|signature|algorithm)[[:space:]=]+['\"]?(md5|sha1|sha-1)['\"]?([[:space:]]|$)" "$p" 2>/dev/null; then
    emit crypto_weak_applied MEDIUM "$r" "weak hash/signature algorithm configured"
  fi

  # Explicit weak cipher/mode configuration.
  if grep -aEqi "^[[:space:]]*(option[[:space:]]+)?(cipher|encryption|algorithm|mode)[[:space:]=]+['\"]?(des|3des|rc4|ecb)['\"]?([[:space:]]|$)" "$p" 2>/dev/null; then
    emit crypto_weak_applied MEDIUM "$r" "weak cipher/mode configured"
  fi
done < "$TEXT_CANDIDATES"

# Modern crypto indicators.
for pattern in "${MODERN_CRYPTO[@]}"; do
  while IFS= read -r p; do
    [[ -f "$p" ]] || continue
    if grep -aIqiF -- "$pattern" "$p" 2>/dev/null; then emit crypto INFO "$(relpath "$p")" "modern crypto indicator: $pattern"; fi
  done < "$TEXT_CANDIDATES"
done

# Encoding / obfuscation indicators.
for pattern in "${ENCODING_PATTERNS[@]}"; do
  while IFS= read -r p; do
    [[ -f "$p" ]] || continue
    if grep -aIqiF -- "$pattern" "$p" 2>/dev/null; then emit encoding INFO "$(relpath "$p")" "encoding/obfuscation indicator: $pattern"; fi
  done < "$TEXT_CANDIDATES"
done

# ---------------------------------------------------------------------------
# IP / URL indicators
# ---------------------------------------------------------------------------
msg "***Selected IP and URL indicators***"
while IFS= read -r p; do
  [[ -f "$p" ]] || continue
  while IFS= read -r ip; do
    [[ -n "$ip" ]] && emit network INFO "$(relpath "$p")" "IP address: $ip"
  done < <(grep -aEho '\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b' "$p" 2>/dev/null | sort -u || true)

  while IFS= read -r url; do
    [[ -n "$url" ]] && emit network INFO "$(relpath "$p")" "URL: $url"
  done < <(grep -aEoh '(http|https)://[^/"[:space:]]+' "$p" 2>/dev/null | sort -u || true)
done < "$TEXT_CANDIDATES"

msg "***Firmwalker-lite selected scan complete***"
