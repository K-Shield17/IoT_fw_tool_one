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
getArray() { array=(); while IFS= read -r line; do [[ -n "$line" ]] && array+=("$line"); done < "$1"; return 0; }
relpath() { local p="$1"; printf '/%s' "${p#"$FIRMDIR"/}"; }
emit() { # category severity path evidence
    printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$TSV"
}

msg "***Firmware Directory***"; msg "$FIRMDIR"

# Upstream Firmwalker: password files
msg "***Search for password files***"
getArray "$DATA_DIR/passfiles.txt"
for passfile in "${array[@]}"; do
    msg "##################################### $passfile"
    while IFS= read -r p; do [[ -z "$p" ]] && continue; r="$(relpath "$p")"; echo "$r" >> "$FILE"; emit credential HIGH "$r" "password-related file: $passfile"; done < <(find "$FIRMDIR" -type f -name "$passfile" 2>/dev/null)
done

# Upstream Firmwalker: Unix MD5 password hashes
msg "***Search for Unix-MD5 hashes***"
while IFS= read -r hit; do [[ -z "$hit" ]] && continue; echo "$hit" >> "$FILE"; p="${hit%%:*}"; emit credential HIGH "$(relpath "$p")" "Unix-MD5 password hash detected"; done < <(grep -sroE '\$1\$[[:alnum:]./]{8}\$[[:alnum:]./]{22}' "$FIRMDIR" 2>/dev/null || true)

# Upstream Firmwalker: SSL-related files; Shodan intentionally removed (offline static analysis)
msg "***Search for SSL related files***"
getArray "$DATA_DIR/sslfiles.txt"
for sslfile in "${array[@]}"; do
    while IFS= read -r p; do [[ -z "$p" ]] && continue; r="$(relpath "$p")"; echo "$r" >> "$FILE"; sev=MEDIUM; [[ "$p" == *.key || "$p" == *private* ]] && sev=HIGH; emit crypto "$sev" "$r" "SSL/TLS material: $sslfile"; done < <(find "$FIRMDIR" -type f -name "$sslfile" 2>/dev/null)
done

# Upstream Firmwalker: SSH-related files
msg "***Search for SSH related files***"
getArray "$DATA_DIR/sshfiles.txt"
for sshfile in "${array[@]}"; do
    while IFS= read -r p; do [[ -z "$p" ]] && continue; r="$(relpath "$p")"; echo "$r" >> "$FILE"; emit ssh HIGH "$r" "SSH key/material: $sshfile"; done < <(find "$FIRMDIR" -type f -name "$sshfile" 2>/dev/null)
done

# Upstream Firmwalker: configuration files
msg "***Search for configuration files***"
getArray "$DATA_DIR/files.txt"
for pat in "${array[@]}"; do while IFS= read -r p; do [[ -z "$p" ]] && continue; r="$(relpath "$p")"; echo "$r" >> "$FILE"; emit config INFO "$r" "configuration file: $pat"; done < <(find "$FIRMDIR" -type f -name "$pat" 2>/dev/null); done

# Upstream Firmwalker: database files
msg "***Search for database related files***"
getArray "$DATA_DIR/dbfiles.txt"
for pat in "${array[@]}"; do while IFS= read -r p; do [[ -z "$p" ]] && continue; r="$(relpath "$p")"; echo "$r" >> "$FILE"; emit database MEDIUM "$r" "database file: $pat"; done < <(find "$FIRMDIR" -type f -name "$pat" 2>/dev/null); done

# Upstream Firmwalker: sensitive patterns. Keep the source rule list unchanged.
msg "***Search for sensitive patterns in files***"
getArray "$DATA_DIR/patterns.txt"
for pattern in "${array[@]}"; do
    while IFS= read -r p; do [[ -z "$p" ]] && continue; r="$(relpath "$p")"; echo "$pattern -> $r" >> "$FILE"; sev=MEDIUM; case "$pattern" in password|passwd|pwd|secret|token|api_key|api\ key|AccessKey|AWSSecretKey|client_secret|private\ key) sev=HIGH;; esac; emit sensitive_pattern "$sev" "$r" "matched pattern: $pattern"; done < <(grep -lsirF --exclude-dir=dev -- "$pattern" "$FIRMDIR" 2>/dev/null || true)
done

# Upstream Firmwalker: web servers
msg "***Search for web servers***"
getArray "$DATA_DIR/webservers.txt"
for webserver in "${array[@]}"; do while IFS= read -r p; do [[ -z "$p" ]] && continue; r="$(relpath "$p")"; echo "$r" >> "$FILE"; emit service MEDIUM "$r" "web server binary: $webserver"; done < <(find "$FIRMDIR" -type f -name "$webserver" 2>/dev/null); done

# Upstream Firmwalker: important network binaries
msg "***Search for important binaries***"
getArray "$DATA_DIR/binaries.txt"
for binary in "${array[@]}"; do while IFS= read -r p; do [[ -z "$p" ]] && continue; r="$(relpath "$p")"; echo "$r" >> "$FILE"; sev=INFO; [[ "$binary" == telnet || "$binary" == telnetd || "$binary" == tftp ]] && sev=HIGH; emit service "$sev" "$r" "important/network binary: $binary"; done < <(find "$FIRMDIR" -type f -name "$binary" 2>/dev/null); done

# Upstream Firmwalker: IPs and URLs. Email enumeration intentionally removed.
msg "***Search for IP addresses***"
grep -sRIEho '\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b' --exclude-dir=dev "$FIRMDIR" 2>/dev/null | sort -u | while IFS= read -r ip; do [[ -z "$ip" ]] || { echo "$ip" >> "$FILE"; emit network INFO "-" "IP address: $ip"; }; done || true
msg "***Search for URLs***"
grep -sRIEoh '(http|https)://[^/"[:space:]]+' --exclude-dir=dev "$FIRMDIR" 2>/dev/null | sort -u | while IFS= read -r url; do [[ -z "$url" ]] || { echo "$url" >> "$FILE"; emit network INFO "-" "URL: $url"; }; done || true
