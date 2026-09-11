#!/usr/bin/env bash
set -euo pipefail
ROOTFS="${1%/}"; BIN="$2"; OUT="$3"; : > "$OUT"

# Preventive triage: check only executable-heavy and externally exposed paths.
TARGET_DIRS=(
  /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin
  /www/cgi-bin /htdocs/cgi-bin /cgi-bin
)

is_elf() {
  local f="$1" magic
  magic=$(dd if="$f" bs=1 count=4 2>/dev/null | od -An -tx1 | tr -d ' \n')
  [[ "$magic" == "7f454c46" ]]
}

# De-duplicate files in case firmware paths are symlinked or overlap.
declare -A SEEN=()
for rel in "${TARGET_DIRS[@]}"; do
  dir="$ROOTFS$rel"
  [[ -d "$dir" ]] || continue
  while IFS= read -r -d '' f; do
    # Do not follow symlinks; analyze the real executable where it resides.
    [[ -f "$f" && ! -L "$f" ]] || continue
    key="$(readlink -f "$f" 2>/dev/null || printf '%s' "$f")"
    [[ -n "${SEEN[$key]:-}" ]] && continue
    SEEN[$key]=1
    is_elf "$f" || continue
    "$BIN" "$f" >> "$OUT" 2>/dev/null || true
  done < <(find "$dir" -maxdepth 3 -type f \( -perm /111 -o -path '*/cgi-bin/*' \) -print0 2>/dev/null)
done
