#!/usr/bin/env bash
set -euo pipefail
ROOTFS="$1"; BIN="$2"; OUT="$3"; : > "$OUT"
while IFS= read -r -d '' f; do
    magic=$(dd if="$f" bs=1 count=4 2>/dev/null | od -An -tx1 | tr -d ' \n')
    [[ "$magic" == "7f454c46" ]] || continue
    "$BIN" "$f" >> "$OUT" 2>/dev/null || true
done < <(find "$ROOTFS" -type f -print0 2>/dev/null)
