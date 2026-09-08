#!/usr/bin/env bash
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="$ROOT/tools/bin:$ROOT/.deps/venv/bin:$PATH"
printf '%-28s %s\n' 'COMPONENT' 'STATUS'
printf '%-28s %s\n' '---------' '------'
for c in rustc cargo go jq file readelf nm strings 7z zstd tar tsk_recover unsquashfs sasquatch jefferson ubireader_extract_files ubireader_extract_images vmlinux-to-elf unyaffs; do
  if command -v "$c" >/dev/null 2>&1; then
    printf '%-28s OK (%s)\n' "$c" "$(command -v "$c")"
  else
    printf '%-28s MISSING/OPTIONAL\n' "$c"
  fi
done
