#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
usage(){ echo "Usage: $0 scan <firmware> [-o output] | analyze-rootfs <rootfs> [-o output]"; exit 1; }
[[ $# -ge 2 ]] || usage
MODE="$1"; INPUT="$2"; shift 2; OUT_BASE="results"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--output) [[ $# -ge 2 ]] || usage; OUT_BASE="$2"; shift 2;;
    *) usage;;
  esac
done
[[ "$MODE" == "scan" || "$MODE" == "analyze-rootfs" ]] || usage

[[ -e "$INPUT" ]] || { echo "[!] Input not found: $INPUT" >&2; exit 1; }
INPUT="$(readlink -f "$INPUT")"
OUT_BASE="$(readlink -m "$OUT_BASE")"

if [[ "$MODE" == "scan" ]]; then
  TARGET_NAME="$(basename "$INPUT")"
  TARGET_NAME="${TARGET_NAME%.*}"
else
  TARGET_NAME="$(basename "$INPUT")"
fi
TARGET_NAME="$(printf '%s' "$TARGET_NAME" | sed -E 's/[^[:alnum:]_.-]+/_/g; s/^_+//; s/_+$//')"
[[ -n "$TARGET_NAME" ]] || TARGET_NAME="analysis"
OUT="$OUT_BASE/$TARGET_NAME"
if [[ -e "$OUT" ]]; then
  N=2
  OUT="$OUT_BASE/${TARGET_NAME}_$N"
  while [[ -e "$OUT" ]]; do N=$((N + 1)); OUT="$OUT_BASE/${TARGET_NAME}_$N"; done
fi

"$ROOT/setup/bootstrap.sh" "$MODE"
# shellcheck disable=SC1090
[[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"
export PATH="$ROOT/tools/bin:$ROOT/.deps/venv/bin:$PATH"
export GOTOOLCHAIN=auto

BW="$ROOT/tools/binwalk-lite/target/release/binwalk"
CS="$ROOT/tools/checksec-lite/checksec-lite"
if [[ ! -x "$BW" || ! -x "$CS" ]]; then
  echo '[*] Analyzer binaries are missing; building automatically.'
  "$ROOT/build.sh"
fi

case "$OUT_BASE" in
  /|"$HOME"|"$(readlink -f "$ROOT")") echo "[!] Unsafe output base directory: $OUT_BASE" >&2; exit 1;;
esac
mkdir -p "$OUT/raw"
echo "[+] Result directory: $OUT"

# Extraction and raw analyzer data are working artifacts only. They are always
# removed on exit; final report.html/report.json remain in the result directory.
cleanup_working_data() {
  [[ -n "${OUT:-}" && -d "$OUT" ]] || return 0
  rm -rf -- "$OUT/extracted" "$OUT/raw"
}
trap cleanup_working_data EXIT

ROOTFS=""
if [[ "$MODE" == "scan" ]]; then
  mkdir -p "$OUT/extracted"
  echo '[1/7] Binwalk scan + temporary extraction'
  if ! "$BW" "$INPUT" "$OUT/extracted" > "$OUT/raw/binwalk.jsonl" 2> "$OUT/raw/binwalk.stderr"; then
    echo '[!] Binwalk returned a non-zero status. Trying to continue with any extracted filesystem.' >&2
  fi
  ROOTFS="$($ROOT/setup/find_rootfs.sh "$OUT/extracted" 2>/dev/null || true)"
  if [[ -z "$ROOTFS" ]]; then
    echo '[!] RootFS not found after extraction.' >&2
    echo '    Temporary extraction/raw data will be removed automatically.' >&2
    exit 1
  fi
else
  [[ -d "$INPUT" ]] || { echo "[!] RootFS path is not a directory: $INPUT" >&2; exit 1; }
  ROOTFS="$INPUT"
fi

printf '%s\n' "$ROOTFS" > "$OUT/raw/rootfs.txt"
echo "[+] RootFS: $ROOTFS"

echo '[2/7] Firmwalker targeted preventive checks'
"$ROOT/tools/firmwalker-lite/firmwalker-lite.sh" "$ROOTFS" "$OUT/raw/firmwalker.txt" "$OUT/raw/firmwalker.tsv"

echo '[3/7] Checksec high-value ELF checks'
"$ROOT/setup/run_checksec.sh" "$ROOTFS" "$CS" "$OUT/raw/checksec.jsonl"

echo '[4/7] Normalize evidence'
"$ROOT/setup/normalize_evidence.sh" "$ROOTFS" "$OUT/raw/firmwalker.tsv" "$OUT/raw/checksec.jsonl" "$OUT/raw/evidence.jsonl"

echo '[5/7] Build asset context'
"$ROOT/setup/build_asset_context.sh" "$ROOTFS" "$OUT/raw/evidence.jsonl" "$OUT/raw/assets.jsonl"

echo '[6/7] Correlate security cases + render report'
"$ROOT/setup/correlate_cases.sh" "$ROOTFS" "$OUT/raw/evidence.jsonl" "$OUT/raw/assets.jsonl" "$OUT/raw/correlated.json"
"$ROOT/setup/render_report.sh" "$ROOTFS" "$OUT/raw/correlated.json" "$OUT/raw/evidence.jsonl" "$OUT/raw/assets.jsonl" "$OUT"

echo '[7/7] Done'
echo "Report: $OUT/report.html"
echo "JSON:   $OUT/report.json"
echo '[+] Temporary extracted/raw analysis data removed.'
