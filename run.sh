#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
usage(){ echo "Usage: $0 scan <firmware> [-o output] | analyze-rootfs <rootfs> [-o output]"; exit 1; }
[[ $# -ge 2 ]] || usage
MODE="$1"; INPUT="$2"; shift 2; OUT="results"
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--output) [[ $# -ge 2 ]] || usage; OUT="$2"; shift 2;;
    *) usage;;
  esac
done
[[ "$MODE" == "scan" || "$MODE" == "analyze-rootfs" ]] || usage

# Resolve input before changing/creating anything. This fixes relative-path and
# Binwalk symlink surprises.
[[ -e "$INPUT" ]] || { echo "[!] Input not found: $INPUT" >&2; exit 1; }
INPUT="$(readlink -f "$INPUT")"
OUT="$(readlink -m "$OUT")"

# Preflight installs/configures what is missing. Existing tools are left alone.
"$ROOT/scripts/bootstrap.sh" "$MODE"
# shellcheck disable=SC1090
[[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"
export PATH="$ROOT/tools/bin:$ROOT/.deps/venv/bin:$PATH"
export GOTOOLCHAIN=auto

BW="$ROOT/tools/binwalk-lite/target/release/binwalk"
CS="$ROOT/tools/checksec-lite/checksec-lite"

# Auto-build if this is a fresh checkout or either binary is absent.
if [[ ! -x "$BW" || ! -x "$CS" ]]; then
  echo '[*] Analyzer binaries are missing; building automatically.'
  "$ROOT/build.sh"
fi

# Prevent stale Binwalk symlink/extraction collisions from previous runs.
# Only remove files owned by this tool under the chosen output directory.
case "$OUT" in
  /|"$HOME"|"$(readlink -f "$ROOT")") echo "[!] Unsafe output directory: $OUT" >&2; exit 1;;
esac
mkdir -p "$OUT"
rm -rf "$OUT/extracted" "$OUT/raw" "$OUT/report.json" "$OUT/report.html"
mkdir -p "$OUT/raw"

ROOTFS=""
if [[ "$MODE" == "scan" ]]; then
  mkdir -p "$OUT/extracted"
  echo '[1/7] Binwalk scan + extraction + recursive extraction'
  # Keep Binwalk stderr separately so an optional extractor failure does not hide
  # the successful signatures/extractions that preceded it.
  if ! "$BW" "$INPUT" "$OUT/extracted" > "$OUT/raw/binwalk.jsonl" 2> >(tee "$OUT/raw/binwalk.stderr" >&2); then
    echo '[!] Binwalk returned a non-zero status. Trying to continue with any extracted filesystem.' >&2
  fi
  ROOTFS="$($ROOT/scripts/find_rootfs.sh "$OUT/extracted" 2>/dev/null || true)"
  if [[ -z "$ROOTFS" ]]; then
    echo '[!] RootFS not found after extraction.' >&2
    echo "    Check: $OUT/raw/binwalk.stderr" >&2
    echo "    Extracted files: $OUT/extracted" >&2
    exit 1
  fi
else
  [[ -d "$INPUT" ]] || { echo "[!] RootFS path is not a directory: $INPUT" >&2; exit 1; }
  ROOTFS="$INPUT"
fi

printf '%s\n' "$ROOTFS" > "$OUT/raw/rootfs.txt"
echo "[+] RootFS: $ROOTFS"

echo '[2/7] Firmwalker selected static checks'
"$ROOT/tools/firmwalker-lite/firmwalker-lite.sh" "$ROOTFS" "$OUT/raw/firmwalker.txt" "$OUT/raw/firmwalker.tsv"

echo '[3/7] Checksec selected ELF checks'
"$ROOT/scripts/run_checksec.sh" "$ROOTFS" "$CS" "$OUT/raw/checksec.jsonl"

echo '[4/7] Normalize raw evidence'
"$ROOT/scripts/normalize_evidence.sh" "$ROOTFS" "$OUT/raw/firmwalker.tsv" "$OUT/raw/checksec.jsonl" "$OUT/raw/evidence.jsonl"

echo '[5/7] Build asset context'
"$ROOT/scripts/build_asset_context.sh" "$ROOTFS" "$OUT/raw/evidence.jsonl" "$OUT/raw/assets.jsonl"

echo '[6/7] Correlate security cases + render analyst report'
"$ROOT/scripts/correlate_cases.sh" "$ROOTFS" "$OUT/raw/evidence.jsonl" "$OUT/raw/assets.jsonl" "$OUT/raw/correlated.json"
"$ROOT/scripts/render_report.sh" "$ROOTFS" "$OUT/raw/correlated.json" "$OUT/raw/evidence.jsonl" "$OUT/raw/assets.jsonl" "$OUT"

echo '[7/7] Done'
echo "Report: $OUT/report.html"
