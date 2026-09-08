#!/usr/bin/env bash
set -euo pipefail
ROOTFS="$1"; FW_TSV="$2"; CS_JSONL="$3"; OUTDIR="$4"
mkdir -p "$OUTDIR/raw"
"$(dirname "$0")/normalize_evidence.sh" "$ROOTFS" "$FW_TSV" "$CS_JSONL" "$OUTDIR/raw/evidence.jsonl"
"$(dirname "$0")/build_asset_context.sh" "$ROOTFS" "$OUTDIR/raw/evidence.jsonl" "$OUTDIR/raw/assets.jsonl"
"$(dirname "$0")/correlate_cases.sh" "$ROOTFS" "$OUTDIR/raw/evidence.jsonl" "$OUTDIR/raw/assets.jsonl" "$OUTDIR/raw/correlated.json"
"$(dirname "$0")/render_report.sh" "$ROOTFS" "$OUTDIR/raw/correlated.json" "$OUTDIR/raw/evidence.jsonl" "$OUTDIR/raw/assets.jsonl" "$OUTDIR"
