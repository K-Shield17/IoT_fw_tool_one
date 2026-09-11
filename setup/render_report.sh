#!/usr/bin/env bash
set -euo pipefail
ROOTFS="$1"; CORRELATED="$2"; EVIDENCE="$3"; ASSETS="$4"; OUTDIR="$5"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$SCRIPT_DIR/render_report.py" "$ROOTFS" "$CORRELATED" "$EVIDENCE" "$ASSETS" "$OUTDIR"
