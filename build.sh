#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Installing/building prerequisites here makes a fresh clone usable with one command.
"$ROOT/setup/bootstrap.sh" build
# shellcheck disable=SC1090
[[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"
export PATH="$ROOT/tools/bin:$ROOT/.deps/venv/bin:$PATH"
export GOTOOLCHAIN=auto

printf '[*] Building Binwalk-lite (Rust)...\n'
(cd "$ROOT/tools/binwalk-lite" && cargo build --release)

printf '[*] Preparing Checksec-lite Go module...\n'
(cd "$ROOT/tools/checksec-lite" && go mod tidy)
printf '[*] Building Checksec-lite (Go)...\n'
(cd "$ROOT/tools/checksec-lite" && go build -o checksec-lite .)

printf '[+] Build complete.\n'
