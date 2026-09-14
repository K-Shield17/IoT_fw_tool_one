#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-scan}"
DEPS="$ROOT/.deps"
VENV="$DEPS/venv"
LOCAL_BIN="$ROOT/tools/bin"
mkdir -p "$DEPS" "$LOCAL_BIN"

log(){ printf '[setup] %s\n' "$*"; }
warn(){ printf '[setup][WARN] %s\n' "$*" >&2; }
die(){ printf '[setup][ERROR] %s\n' "$*" >&2; exit 1; }
has(){ command -v "$1" >/dev/null 2>&1; }

[[ "$(uname -s)" == "Linux" ]] || die "Automatic dependency setup currently supports Linux only."

APT_PKGS=(
  ca-certificates curl wget git patch build-essential pkg-config
  jq file binutils coreutils findutils grep sed gawk
  tar p7zip-full zstd squashfs-tools sleuthkit
  python3 python3-venv python3-pip
  zlib1g-dev liblzma-dev liblzo2-dev
)

apt_install_missing() {
  has apt-get || return 1
  local missing=() p
  for p in "${APT_PKGS[@]}"; do dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p"); done
  if ((${#missing[@]})); then
    log "Installing missing Ubuntu packages: ${missing[*]}"
    sudo apt-get update
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
  else
    log "Ubuntu packages already present."
  fi
}

if has apt-get; then apt_install_missing; else warn "apt-get not found. Automatic OS package installation skipped."; fi

if ! has cargo || ! has rustc; then
  log "Rust/Cargo not found. Installing rustup toolchain..."
  has curl || die "curl is required to install Rust."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
  [[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"
fi
has cargo || die "cargo is still unavailable after setup."
has rustc || die "rustc is still unavailable after setup."

if ! has go; then
  if has apt-get; then
    log "Go not found. Installing golang-go..."
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y golang-go
  else
    die "Go is required and could not be installed automatically."
  fi
fi
has go || die "go is still unavailable after setup."
export GOTOOLCHAIN=auto

if [[ "$MODE" == "scan" ]]; then
  if [[ ! -x "$VENV/bin/python" ]]; then
    log "Creating isolated extractor virtualenv..."
    python3 -m venv "$VENV"
  fi

  "$VENV/bin/python" -m pip install --disable-pip-version-check -q --upgrade pip setuptools wheel

  install_py_tool() {
    local exe="$1" pkg="$2"
    if [[ ! -x "$VENV/bin/$exe" ]] && ! has "$exe"; then
      log "Installing extractor utility: $pkg ($exe)"
      "$VENV/bin/python" -m pip install --disable-pip-version-check -q "$pkg" || {
        warn "Could not install optional extractor '$pkg'."
        return 0
      }
    fi
  }

  install_py_tool jefferson jefferson
  install_py_tool ubireader_extract_files ubi-reader
  install_py_tool ubireader_extract_images ubi-reader
  install_py_tool vmlinux-to-elf vmlinux-to-elf

  for exe in jefferson ubireader_extract_files ubireader_extract_images vmlinux-to-elf; do
    [[ -x "$VENV/bin/$exe" ]] && ln -sf "$VENV/bin/$exe" "$LOCAL_BIN/$exe"
  done

  # Real sasquatch first, unsquashfs fallback
  if ! has sasquatch && [[ ! -x "$LOCAL_BIN/sasquatch" ]]; then
    SASQUATCH_DIR="$DEPS/sasquatch"
    log "Installing sasquatch..."

    if [[ ! -d "$SASQUATCH_DIR/.git" ]]; then
      rm -rf "$SASQUATCH_DIR"
      git clone --depth 1 https://github.com/devttys0/sasquatch.git "$SASQUATCH_DIR" || true
    fi

    if [[ -x "$SASQUATCH_DIR/build.sh" ]] && (cd "$SASQUATCH_DIR" && ./build.sh); then
      hash -r 2>/dev/null || true
      if has sasquatch; then
        ln -sf "$(command -v sasquatch)" "$LOCAL_BIN/sasquatch"
      fi
    fi

    if [[ ! -x "$LOCAL_BIN/sasquatch" ]]; then
      has unsquashfs || die "Neither sasquatch nor unsquashfs is available."
      warn "sasquatch unavailable; using unsquashfs fallback."
      cat > "$LOCAL_BIN/sasquatch" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
src="${@: -1}"
rm -rf squashfs-root 2>/dev/null || true
exec unsquashfs -f -d squashfs-root "$src"
SH
      chmod +x "$LOCAL_BIN/sasquatch"
    fi
  fi

  [[ -x "$LOCAL_BIN/sasquatch-v4be" ]] || ln -sf "$LOCAL_BIN/sasquatch" "$LOCAL_BIN/sasquatch-v4be"

  if ! has unyaffs && [[ ! -x "$LOCAL_BIN/unyaffs" ]] && has apt-cache && apt-cache show unyaffs >/dev/null 2>&1; then
    log "Installing optional YAFFS extractor..."
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y unyaffs || true
  fi
fi

REQUIRED=(jq file readelf nm strings grep find sed awk tar 7z zstd tsk_recover)
MISSING=()
for c in "${REQUIRED[@]}"; do has "$c" || MISSING+=("$c"); done
((${#MISSING[@]})) && die "Required commands still missing: ${MISSING[*]}"

log "Dependency setup complete."
log "Rust: $(rustc --version 2>/dev/null || true)"
log "Cargo: $(cargo --version 2>/dev/null || true)"
log "Go: $(go version 2>/dev/null || true)"
