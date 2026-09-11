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

if [[ "$(uname -s)" != "Linux" ]]; then
  die "Automatic dependency setup currently supports Linux only."
fi

APT_PKGS=(
  ca-certificates curl git build-essential pkg-config
  jq file binutils coreutils findutils grep sed gawk
  tar p7zip-full zstd squashfs-tools sleuthkit
  python3 python3-venv python3-pip
  zlib1g-dev liblzma-dev liblzo2-dev
)

apt_install_missing() {
  has apt-get || return 1
  local missing=() p
  for p in "${APT_PKGS[@]}"; do
    dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p")
  done
  if ((${#missing[@]})); then
    log "Installing missing Ubuntu packages: ${missing[*]}"
    sudo apt-get update
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
  else
    log "Ubuntu packages already present."
  fi
}

if has apt-get; then
  apt_install_missing
else
  warn "apt-get not found. Automatic OS package installation skipped."
fi

# Rust/Cargo: rustup installs both. Avoid replacing an existing toolchain.
if ! has cargo || ! has rustc; then
  log "Rust/Cargo not found. Installing rustup toolchain..."
  has curl || die "curl is required to install Rust."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
  # shellcheck disable=SC1090
  [[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"
fi
has cargo || die "cargo is still unavailable after setup."
has rustc || die "rustc is still unavailable after setup."

# Go: only required for checksec-lite. Ubuntu package first; Go may auto-download
# the newer toolchain declared by go.mod when GOTOOLCHAIN=auto.
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

# Python is NOT used by IoT_fw_tool itself. It is used only to provide upstream
# extraction utilities required by selected Binwalk extractors (Jefferson,
# ubi-reader, vmlinux-to-elf).
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
      if ! "$VENV/bin/python" -m pip install --disable-pip-version-check -q "$pkg"; then
        warn "Could not install optional extractor '$pkg'. Firmware needing '$exe' may not extract."
        return 0
      fi
    fi
  }
  install_py_tool jefferson jefferson
  install_py_tool ubireader_extract_files ubi-reader
  install_py_tool ubireader_extract_images ubi-reader
  #innstall_py_tool vmlinux-to-elf vmlinux-to-elf
 

  # Expose virtualenv utilities without modifying the user's global environment.
  for exe in jefferson ubireader_extract_files ubireader_extract_images vmlinux-to-elf; do
    if [[ -x "$VENV/bin/$exe" ]]; then ln -sf "$VENV/bin/$exe" "$LOCAL_BIN/$exe"; fi
  done

  # Binwalk 3.1 uses 'sasquatch'. Modern distro packages usually provide
  # 'unsquashfs' instead. A project-local compatibility wrapper is installed so
  # standard SquashFS images work without compiling the old sasquatch fork.
  if ! has sasquatch && [[ ! -x "$LOCAL_BIN/sasquatch" ]]; then
    has unsquashfs || die "Neither sasquatch nor unsquashfs is available."
    log "Installing project-local sasquatch compatibility wrapper using unsquashfs."
    cat > "$LOCAL_BIN/sasquatch" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
src="${@: -1}"
# Binwalk executes the extractor inside a dedicated output directory.
# sasquatch defaults to squashfs-root; mirror that behavior with unsquashfs.
rm -rf squashfs-root 2>/dev/null || true
exec unsquashfs -f -d squashfs-root "$src"
SH
    chmod +x "$LOCAL_BIN/sasquatch"
  fi
  if ! has sasquatch-v4be && [[ ! -x "$LOCAL_BIN/sasquatch-v4be" ]]; then
    ln -sf "$LOCAL_BIN/sasquatch" "$LOCAL_BIN/sasquatch-v4be"
  fi

  # YAFFS extractor is uncommon and is not consistently packaged across Ubuntu
  # versions. Install it when the distro provides it; otherwise report it as an
  # optional capability instead of aborting all analysis.
  if ! has unyaffs && [[ ! -x "$LOCAL_BIN/unyaffs" ]] && has apt-cache && apt-cache show unyaffs >/dev/null 2>&1; then
    log "Installing optional YAFFS extractor (unyaffs)..."
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y unyaffs || true
  fi
fi

# Verify commands that are expected to be supplied by OS packages.
REQUIRED=(jq file readelf nm strings grep find sed awk tar 7z zstd tsk_recover)
MISSING=()
for c in "${REQUIRED[@]}"; do has "$c" || MISSING+=("$c"); done
if ((${#MISSING[@]})); then
  die "Required commands still missing: ${MISSING[*]}"
fi

log "Dependency setup complete."
log "Rust: $(rustc --version 2>/dev/null || true)"
log "Cargo: $(cargo --version 2>/dev/null || true)"
log "Go: $(go version 2>/dev/null || true)"
