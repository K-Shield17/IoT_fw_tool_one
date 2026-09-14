#!/usr/bin/env bash
set -euo pipefail

BASE="$1"

best=""
bestscore=-1

while IFS= read -r -d '' d; do
  score=0

  # --------------------------------------------------
  # Basic Linux root filesystem structure
  # --------------------------------------------------
  [[ -d "$d/etc"  ]] && ((score+=3)) || true
  [[ -d "$d/bin"  ]] && ((score+=2)) || true
  [[ -d "$d/sbin" ]] && ((score+=2)) || true
  [[ -d "$d/usr"  ]] && ((score+=1)) || true
  [[ -d "$d/lib"  || -d "$d/lib64" ]] && ((score+=1)) || true
  [[ -d "$d/var"  ]] && ((score+=1)) || true

  # --------------------------------------------------
  # Strong RootFS indicators
  # --------------------------------------------------
  [[ -f "$d/etc/passwd" ]] && ((score+=5)) || true
  [[ -f "$d/etc/shadow" ]] && ((score+=2)) || true
  [[ -f "$d/etc/inittab" ]] && ((score+=3)) || true

  [[ -f "$d/init" ]] && ((score+=3)) || true
  [[ -f "$d/sbin/init" ]] && ((score+=3)) || true

  # BusyBox is very common in embedded Linux firmware.
  if [[ -e "$d/bin/busybox" || -e "$d/sbin/busybox" || -e "$d/usr/bin/busybox" ]]; then
    ((score+=4))
  fi

  # --------------------------------------------------
  # Common extraction directory names
  # Bonus only — directory name alone is not enough.
  # --------------------------------------------------
  base_name="$(basename "$d")"

  case "$base_name" in
    squashfs-root|ubifs-root|rootfs|romfs-root|cramfs-root)
      ((score+=2))
      ;;
  esac

  # --------------------------------------------------
  # Keep best candidate
  # --------------------------------------------------
  if (( score > bestscore )); then
    best="$d"
    bestscore=$score
  fi

done < <(find "$BASE" -type d -print0 2>/dev/null)

# --------------------------------------------------
# Validate candidate
# --------------------------------------------------
if [[ -z "$best" || $bestscore -lt 5 ]]; then
  echo "[!] RootFS candidate not found." >&2
  echo "    search base : $BASE" >&2
  echo "    best score  : $bestscore" >&2

  if [[ -n "$best" ]]; then
    echo "    best path   : $best" >&2
  fi

  exit 1
fi

printf '%s\n' "$best"
