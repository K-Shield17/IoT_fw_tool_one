#!/usr/bin/env bash
set -euo pipefail
BASE="$1"
best=""; bestscore=-1
while IFS= read -r -d '' d; do
  score=0
  [[ -d "$d/etc" ]] && ((score+=3)) || true
  [[ -d "$d/bin" ]] && ((score+=2)) || true
  [[ -d "$d/sbin" ]] && ((score+=1)) || true
  [[ -d "$d/usr" ]] && ((score+=1)) || true
  [[ -f "$d/etc/passwd" ]] && ((score+=5)) || true
  if (( score > bestscore )); then best="$d"; bestscore=$score; fi
done < <(find "$BASE" -type d -print0 2>/dev/null)
[[ $bestscore -ge 5 ]] || exit 1
printf '%s\n' "$best"
