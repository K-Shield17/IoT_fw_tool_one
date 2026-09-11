#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOL_VERSION="${TOOL_VERSION:-v1.0}"

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

# ---------------------------------------------------------------------------
# 배너 / 진행 표시
# ---------------------------------------------------------------------------
# =========================================================================
# 배너 / 진행 표시
# =========================================================================
# ---------------------------------------------------------------------------
# 배너 / 완료 요약
#   NO_COLOR=1      색 해제
#   ASCII_ONLY=1    박스/아트를 ASCII 로 대체
#   QUIET_BANNER=1  배너 생략
# ---------------------------------------------------------------------------
BANNER_W=56   # 상자 안쪽 폭

_b_short() {
  local s="$1" max="$2"
  s="${s/#$HOME/~}"
  if (( ${#s} > max )); then printf '...%s' "${s: -$((max - 3))}"; else printf '%s' "$s"; fi
}

_b_style() {   # 색/박스 문자 설정 (banner 와 summary 가 공유)
  C1=''; C2=''; C3=''; C4=''; CH=''; EY=''; DD=''; DIM=''; G=''; Y=''; M=''; RD=''; B=''; R=''
  if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C1=$'\033[38;5;51m'; C2=$'\033[38;5;45m'; C3=$'\033[38;5;39m'; C4=$'\033[38;5;33m'
    CH=$'\033[38;5;110m'; EY=$'\033[38;5;215m'
    DD=$'\033[38;5;238m'; DIM=$'\033[38;5;245m'
    G=$'\033[38;5;114m'; Y=$'\033[38;5;179m'; M=$'\033[38;5;141m'; RD=$'\033[38;5;203m'
    B=$'\033[1m'; R=$'\033[0m'
  fi
  B_ASCII=0
  [[ "${ASCII_ONLY:-0}" == "1" || -z "${LANG:-}${LC_ALL:-}" ]] && B_ASCII=1
  if (( B_ASCII )); then
    TL='+'; TR='+'; BL='+'; BR='+'; HZ='-'; VT='|'; LT='+'; RT='+'; DIA='*'
  else
    TL='╭'; TR='╮'; BL='╰'; BR='╯'; HZ='─'; VT='│'; LT='├'; RT='┤'; DIA='◆'
  fi
  # tr 은 멀티바이트 치환에서 바이트 단위로 동작해 UTF-8 을 깨뜨린다.
  BAR=''; local _i
  for ((_i = 0; _i < BANNER_W; _i++)); do BAR+="$HZ"; done
}

_b_row()  { printf '  %s%s%s %-*s %s%s%s\n' "$DD" "$VT" "$R" $((BANNER_W - 2)) "$1" "$DD" "$VT" "$R"; }
_b_kv()   { printf '  %s%s%s %s%-8s%s %s%-*s%s %s%s%s\n' \
              "$DD" "$VT" "$R" "$Y" "$1" "$R" "$G" $((BANNER_W - 11)) "$2" "$R" "$DD" "$VT" "$R"; }
_b_step() { printf '  %s%s%s %s%s%s %-16s %s%-*s%s %s%s%s\n' \
              "$DD" "$VT" "$R" "$C2" "$DIA" "$R" "$1" "$DIM" $((BANNER_W - 21)) "$2" "$R" "$DD" "$VT" "$R"; }
_b_line() { printf '  %s%s%s%s%s\n' "$DD" "$1" "$BAR" "$2" "$R"; }

banner() {
  [[ "${QUIET_BANNER:-0}" == "1" ]] && return 0
  _b_style
  echo
  if (( B_ASCII )); then
    local -a _la=(
      '  ___     _____   _____      __'
      ' |_ _|___ |_   _| |  ___\ \    / /'
      '  | |/ _ \  | |   | |_   \ \/\/ /'
      '  | | (_) | | |   |  _|   \    /'
      ' |___\___/  |_|   |_|      \/\/'
    )
    local -a _ca=(
      '+-------------+'
      '|7F454C46|.ELF|'
      '|02010100|....|'
      '|######.....  |'
      '+-------------+'
    )
    local -a _cc=("$C1" "$C2" "$C3" "$C3" "$C4")
    local _i
    for _i in 0 1 2 3 4; do
      printf '  %s%-41s%s  %s%s%s\n' "${_cc[$_i]}" "${_la[$_i]}" "$R" "$DD" "${_ca[$_i]}" "$R"
    done
  else
    printf '  %s██╗ ██████╗ ████████╗  ███████╗██╗    ██╗%s  %s┌─────────────┐%s\n'         "$C1" "$R" "$DD" "$R"
    printf '  %s██║██╔═══██╗╚══██╔══╝  ██╔════╝██║    ██║%s  %s│%s7F454C46%s│%s.ELF%s│%s\n' "$C2" "$R" "$DD" "$EY" "$DD" "$G" "$DD" "$R"
    printf '  %s██║██║   ██║   ██║     █████╗  ██║ █╗ ██║%s  %s│%s02010100%s│%s....%s│%s\n' "$C3" "$R" "$DD" "$EY" "$DD" "$DIM" "$DD" "$R"
    printf '  %s██║██║   ██║   ██║     ██╔══╝  ██║███╗██║%s  %s│%s▰▰▰▰▰▰%s▱▱▱▱▱%s  │%s\n'  "$C3" "$R" "$DD" "$CH" "$DIM" "$DD" "$R"
    printf '  %s██║╚██████╔╝   ██║     ██║     ╚███╔███╔╝%s  %s└─────────────┘%s\n'         "$C4" "$R" "$DD" "$R"
    printf '  %s╚═╝ ╚═════╝    ╚═╝     ╚═╝      ╚══╝╚══╝ %s   %sanalyzing...%s  \n'         "$C4" "$R" "$DIM" "$R"
  fi
  printf '  %s%sA N A L Y S T   R E P O R T%s   %sIoT firmware static analysis%s\n' "$B" "$M" "$R" "$DIM" "$R"
  echo
  _b_line "$TL" "$TR"
  _b_step "binwalk-lite"     "extract"
  _b_step "firmwalker-lite"  "scan"
  _b_step "checksec-lite"    "harden"
  _b_line "$LT" "$RT"
  _b_kv "version" "${TOOL_VERSION:-v1.0}"
  _b_kv "mode"    "$MODE"
  _b_kv "target"  "$(_b_short "$INPUT" $((BANNER_W - 11)))"
  _b_kv "output"  "$(_b_short "$OUT"   $((BANNER_W - 11)))"
  _b_line "$BL" "$BR"
  echo
}

# summary <출력디렉터리>
#   render_report.sh 가 report.json 의 .summary 에 집계를 미리 계산해 둔다.
#   그 값을 우선 사용하고, 없으면 security_cases 배열에서 직접 센다.
#   읽지 못하면 0 을 조용히 보여주지 않고 이유를 표시한다.
summary() {
  local out="$1"
  local json="$out/report.json"
  local hi=0 md=0 lo=0 cr=0 tot=0 sysn=0 assets=0 ev=0 risk='-' note='' vals=''
  _b_style

  if [[ ! -r "$json" ]]; then
    note="report.json not found"
  elif ! command -v jq >/dev/null 2>&1; then
    note="jq not available"
  else
    vals="$(jq -r '
      (.summary // {}) as $s |
      ((.findings // .security_cases) // []) as $c |
      def cnt($sev): [$c[]? | select((.severity // "") == $sev)] | length;
      [ ($s.critical // $s.critical_cases // cnt("CRITICAL")),
        ($s.high     // $s.high_cases     // cnt("HIGH")),
        ($s.medium   // $s.medium_cases   // cnt("MEDIUM")),
        ($s.low      // cnt("LOW")),
        ($s.findings // $s.security_cases // ($c|length)),
        ((.systemic_findings // [])|length),
        ($s.analyzed_elf // $s.analyzed_assets // (.metadata.asset_count // 0)),
        ($s.owasp_evidence // $s.raw_evidence // (.metadata.evidence_count // 0)),
        ($s.overall_risk // "-")
      ] | @tsv' "$json" 2>/dev/null)" || vals=''
    if [[ -n "$vals" ]]; then
      IFS=$'\t' read -r cr hi md lo tot sysn assets ev risk <<< "$vals"
    else
      note="report.json parse failed"
    fi
  fi
  : "${hi:=0}" "${md:=0}" "${lo:=0}" "${cr:=0}" "${tot:=0}" "${sysn:=0}" "${assets:=0}" "${ev:=0}" "${risk:=-}"

  local rc="$DIM"
  case "$risk" in CRITICAL|HIGH) rc="$RD" ;; MEDIUM) rc="$Y" ;; esac

  echo
  _b_line "$TL" "$TR"
  printf '  %s%s%s %s%-22s%s%s%-*s%s %s%s%s\n' "$DD" "$VT" "$R" \
    "$B" "ANALYSIS COMPLETE" "$R" "$rc" $((BANNER_W - 24)) "overall risk: $risk" "$R" "$DD" "$VT" "$R"
  _b_line "$LT" "$RT"
  printf '  %s%s%s %s%-9s%s%s%4d%s  %s%-7s%s%s%4d%s  %s%-4s%s%s%4d%s%*s %s%s%s\n' \
    "$DD" "$VT" "$R" \
    "$RD"  "CRITICAL" "$R" "$RD"  "$cr" "$R" \
    "$RD"  "HIGH"     "$R" "$RD"  "$hi" "$R" \
    "$Y"   "MED"      "$R" "$Y"   "$md" "$R" \
    18 "" "$DD" "$VT" "$R"
  _b_row "$(printf 'findings %-4d systemic %-3d ELF %-6d owasp %d' "$tot" "$sysn" "$assets" "$ev")"
  [[ -n "$note" ]] && printf '  %s%s%s %s%-*s%s %s%s%s\n' \
    "$DD" "$VT" "$R" "$RD" $((BANNER_W - 2)) "! $note" "$R" "$DD" "$VT" "$R"
  _b_line "$BL" "$BR"
  echo
  printf '  %sreport%s  %s%s/report.html%s\n' "$Y" "$R" "$G" "$out" "$R"
  printf '  %sjson%s    %s%s/report.json%s\n' "$Y" "$R" "$G" "$out" "$R"
  [[ "${KEEP_RAW:-0}" == "1" ]] && printf '  %sraw%s     %s%s/raw%s %s(KEEP_RAW=1)%s\n' "$Y" "$R" "$G" "$out" "$R" "$DIM" "$R"
  echo
}

# ---------------------------------------------------------------------------
# 파이프라인 진행 표시
#   step_begin <번호> <전체> <제목>   단계 시작
#   step_end   [상태]                 단계 종료 (ok | skip | fail, 기본 ok)
#
#   - 터미널이면 같은 줄을 덮어써 스피너와 경과 시간을 갱신
#   - 파이프/리다이렉트/CI 면 한 줄씩만 남겨 로그를 더럽히지 않음
#   - NO_COLOR=1 / ASCII_ONLY=1 / QUIET_BANNER=1 존중
# ---------------------------------------------------------------------------
PROG_W=24          # 진행 바 칸 수
_PROG_PID=""       # 스피너 백그라운드 PID
_PROG_T0=0         # 단계 시작 시각
_PROG_CUR=0
_PROG_TOTAL=7
_PROG_TITLE=""

_prog_tty() { [[ -t 1 && "${QUIET_BANNER:-0}" != "1" ]]; }

_prog_colors() {
  if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    P_ON=$'\033[38;5;45m'; P_OFF=$'\033[38;5;238m'; P_DIM=$'\033[38;5;245m'
    P_OK=$'\033[38;5;114m'; P_WARN=$'\033[38;5;179m'; P_ERR=$'\033[38;5;203m'
    P_R=$'\033[0m'
  else
    P_ON=''; P_OFF=''; P_DIM=''; P_OK=''; P_WARN=''; P_ERR=''; P_R=''
  fi
  if [[ "${ASCII_ONLY:-0}" == "1" || -z "${LANG:-}${LC_ALL:-}" ]]; then
    P_FULL='#'; P_EMPTY='.'; P_TICK='[ok]'; P_SKIP='[--]'; P_CROSS='[!!]'
    P_SPIN=('-' '\' '|' '/')
  else
    P_FULL='▰'; P_EMPTY='▱'; P_TICK='✔'; P_SKIP='–'; P_CROSS='✘'
    P_SPIN=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
  fi
}
_prog_colors

# 진행 바 문자열 생성: <완료칸수>
_prog_bar() {
  local done="$1" i on='' off=''
  for ((i = 0; i < done; i++));        do on+="$P_FULL";  done
  for ((i = done; i < PROG_W; i++));   do off+="$P_EMPTY"; done
  printf '%s%s%s%s%s' "$P_ON" "$on" "$P_OFF" "$off" "$P_R"
}

# 경과 시간 mm:ss
_prog_elapsed() {
  local s=$(( $(date +%s) - _PROG_T0 ))
  printf '%02d:%02d' $((s / 60)) $((s % 60))
}

# 스피너 루프 (백그라운드)
_prog_spin() {
  local i=0 n=${#P_SPIN[@]}
  while :; do
    printf '\r  %s%s%s  %s  %s%-28s%s %s%s%s' \
      "$P_ON" "${P_SPIN[$((i % n))]}" "$P_R" \
      "$(_prog_bar "$1")" \
      "$P_DIM" "$_PROG_TITLE" "$P_R" \
      "$P_DIM" "$(_prog_elapsed)" "$P_R"
    i=$((i + 1))
    sleep 0.12
  done
}

step_begin() {
  _PROG_CUR="$1"; _PROG_TOTAL="$2"; _PROG_TITLE="$3"
  _PROG_T0=$(date +%s)
  local filled=$(( (_PROG_CUR - 1) * PROG_W / _PROG_TOTAL ))

  if _prog_tty; then
    _prog_spin "$filled" &
    _PROG_PID=$!
    disown "$_PROG_PID" 2>/dev/null || true
  else
    printf '[%d/%d] %s\n' "$_PROG_CUR" "$_PROG_TOTAL" "$_PROG_TITLE"
  fi
}

step_end() {
  local status="${1:-ok}" mark color
  case "$status" in
    ok)   mark="$P_TICK";  color="$P_OK"   ;;
    skip) mark="$P_SKIP";  color="$P_WARN" ;;
    *)    mark="$P_CROSS"; color="$P_ERR"  ;;
  esac

  if [[ -n "$_PROG_PID" ]]; then
    kill "$_PROG_PID" 2>/dev/null || true
    wait "$_PROG_PID" 2>/dev/null || true
    _PROG_PID=""
  fi

  local filled=$(( _PROG_CUR * PROG_W / _PROG_TOTAL ))
  if _prog_tty; then
    printf '\r\033[K  %s%s%s  %s  %s%-28s%s %s%s%s\n' \
      "$color" "$mark" "$P_R" \
      "$(_prog_bar "$filled")" \
      "$P_DIM" "$_PROG_TITLE" "$P_R" \
      "$P_DIM" "$(_prog_elapsed)" "$P_R"
  fi
}

# 중간에 끊겨도 스피너가 남지 않도록
_prog_cleanup() {
  [[ -n "$_PROG_PID" ]] && { kill "$_PROG_PID" 2>/dev/null || true; }
  _prog_tty && printf '\r\033[K'
}

# =========================================================================
# 파이프라인
# =========================================================================
banner

# 입력이 XZ 인데 잘려 있으면 추출이 조용히 실패한다. 미리 알려준다.
if [[ "$MODE" == "scan" ]] && command -v xz >/dev/null 2>&1; then
  case "$(file -b "$INPUT" 2>/dev/null)" in
    XZ\ compressed*)
      if ! xz -t "$INPUT" 2>/dev/null; then
        echo "  [!] 입력 파일이 손상되었거나 잘렸습니다 (xz -t 실패): $INPUT" >&2
        echo "      크기: $(stat -c '%s' "$INPUT" 2>/dev/null) bytes. 다시 내려받아 주세요." >&2
        exit 1
      fi ;;
  esac
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
echo "  [+] Result directory: $OUT"
echo

# ---------------------------------------------------------------------------
# 작업 산출물 정리
#   파이프라인이 성공했을 때만 지운다. 실패 시에는 binwalk.jsonl 과
#   binwalk.stderr 가 원인 파악의 유일한 단서이므로 보존한다.
#   KEEP_RAW=1 이면 성공해도 남긴다.
# ---------------------------------------------------------------------------
PIPELINE_OK=0
cleanup_working_data() {
  _prog_cleanup
  [[ "${KEEP_RAW:-0}" == "1" ]] && return 0
  [[ "$PIPELINE_OK" == "1" ]] || return 0
  [[ -n "${OUT:-}" && -d "$OUT" ]] || return 0
  rm -rf -- "$OUT/extracted" "$OUT/raw"
}
trap cleanup_working_data EXIT

TOTAL=7

ROOTFS=""
if [[ "$MODE" == "scan" ]]; then
  mkdir -p "$OUT/extracted"

  step_begin 1 "$TOTAL" "Binwalk scan + extraction"
  if "$BW" "$INPUT" "$OUT/extracted" > "$OUT/raw/binwalk.jsonl" 2> "$OUT/raw/binwalk.stderr"; then
    step_end ok
  else
    step_end fail
    echo "  [!] Binwalk returned a non-zero status. Continuing with whatever was extracted." >&2
  fi

  ROOTFS="$("$ROOT/setup/find_rootfs.sh" "$OUT/extracted" 2>/dev/null || true)"
  if [[ -z "$ROOTFS" ]]; then
    echo "  [!] RootFS not found after extraction." >&2
    echo "      signatures : $(wc -l < "$OUT/raw/binwalk.jsonl" 2>/dev/null || echo 0) line(s)" >&2
    echo "      extracted  : $(find "$OUT/extracted" -type f 2>/dev/null | wc -l) file(s)" >&2
    echo "      check      : $OUT/raw/binwalk.jsonl, $OUT/raw/binwalk.stderr" >&2
    exit 1
  fi
else
  [[ -d "$INPUT" ]] || { echo "[!] RootFS path is not a directory: $INPUT" >&2; exit 1; }
  ROOTFS="$INPUT"
  step_begin 1 "$TOTAL" "Using pre-extracted RootFS"
  step_end skip
fi

printf '%s\n' "$ROOTFS" > "$OUT/raw/rootfs.txt"

step_begin 2 "$TOTAL" "Firmwalker targeted scan"
"$ROOT/tools/firmwalker-lite/firmwalker-lite.sh" "$ROOTFS" "$OUT/raw/firmwalker.txt" "$OUT/raw/firmwalker.tsv"
step_end ok

step_begin 3 "$TOTAL" "Checksec ELF hardening"
"$ROOT/setup/run_checksec.sh" "$ROOTFS" "$CS" "$OUT/raw/checksec.jsonl"
step_end ok

step_begin 4 "$TOTAL" "Normalize evidence"
"$ROOT/setup/normalize_evidence.sh" "$ROOTFS" "$OUT/raw/firmwalker.tsv" "$OUT/raw/checksec.jsonl" "$OUT/raw/evidence.jsonl"
step_end ok

step_begin 5 "$TOTAL" "Build asset context"
"$ROOT/setup/build_asset_context.sh" "$ROOTFS" "$OUT/raw/evidence.jsonl" "$OUT/raw/assets.jsonl"
step_end ok

step_begin 6 "$TOTAL" "Correlate security cases"
"$ROOT/setup/correlate_cases.sh" "$ROOTFS" "$OUT/raw/evidence.jsonl" "$OUT/raw/assets.jsonl" "$OUT/raw/correlated.json"
step_end ok

step_begin 7 "$TOTAL" "Render analyst report"
"$ROOT/setup/render_report.sh" "$ROOTFS" "$OUT/raw/correlated.json" "$OUT/raw/evidence.jsonl" "$OUT/raw/assets.jsonl" "$OUT"
step_end ok

PIPELINE_OK=1
summary "$OUT" "$ROOTFS"
