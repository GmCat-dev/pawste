#!/usr/bin/env bash
# pawste: share a file or command output on Pawste (https://paw.gmcat.io) and print the short link.
# Short links aren't encrypted: don't send secrets this way (use https://paw.gmcat.io/secure-note/).
# Usage: pawste [-t 10m|1h|1d|1w|1m|6m|1y] [-b] [-T title] [-l language] [-f] [file]
#   -b burn after reading   -f share even if Leak Guard objects   (no file: reads standard input)
set -euo pipefail
ttl=1w burn=0 title="" lang="" force=0
while getopts "t:bT:l:fh" o; do
  case $o in
    t) ttl=$OPTARG ;; b) burn=1 ;; T) title=$OPTARG ;; l) lang=$OPTARG ;; f) force=1 ;;
    *) sed -n '2,6p' "$0"; exit 0 ;;
  esac
done
shift $((OPTIND - 1))
src=${1:--}
[ "$src" = - ] || [ -f "$src" ] || { echo "pawste: no such file: $src" >&2; exit 1; }
[ -n "$title" ] || { [ "$src" = - ] || title=$(basename -- "$src"); }
enc() { local LC_ALL=C s=$1 out="" c i; for ((i = 0; i < ${#s}; i++)); do c=${s:i:1}
  case $c in [a-zA-Z0-9.~_-]) out+=$c ;; *) out+=$(printf '%%%02X' "'$c") ;; esac; done; printf %s "$out"; }
headers=$(mktemp)
trap 'rm -f "$headers"' EXIT
base=${PAWSTE_URL:-https://paw.gmcat.io}
url="$base/?ttl=$(enc "$ttl")&burn=$burn&force=$force&title=$(enc "$title")&lang=$(enc "$lang")"
link=$(curl -sS -D "$headers" --data-binary "@$src" -H "Content-Type: text/plain; charset=utf-8" "$url")
case $(head -1 "$headers") in
  *" 201"*) echo "$link"; edit=$(grep -i '^x-pawste-edit:' "$headers" | cut -d' ' -f2- | tr -d '\r'); [ -z "$edit" ] || echo "edit/delete (keep private): $edit" >&2 ;;
  *) echo "pawste: $link" >&2; exit 1 ;;
esac
