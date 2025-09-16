#!/usr/bin/env bash
# Comprehensive smoke test for olsrd-status-plugin endpoints
# Override BASE to point at another host (e.g. http://127.0.0.1:11080)
BASE="${BASE:-http://193.238.158.74}"
TIMEOUT=${TIMEOUT:-6}
SNIP=${SNIP:-300}
# CI mode: pass --ci to the script or set CI_MODE=1. Define CRITICAL endpoints (comma-separated) via env var if needed.
CI_MODE=0
if [ "$1" = "--ci" ] || [ "$CI_MODE" = "1" ]; then CI_MODE=1; fi
CRITICAL=${CRITICAL:-"/status,/status/lite,/capabilities,/olsrd.json?q=links,/olsr/links"}

echo "Testing $BASE..."

# init results and failure counter
results=()
fail_count=0

check_one() {
  local path="$1"
  # use curl to fetch into a temp file, capture HTTP code and size
  tmp=$(mktemp /tmp/smoke.XXXXXX) || tmp=/tmp/smoke.tmp
  # collect http code, size and time_total
  meta=$(curl -sS --max-time "$TIMEOUT" -w "%{http_code} %{size_download} %{time_total}" -o "$tmp" "$BASE$path" 2>/dev/null) || meta="000 0 0"
  code=$(printf "%s" "$meta" | awk '{print $1}')
  size=$(printf "%s" "$meta" | awk '{print $2}')
  tim=$(printf "%s" "$meta" | awk '{print $3}')
  if [ "$code" = "200" ] && [ "$size" -gt 0 ]; then
    status="PASS"
  else
    status="FAIL"
  fi
  msg="--- $status $path (code=$code size=$size) ---"
  printf '%s\n' "$msg"
  if [ "$size" -gt 0 ]; then
    head -c "$SNIP" "$tmp" | sed -e 's/\n/\\n/g'
    echo
  fi
  # record result for JSON report
  results+=("{\"path\":\"$path\",\"status\":\"$status\",\"code\":$code,\"size\":$size,\"time\":$tim}")
  if [ "$status" = "FAIL" ]; then fail_count=$((fail_count+1)); failed_list+=("$path") ; fi
  rm -f "$tmp"
}

# endpoints to check
endpoints=(
  "/"
  "/index.html"
  "/js/app.js"
  "/js/jquery.min.js"
  "/js/bootstrap.min.js"
  "/css/custom.css"
  "/status"
  "/status/lite"
  "/capabilities"
  "/fetch_debug"
  "/connections.json"
  "/connections"
  "/versions.json"
  "/nodedb.json"
  "/airos"
  "/olsr/links"
  "/olsr/routes?via=193.238.156.86"
  "/traceroute?target=8.8.8.8"
)

olsrd_qs=("links" "neighbors" "routes" "all" "version" "interfaces" "topology" "mid" "2hop" "neighbours")

for e in "${endpoints[@]}"; do
  check_one "$e"
done

echo "--- OLSRd proxy checks ---"
for q in "${olsrd_qs[@]}"; do
  check_one "/olsrd.json?q=$q"
done

# build JSON report
report_file="smoke_report.json"
printf '{"base":"%s","timestamp":%d,"total":%d,"failures":%d,"results":[' "$BASE" "$(date +%s)" ${#results[@]} $fail_count > "$report_file"
first=1
for r in "${results[@]}"; do
  if [ $first -eq 0 ]; then printf ',' >> "$report_file"; fi
  first=0
  printf '%s' "$r" >> "$report_file"
done
printf ']}' >> "$report_file"

echo "JSON report written to $report_file"
# Human summary
echo
echo "Summary: total=${#results[@]} passed=$(( ${#results[@]} - fail_count )) failed=$fail_count"
if [ ${#failed_list[@]} -gt 0 ]; then
  echo "Failed endpoints:"; for p in "${failed_list[@]}"; do echo " - $p"; done
fi

# CI failure logic: if CI mode and any critical endpoint failed, exit non-zero
if [ $CI_MODE -eq 1 ]; then
  # build critical list
  IFS=',' read -r -a crits <<< "$CRITICAL"
  ci_fail=0
  for cf in "${crits[@]}"; do
    for f in "${failed_list[@]}"; do
      if [ "$cf" = "$f" ]; then ci_fail=1; fi
    done
  done
  if [ $ci_fail -eq 1 ]; then echo "CI: critical endpoint failed" >&2; exit 3; fi
fi

if [ $fail_count -gt 0 ]; then
  echo "Some endpoints failed: $fail_count failures" >&2
  exit 2
fi
echo "All checks passed."; exit 0
