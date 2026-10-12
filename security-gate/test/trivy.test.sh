#!/usr/bin/env bash
# Checks the pinned trivy and scan-vulns.mjs together: a lockfile with a known
# advisory must be reported as new against a clean one, and not against itself.
#
#   TRIVY=/path/to/trivy ./security-gate/test/trivy.test.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
TRIVY="${TRIVY:-trivy}"
CACHE="${TRIVY_CACHE_DIR:-${RUNNER_TEMP:-/tmp}/trivy-cache}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/vulnerable" "$tmp/clean"
cat >"$tmp/vulnerable/package-lock.json" <<'JSON'
{
  "name": "fixture",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "fixture", "dependencies": { "lodash": "4.17.15" } },
    "node_modules/lodash": { "version": "4.17.15", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz" }
  }
}
JSON
cat >"$tmp/clean/package-lock.json" <<'JSON'
{ "name": "fixture", "lockfileVersion": 3, "packages": { "": { "name": "fixture" } } }
JSON

scan() { "$TRIVY" --cache-dir "$CACHE" fs --scanners vuln --format json --output "$2" --quiet "$1"; }
scan "$tmp/clean" "$tmp/clean.json"
scan "$tmp/vulnerable" "$tmp/vulnerable.json"

fail=0
check() { # check <name> <expected exit> <base> <head>
    local got=0
    node security-gate/scan-vulns.mjs --base "$3" --head "$4" >"$tmp/out" 2>&1 || got=$?
    if [ "$got" = "$2" ]; then
        echo "ok   $1"
    else
        echo "FAIL $1: expected exit $2, got $got"; cat "$tmp/out"; fail=1
    fi
}
check "lodash 4.17.15 added against a clean base blocks" 1 "$tmp/clean.json" "$tmp/vulnerable.json"
grep -q "::error file=package-lock.json,title=new-vulnerability::lodash 4.17.15" "$tmp/out" && echo "ok   the annotation names the package" || { echo "FAIL annotation"; cat "$tmp/out"; fail=1; }
check "the same lockfile against itself passes" 0 "$tmp/vulnerable.json" "$tmp/vulnerable.json"
grep -q "already on the base branch: [1-9]" "$tmp/out" && echo "ok   the backlog is counted" || { echo "FAIL backlog"; cat "$tmp/out"; fail=1; }
check "a clean lockfile passes" 0 "$tmp/clean.json" "$tmp/clean.json"
exit $fail
