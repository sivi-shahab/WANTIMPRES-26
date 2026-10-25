#!/bin/sh
# Ticket 21: OPA decision cost as spec §13.1 asks (opa bench), on 1 vCPU like the sidecar, plus a profile of the
# most expensive expressions. The gateways ask for decision.checked (input validated in Go, ticket 47) with the
# sidecar's GOGC/GOMEMLIMIT. Needs the signed bundle from run.sh up. Output: results/opa-bench.txt.
set -eu
cd "$(dirname "$0")"
opa() { docker run --rm --cpus=1 -e GOGC=800 -e GOMEMLIMIT=200MiB -v "$PWD/.bundle":/b:ro -v "$PWD/config":/c:ro openpolicyagent/opa:1.21.1-static "$@"; }
{
  opa bench --bundle /b/wantimpres26.tar.gz --input /c/opa-input.json --count 3 'data.wantimpres26.decision.checked' |
    grep -E 'samples|ns/op|query_eval_ns_(median|90%|95%|99%|max)'
  echo "--- profile (top expressions by time)"
  opa eval --bundle /b/wantimpres26.tar.gz --input /c/opa-input.json --profile --profile-limit 10 --format pretty \
    'data.wantimpres26.decision.checked' | grep -E '^[|│] *[0-9.]+[µm]?s ' | head -10 | cut -c1-160
} | tee results/opa-bench.txt
