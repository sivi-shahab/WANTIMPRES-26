#!/bin/sh
# Ticket 21: the §13.1 timings the repo's tests already measure (policy publish → PEP p99, kill switch), run on an
# idle host with a throwaway Postgres. Output: results/propagation-killswitch.txt.
set -eu
cd "$(dirname "$0")"
root=$(cd ../.. && pwd)
docker network create t21-tt >/dev/null
docker run -d --rm --name t21-tt-pg --network t21-tt -e POSTGRES_PASSWORD=test postgres:17 >/dev/null
trap 'docker rm -f t21-tt-pg >/dev/null; docker network rm t21-tt >/dev/null' EXIT
until docker exec t21-tt-pg pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
sleep 3
docker run --rm --network t21-tt -v "$root":/src -v riskcal-gomod:/go/pkg/mod -v riskcal-gocache:/root/.cache/go-build -w /src \
  -e AUDIT_TEST_DATABASE_URL=postgres://postgres:test@t21-tt-pg:5432/postgres golang:1.26 sh -c '
  go test -count=1 -v -run "TestPropagation" ./internal/lifecycle
  go test -count=1 -v -run "TestKillSwitchPropagation" ./internal/agents
  go test -count=1 -v -run "TestKillSwitch\$" ./internal/mcpgw' 2>&1 |
  grep -E 'publish→PEP|kill → OPA|session cut|^(ok|FAIL|--- )' | tee results/propagation-killswitch.txt
