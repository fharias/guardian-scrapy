#!/usr/bin/env bash
# CI local de Guardian: lo mismo que correrá GitHub Actions.
#   ./scripts/ci-local.sh                  formato, vet, race, fuzz corto
#   INTEGRATION=1 ./scripts/ci-local.sh    + tests con Valkey real (Docker)
#   FUZZTIME=2m ./scripts/ci-local.sh      fuzz más largo (job nocturno)
set -euo pipefail

cd "$(dirname "$0")/.."

FUZZTIME="${FUZZTIME:-20s}"

step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

step "gofmt"
unformatted="$(gofmt -l .)"
if [[ -n "$unformatted" ]]; then
	echo "Archivos sin gofmt:" >&2
	echo "$unformatted" >&2
	exit 1
fi

step "go vet"
go vet ./...
go vet -tags=integration ./...

step "go test -race -shuffle=on"
go test -race -shuffle=on -count=1 ./...

step "fuzz (${FUZZTIME} por target)"
# -fuzz acepta un solo target por paquete: un loop "Target paquete".
targets=(
	"FuzzVerify ./internal/challenge"
	"FuzzClientIP ./internal/clientip"
	"FuzzProxyProtoRead ./cmd/guardian"
)
for t in "${targets[@]}"; do
	read -r name pkg <<<"$t"
	echo "-- $name ($pkg)"
	go test -run='^$' -fuzz="^${name}\$" -fuzztime="$FUZZTIME" "$pkg"
done

if [[ "${INTEGRATION:-0}" == "1" ]]; then
	step "integración (Docker + testcontainers)"
	if ! docker info >/dev/null 2>&1; then
		echo "INTEGRATION=1 pero Docker no responde" >&2
		exit 1
	fi
	go test -race -count=1 -tags=integration ./internal/ratelimit ./internal/reputation
fi

step "todo verde ✅"
