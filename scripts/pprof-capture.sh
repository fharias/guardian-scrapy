#!/usr/bin/env bash
# Captura los perfiles del Reto 4 desde la Admin API (:9091) mientras corre la carga.
#   export GUARDIAN_ADMIN_TOKEN="$(grep GUARDIAN_ADMIN_TOKEN deploy/compose/.env | cut -d= -f2)"
#   ./scripts/pprof-capture.sh                  desde la raíz del repo
#   CPU_SECONDS=15 ./scripts/pprof-capture.sh   perfil de CPU más corto
# Deja todo en ./prof-<fecha>/ (los *.pb.gz se abren con `go tool pprof`).
set -euo pipefail

: "${GUARDIAN_ADMIN_TOKEN:?exporta GUARDIAN_ADMIN_TOKEN (ver arriba)}"
ADMIN_URL="${ADMIN_URL:-http://127.0.0.1:9091}"
CPU_SECONDS="${CPU_SECONDS:-30}"
TRACE_SECONDS="${TRACE_SECONDS:-5}"
OUT="${OUT:-prof-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUT"

# -f: si el servidor responde 4xx/5xx, curl falla y el script se detiene.
# --max-time: el perfil de CPU tarda CPU_SECONDS; dejamos 30 s de margen.
fetch() { # fetch <ruta> <archivo> <max-time>
	curl -fsS --max-time "$3" -H "Authorization: Bearer $GUARDIAN_ADMIN_TOKEN" \
		"$ADMIN_URL/debug/pprof/$1" -o "$OUT/$2"
	echo "  $2  ($(wc -c <"$OUT/$2" | tr -d ' ') bytes)"
}

echo "==> antes de la ventana (para restar con -base)"
fetch allocs allocs-before.pb.gz 10
fetch mutex mutex-before.pb.gz 10
fetch block block-before.pb.gz 10

echo "==> CPU ${CPU_SECONDS}s"
fetch "profile?seconds=${CPU_SECONDS}" cpu.pb.gz $((CPU_SECONDS + 30))

echo "==> trace ${TRACE_SECONDS}s"
fetch "trace?seconds=${TRACE_SECONDS}" trace.out $((TRACE_SECONDS + 30))

echo "==> después"
fetch allocs allocs.pb.gz 10
fetch heap heap.pb.gz 10
fetch goroutine goroutine.pb.gz 10
fetch mutex mutex.pb.gz 10
fetch block block.pb.gz 10

echo "listo: $OUT"
