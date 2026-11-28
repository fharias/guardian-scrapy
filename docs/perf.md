# Performance de Guardian

Cómo medimos el overhead del proxy, qué encontramos y qué arreglamos.
Los números de **Fabio** son de su MacBook (M3 Pro) con Docker Desktop. Los
números marcados **(caja)** son de una VM Linux x86 compartida: sirven para
comparar antes/después entre sí, no para compararlos con el M3.

## Metodología

1. **Carga con k6** (`scripts/k6/load.js`, dos scenarios `constant-arrival-rate`):
   - `browsers`: 100 req/s con headers de Chrome. Esperan **200**.
   - `bots`: 40 req/s con `User-Agent: curl/...`. Esperan **403** (`expectedStatuses(403)`).
   - Host `shop.local` (con `127.0.0.1` el router responde 421).
   - Config `deploy/compose/config/guardian.load.yml`: Valkey real, rate/burst 100000,
     tracing `sample_ratio: 0.01`, `events.enabled: false`.
2. **Baseline del upstream** con `scripts/k6/upstream.js` (100 req/s directo al upstream).
3. **Overhead de Guardian = p99 de `http_req_duration{kind:browser}` − p99 del upstream.**
   Meta: **< 10 ms** (stretch: < 5 ms).
4. **Perfiles** con `scripts/pprof-capture.sh` contra la Admin API (`:9091`, Bearer token)
   mientras corre `DURATION=90s`: CPU 30 s, trace 5 s, y `allocs`, `heap`, `goroutine`,
   `mutex`, `block` (los dos últimos activados con `admin.mutex_profile_fraction` y
   `admin.block_profile_rate`, solo en la config de carga). `allocs`, `mutex` y `block` son
   acumulados desde el arranque: se restan con `-base <snapshot-antes>`.
5. **Benchmarks de Go** con `b.Loop()` y `b.ReportAllocs()`, comparados con `benchstat`
   (`-count=10`).

## Números reales de Fabio (M3 Pro, Docker Desktop, ~140 req/s, 90 s)

| Medida | Valor |
|---|---|
| Upstream directo, p99 | 5.66 ms |
| Browsers a través de Guardian, p99 (2 corridas de 90 s) | 8.02 ms y 11.69 ms |
| **Overhead p99** | **≈ 2.4 a 6.0 ms** (cumple la meta de 10 ms) |
| Overhead en la mediana | ≈ 1.15 ms |
| Primera corrida (45 s) | p99 47 ms: ruido de calentamiento (conexiones, caches, GC iniciales), no se repitió |
| Utilización de CPU del proceso | 14.7% |

Perfiles de la misma carga:

- **CPU:** `Syscall6` 28% flat (I/O de red y escrituras de log), `futex` 8%.
  `otel ... newSpan` 6% cum aun con `sample_ratio: 0.01`.
  `fingerprint.Compute` **no** aparece en el top.
- **alloc_space (con `-base`):**
  - `httputil.(*ReverseProxy).copyBuffer` 121.73 MB, **49.8%**
  - `net/http.(*Request).WithContext` 46 MB, 18.8%
  - `context.WithValue` 3.5%
- **mutex:** despreciable, 3 ms en total.
- **block:** solo `ratelimit.(*Pool).StartJanitor` en `selectgo` (goroutine de fondo, no contención).

## Hallazgos

- El proxy está sano: el overhead típico es de ~1 ms y la cola cumple la meta.
  Las sospechas del Reto 3 (Valkey, locks, `Compute`) **no** eran el problema:
  no hay contención de mutex ni de pool de conexiones.
- El hotspot de memoria real era `ReverseProxy.copyBuffer`: sin `BufferPool`,
  `httputil.ReverseProxy` hace `make([]byte, 32*1024)` en **cada respuesta**,
  aunque el body mida 200 bytes. Solo los browsers pasan por el upstream (los bots reciben 403 antes):
  100 req/s × 32 KB ≈ 3.2 MB/s de basura solo ahí, que el GC tiene que liberar.
  Cuadra con los 121.73 MB de la ventana de captura (~36 s).
- Optimizar `fingerprint.Compute` (22 allocs, 1.5 KB) habría sido un error:
  el perfil real dice que no importa. Por eso se mide antes de optimizar.

## El fix

`cmd/guardian/bufpool.go`: un `httputil.BufferPool` respaldado por `sync.Pool` de
buffers de 32 KB, **uno por proceso** (sobrevive a las recargas, igual que
`http.DefaultTransport`), conectado en `newUpstreamProxy` (`cmd/guardian/build.go`)
con `BufferPool: proxyBufferPool`.

Tradeoff conocido (staticcheck **SA6002**): la interfaz fija `Put([]byte)`, y
meter un slice en el `any` de `sync.Pool` reserva su encabezado (24 B) en cada
`Put`. Lo ideal sería guardar `*[]byte`, pero `ReverseProxy` nos entrega el slice,
no el puntero, así que crear uno nuevo costaría la misma alloc. 24 B contra 32 KB
por respuesta es una ganancia clara y queda documentado en el código.

### Antes / después (M3 Pro, `-count=10`, benchstat)

`BenchmarkUpstreamProxy`: una vuelta completa por el `ReverseProxy` real
(Rewrite + Transport keep-alive + copyResponse) contra un `httptest.Server`.
Los `allocs/op` incluyen al servidor del upstream, que corre en el mismo proceso.

| body | sec/op antes | sec/op después | B/op antes | B/op después |
|---|---|---|---|---|
| 256 B | 59.23 µs | 50.80 µs (−14.2%) | 39.29 KiB | 7.45 KiB (−81.1%) |
| 16 KiB | 61.73 µs | 51.61 µs (−16.4%) | 39.26 KiB | 7.53 KiB (−80.8%) |
| 64 KiB | 64.92 µs | 58.38 µs (−10.1%) | 39.26 KiB | 7.51 KiB (−80.9%) |
| **geomean** | 61.92 µs | 53.49 µs (**−13.6%**) | 39.27 KiB | 7.50 KiB (**−80.9%**) |

Todos con `p=0.000, n=10`. `allocs/op` queda igual en 85: el buffer de 32 KB era UNA de esas
allocs y la reemplaza el encabezado de 24 B del `Put`. Lo que baja es el **tamaño**, no la cantidad.
Archivos: `docs/bench-baseline.txt` y `docs/bench-new.txt` (números del M3 Pro).

## Próximos candidatos (en orden de ganancia esperada)

1. **Cadena de `WithContext` (18.8% de alloc_space):** cada middleware que guarda algo
   en el contexto hace `r.WithContext(...)`, que copia el `http.Request` completo.
   Idea: un solo `context.WithValue` con un struct mutable (el `verdict`) en lugar de varios.
2. **`otel newSpan` (6% cum de CPU con ratio 0.01):** el sampler descarta el 99%, pero
   igual se crea el span no-recording. Hipótesis a verificar en `middleware.Trace`:
   evitar crear el span cuando el sampler dice "no" sin perder la propagación del `traceparent`.
3. **Logging en Info por request (`Syscall6` 28%):** una escritura por request a stdout.
   Opciones: nivel Debug para los 200, sampling de logs, o un `bufio` con flush periódico.
4. `fingerprint.Compute`: baja prioridad (no aparece en el perfil).

## Cómo repetirlo

```bash
# 1) Benchmark antes/después (raíz del repo). El "antes" quita la línea del pool.
sed -i.bak '/BufferPool: proxyBufferPool,/d' cmd/guardian/build.go
go test ./cmd/guardian -run '^$' -bench BenchmarkUpstreamProxy -benchmem -count=10 | tee docs/bench-baseline.txt
mv cmd/guardian/build.go.bak cmd/guardian/build.go
go test ./cmd/guardian -run '^$' -bench BenchmarkUpstreamProxy -benchmem -count=10 | tee docs/bench-new.txt
go install golang.org/x/perf/cmd/benchstat@latest
benchstat docs/bench-baseline.txt docs/bench-new.txt

# 2) Carga y perfiles (3 terminales)
cd deploy/compose
docker compose -f docker-compose.yml -f docker-compose.load.yml up -d --build
DURATION=90s docker compose -f docker-compose.yml -f docker-compose.load.yml --profile load run --rm k6 run --summary-trend-stats="avg,med,p(95),p(99),max" /scripts/load.js
docker compose -f docker-compose.yml -f docker-compose.load.yml --profile load run --rm k6 run --summary-trend-stats="avg,med,p(95),p(99),max" /scripts/upstream.js
# desde la raíz del repo, con k6 corriendo:
export GUARDIAN_ADMIN_TOKEN="$(grep GUARDIAN_ADMIN_TOKEN deploy/compose/.env | cut -d= -f2)"
sleep 5 && ./scripts/pprof-capture.sh

# 3) Análisis
P=prof-AAAAMMDD-HHMMSS
go tool pprof -sample_index=alloc_space -base $P/allocs-before.pb.gz -top -nodecount=10 $P/allocs.pb.gz
go tool pprof -top -nodecount=10 $P/cpu.pb.gz
```

Overhead p99 = p99 de `{kind:browser}` en `load.js` − p99 de `upstream.js`.
