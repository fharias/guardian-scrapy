# Guardian performance

[Español](perf.md)

How we measure the proxy overhead, what we found, and what we fixed.
**Fabio**'s numbers are from his MacBook (M3 Pro) with Docker Desktop. Numbers
marked **(box)** are from a shared x86 Linux VM: they compare before and after
with each other, and they are not for comparing with the M3.

## Method

1. **k6 load** (`scripts/k6/load.js`, two `constant-arrival-rate` scenarios):
   - `browsers`: 100 req/s with Chrome headers. They expect **200**.
   - `bots`: 40 req/s with `User-Agent: curl/...`. They expect **403** (`expectedStatuses(403)`).
   - Host `shop.local` (with `127.0.0.1` the router responds 421).
   - Config `deploy/compose/config/guardian.load.yml`: real Valkey, rate/burst 100000,
     tracing `sample_ratio: 0.01`, `events.enabled: false`.
2. **Upstream baseline** with `scripts/k6/upstream.js` (100 req/s straight at the upstream).
3. **Guardian overhead = p99 of `http_req_duration{kind:browser}` − upstream p99.**
   Target: **< 10 ms** (stretch: < 5 ms).
4. **Profiles** with `scripts/pprof-capture.sh` against the Admin API (`:9091`, Bearer token)
   while `DURATION=90s` is running: CPU 30 s, trace 5 s, and `allocs`, `heap`, `goroutine`,
   `mutex`, `block` (the last two turned on with `admin.mutex_profile_fraction` and
   `admin.block_profile_rate`, only in the load config). `allocs`, `mutex`, and `block` are
   accumulated from startup: they are subtracted with `-base <snapshot-before>`.
5. **Go benchmarks** with `b.Loop()` and `b.ReportAllocs()`, compared with `benchstat`
   (`-count=10`).

## Fabio's measured numbers (M3 Pro, Docker Desktop, ~140 req/s, 90 s)

| Measure | Value |
|---|---|
| Upstream directly, p99 | 5.66 ms |
| Browsers through Guardian, p99 (2 runs of 90 s) | 8.02 ms and 11.69 ms |
| **p99 overhead** | **≈ 2.4 to 6.0 ms** (meets the 10 ms target) |
| Overhead at the median | ≈ 1.15 ms |
| First run (45 s) | p99 47 ms: warmup noise (connections, caches, initial GC), it did not repeat |
| Process CPU utilization | 14.7% |

Profiles from the same load:

- **CPU:** `Syscall6` 28% flat (network I/O and log writes), `futex` 8%.
  `otel ... newSpan` 6% cum even with `sample_ratio: 0.01`.
  `fingerprint.Compute` does **not** show up in the top.
- **alloc_space (with `-base`):**
  - `httputil.(*ReverseProxy).copyBuffer` 121.73 MB, **49.8%**
  - `net/http.(*Request).WithContext` 46 MB, 18.8%
  - `context.WithValue` 3.5%
- **mutex:** negligible, 3 ms in total.
- **block:** only `ratelimit.(*Pool).StartJanitor` in `selectgo` (background goroutine, not contention).

## Findings

- The proxy is healthy: the typical overhead is ~1 ms and the queue meets the target.
  The Reto 3 suspects (Valkey, locks, `Compute`) were **not** the problem:
  there is no mutex contention and no connection-pool contention.
- The real memory hotspot was `ReverseProxy.copyBuffer`: without `BufferPool`,
  `httputil.ReverseProxy` does `make([]byte, 32*1024)` on **every response**,
  even when the body is 200 bytes. Only the browsers reach the upstream (the bots get 403 first):
  100 req/s × 32 KB ≈ 3.2 MB/s of garbage from that path alone, which the GC has to free.
  It matches the 121.73 MB of the capture window (~36 s).
- Optimizing `fingerprint.Compute` (22 allocs, 1.5 KB) would have been a mistake:
  the real profile says it does not matter. That is why we measure before optimizing.

## The fix

`cmd/guardian/bufpool.go`: an `httputil.BufferPool` backed by a `sync.Pool` of
32 KB buffers, **one per process** (it survives reloads, the same as
`http.DefaultTransport`), wired in `newUpstreamProxy` (`cmd/guardian/build.go`)
with `BufferPool: proxyBufferPool`.

Known tradeoff (staticcheck **SA6002**): the interface fixes `Put([]byte)`, and
putting a slice into the `any` of `sync.Pool` allocates its header (24 B) on every
`Put`. The ideal would be to store `*[]byte`, but `ReverseProxy` hands us the slice,
not the pointer, so allocating a new one would cost the same alloc. 24 B against 32 KB
per response is a clear gain, and it is documented in the code.

### Before / after (M3 Pro, `-count=10`, benchstat)

`BenchmarkUpstreamProxy`: one full pass through the real `ReverseProxy`
(Rewrite + keep-alive Transport + copyResponse) against an `httptest.Server`.
The `allocs/op` include the upstream server, which runs in the same process.

| body | sec/op before | sec/op after | B/op before | B/op after |
|---|---|---|---|---|
| 256 B | 59.23 µs | 50.80 µs (−14.2%) | 39.29 KiB | 7.45 KiB (−81.1%) |
| 16 KiB | 61.73 µs | 51.61 µs (−16.4%) | 39.26 KiB | 7.53 KiB (−80.8%) |
| 64 KiB | 64.92 µs | 58.38 µs (−10.1%) | 39.26 KiB | 7.51 KiB (−80.9%) |
| **geomean** | 61.92 µs | 53.49 µs (**−13.6%**) | 39.27 KiB | 7.50 KiB (**−80.9%**) |

All with `p=0.000, n=10`. `allocs/op` stays at 85: the 32 KB buffer was ONE of those
allocs and the 24 B header of `Put` replaces it. What drops is the **size**, not the count.
Files: `docs/bench-baseline.txt` and `docs/bench-new.txt` (M3 Pro numbers).

## Next candidates (in order of expected gain)

1. **`WithContext` chain (18.8% of alloc_space):** every middleware that stores something
   in the context does `r.WithContext(...)`, which copies the whole `http.Request`.
   Idea: a single `context.WithValue` with a mutable struct (the `verdict`) instead of several.
2. **`otel newSpan` (6% cum CPU at ratio 0.01):** the sampler drops 99%, but
   the non-recording span is still created. Hypothesis to check in `middleware.Trace`:
   skip creating the span when the sampler says no, without losing `traceparent` propagation.
3. **Info logging per request (`Syscall6` 28%):** one write per request to stdout.
   Options: Debug level for the 200s, log sampling, or a `bufio` with a periodic flush.
4. `fingerprint.Compute`: low priority (it does not show up in the profile).

## How to repeat it

```bash
# 1) Before/after benchmark (repo root). The "before" removes the pool line.
sed -i.bak '/BufferPool: proxyBufferPool,/d' cmd/guardian/build.go
go test ./cmd/guardian -run '^$' -bench BenchmarkUpstreamProxy -benchmem -count=10 | tee docs/bench-baseline.txt
mv cmd/guardian/build.go.bak cmd/guardian/build.go
go test ./cmd/guardian -run '^$' -bench BenchmarkUpstreamProxy -benchmem -count=10 | tee docs/bench-new.txt
go install golang.org/x/perf/cmd/benchstat@latest
benchstat docs/bench-baseline.txt docs/bench-new.txt

# 2) Load and profiles (3 terminals)
cd deploy/compose
docker compose -f docker-compose.yml -f docker-compose.load.yml up -d --build
DURATION=90s docker compose -f docker-compose.yml -f docker-compose.load.yml --profile load run --rm k6 run --summary-trend-stats="avg,med,p(95),p(99),max" /scripts/load.js
docker compose -f docker-compose.yml -f docker-compose.load.yml --profile load run --rm k6 run --summary-trend-stats="avg,med,p(95),p(99),max" /scripts/upstream.js
# from the repo root, with k6 running:
export GUARDIAN_ADMIN_TOKEN="$(grep GUARDIAN_ADMIN_TOKEN deploy/compose/.env | cut -d= -f2)"
sleep 5 && ./scripts/pprof-capture.sh

# 3) Analysis
P=prof-AAAAMMDD-HHMMSS
go tool pprof -sample_index=alloc_space -base $P/allocs-before.pb.gz -top -nodecount=10 $P/allocs.pb.gz
go tool pprof -top -nodecount=10 $P/cpu.pb.gz
```

p99 overhead = p99 of `{kind:browser}` in `load.js` − p99 of `upstream.js`.
