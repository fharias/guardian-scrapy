import http from 'k6/http';
import { check } from 'k6';

// Baseline: pega al upstream DIRECTO, sin pasar por Guardian.
// Corre este script y load.js por separado para que no se peleen el CPU.
// La resta p99(proxy) - p99(upstream) es el overhead.
const UPSTREAM_URL = __ENV.UPSTREAM_URL || 'http://127.0.0.1:9000';
const HOST = __ENV.HOST || 'shop.local';

export const options = {
  scenarios: {
    upstream: {
      executor: 'constant-arrival-rate',
      rate: 100,
      timeUnit: '1s',
      duration: '45s',
      preAllocatedVUs: 40,
      maxVUs: 80,
      exec: 'upstreamDirect',
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<500'],
    checks: ['rate>0.99'],
  },
};

export function upstreamDirect() {
  const res = http.get(`${UPSTREAM_URL}/`, {
    headers: { Host: HOST },
    tags: { kind: 'upstream' },
  });
  check(res, { 'upstream got 200': (r) => r.status === 200 }, { kind: 'upstream' });
}
