import http from 'k6/http';
import { check } from 'k6';

// Desde compose: BASE_URL=http://guardian:8080 y HOST=shop.local.
// Desde tu Mac:  BASE_URL=http://127.0.0.1:8080 y el mismo HOST.
// Sin Host: shop.local, apps responde 421 (el Host sería 127.0.0.1).
const BASE_URL = __ENV.BASE_URL || 'http://127.0.0.1:8080';
const HOST = __ENV.HOST || 'shop.local';
// DURATION=90s para dejar tiempo a capturar perfiles (el Reto 4 pide ~40 s).
const DURATION = __ENV.DURATION || '45s';

const browserHeaders = {
  Host: HOST,
  'User-Agent':
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'Accept-Language': 'es-CO,es;q=0.9',
  'Accept-Encoding': 'gzip, deflate',
};

const botHeaders = {
  Host: HOST,
  'User-Agent': 'curl/8.5.0',
};

export const options = {
  scenarios: {
    browsers: {
      executor: 'constant-arrival-rate',
      rate: 100,
      timeUnit: '1s',
      duration: DURATION,
      preAllocatedVUs: 40,
      maxVUs: 80,
      exec: 'browser',
    },
    bots: {
      executor: 'constant-arrival-rate',
      rate: 40,
      timeUnit: '1s',
      duration: DURATION,
      preAllocatedVUs: 20,
      maxVUs: 40,
      exec: 'bot',
    },
  },
  thresholds: {
    // 403 no cuenta como error: abajo usamos expectedStatuses.
    'http_req_failed{kind:browser}': ['rate<0.01'],
    'http_req_failed{kind:bot}': ['rate<0.01'],
    // p95 del PROXY (incluye upstream): no es el SLO de overhead.
    'http_req_duration{kind:browser}': ['p(95)<500'],
    'checks{kind:browser}': ['rate>0.99'],
    'checks{kind:bot}': ['rate>0.99'],
  },
};

export function browser() {
  const res = http.get(`${BASE_URL}/`, {
    headers: browserHeaders,
    tags: { kind: 'browser' },
  });
  check(res, { 'browser got 200': (r) => r.status === 200 }, { kind: 'browser' });
}

export function bot() {
  // k6 marca 4xx como http_req_failed; 403 es el resultado esperado.
  const res = http.get(`${BASE_URL}/`, {
    headers: botHeaders,
    tags: { kind: 'bot' },
    responseCallback: http.expectedStatuses(403),
  });
  check(res, { 'bot got 403': (r) => r.status === 403 }, { kind: 'bot' });
}
