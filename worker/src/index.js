// SplitHello Worker - single source of truth.
//
// This exact file is embedded into the client binary at build time
// (see cmake/EmbedWorker.cmake) and is what `--setup` / `--redeploy` upload.
// Editing it here is enough; there is no second copy in the C++ sources.
// `wrangler deploy` from the worker/ directory uploads the same code.
//
// Endpoints
//   GET  /health   - unauthenticated liveness probe, leaks nothing
//   GET  /resolve  - DNS-over-HTTPS lookup (A + AAAA) for one hostname
//   GET  /tunnel   - WebSocket-to-TCP relay, used only as a fallback
//
// /resolve and /tunnel both require `Authorization: Bearer <SHARED_SECRET>`.
// SHARED_SECRET is a secret_text binding written at deploy time. If it is
// missing the Worker fails closed: an unauthenticated deployment is an open
// DNS proxy and an open TCP relay against the account's quota.
//
// Note for maintainers: avoid backtick template literals in this file. It is
// embedded into a C++ raw string via CMake, and plain concatenation keeps that
// pipeline free of surprises.

import { connect } from 'cloudflare:sockets';

const ALLOWED_PORTS = new Set([80, 443, 853]);
const MAX_HOSTNAME_LENGTH = 253;
const HOSTNAME_PATTERN =
  /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.?$/i;

const MIN_TTL = 60;
const MAX_TTL = 3600;

// Fallback limiter for deployments where the ratelimit binding is unavailable.
// Per-isolate, so it is a backstop rather than a guarantee.
const LOCAL_WINDOW_MS = 60000;
const LOCAL_MAX_REQUESTS = 240;
const LOCAL_MAX_KEYS = 5000;
const localHits = new Map();

function jsonResponse(body, status) {
  return new Response(JSON.stringify(body), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}

// Comparison whose duration does not depend on how many characters matched.
function constantTimeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function bearerToken(request) {
  const header = request.headers.get('Authorization') || '';
  return header.startsWith('Bearer ') ? header.slice(7).trim() : '';
}

function isAuthorized(request, env) {
  const expected = env && env.SHARED_SECRET;
  if (!expected) return false; // fail closed: no secret configured, no service
  return constantTimeEqual(bearerToken(request), expected);
}

function clientKey(request) {
  return request.headers.get('CF-Connecting-IP') || 'unknown';
}

async function isRateLimited(request, env) {
  if (env && env.RATE_LIMITER) {
    try {
      const outcome = await env.RATE_LIMITER.limit({ key: clientKey(request) });
      return !outcome.success;
    } catch (e) {
      // Binding missing or misconfigured: fall through to the local counter.
    }
  }

  const key = clientKey(request);
  const now = Date.now();
  const entry = localHits.get(key);

  if (!entry || now - entry.start > LOCAL_WINDOW_MS) {
    if (localHits.size > LOCAL_MAX_KEYS) localHits.clear();
    localHits.set(key, { start: now, count: 1 });
    return false;
  }

  entry.count += 1;
  return entry.count > LOCAL_MAX_REQUESTS;
}

function isValidHostname(hostname) {
  return typeof hostname === 'string' &&
    hostname.length > 0 &&
    hostname.length <= MAX_HOSTNAME_LENGTH &&
    HOSTNAME_PATTERN.test(hostname);
}

// Cloudflare already refuses to open sockets to loopback, private ranges and
// its own IPs. We check anyway so a misconfigured or future runtime cannot
// turn this Worker into an internal port scanner.
function isPrivateV4(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return true;
  if (parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;

  const [a, b] = parts;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true;         // link-local
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a >= 224) return true;                        // multicast / reserved
  return false;
}

function isPrivateV6(ip) {
  const value = ip.toLowerCase();
  if (value === '::' || value === '::1') return true;
  if (value.startsWith('::ffff:')) return isPrivateV4(value.slice(7));
  if (value.startsWith('fe80') || value.startsWith('fc') || value.startsWith('fd')) return true;
  return false;
}

function isPublicAddress(ip, family) {
  return family === 6 ? !isPrivateV6(ip) : !isPrivateV4(ip);
}

async function queryDoh(hostname, recordType) {
  const url = 'https://1.1.1.1/dns-query?name=' + encodeURIComponent(hostname) +
    '&type=' + recordType;

  try {
    const response = await fetch(url, { headers: { Accept: 'application/dns-json' } });
    if (!response.ok) return { addresses: [], ttl: 0 };

    const payload = await response.json();
    if (!payload || !Array.isArray(payload.Answer)) return { addresses: [], ttl: 0 };

    const wanted = recordType === 'AAAA' ? 28 : 1;
    const family = recordType === 'AAAA' ? 6 : 4;

    const answers = payload.Answer.filter((entry) => entry.type === wanted);
    const addresses = answers
      .map((entry) => entry.data)
      .filter((address) => typeof address === 'string' && isPublicAddress(address, family));

    const ttls = answers.map((entry) => entry.TTL).filter((ttl) => Number.isInteger(ttl));
    const ttl = ttls.length > 0 ? Math.min.apply(null, ttls) : 0;

    return { addresses, ttl };
  } catch (e) {
    return { addresses: [], ttl: 0 };
  }
}

async function resolveHost(hostname) {
  const [v4, v6] = await Promise.all([queryDoh(hostname, 'A'), queryDoh(hostname, 'AAAA')]);

  const ttls = [v4.ttl, v6.ttl].filter((ttl) => ttl > 0);
  const ttl = ttls.length > 0 ? Math.min.apply(null, ttls) : MIN_TTL;

  return {
    a: v4.addresses,
    aaaa: v6.addresses,
    ttl: Math.max(MIN_TTL, Math.min(MAX_TTL, ttl)),
  };
}

async function handleResolve(url) {
  const hostname = url.searchParams.get('host');

  if (!isValidHostname(hostname)) {
    return jsonResponse({ error: 'invalid host' }, 400);
  }

  const result = await resolveHost(hostname);
  if (result.a.length === 0 && result.aaaa.length === 0) {
    return jsonResponse({ error: 'no records', host: hostname }, 404);
  }

  return jsonResponse({ host: hostname, a: result.a, aaaa: result.aaaa, ttl: result.ttl });
}

async function handleDnsQuery(request) {
  if (request.method !== 'POST') {
    return new Response('Method Not Allowed', {
      status: 405,
      headers: { Allow: 'POST' },
    });
  }

  const contentType = request.headers.get('Content-Type') || '';
  if (!contentType.toLowerCase().startsWith('application/dns-message')) {
    return new Response('Unsupported Media Type', { status: 415 });
  }

  const query = await request.arrayBuffer();
  if (query.byteLength < 12 || query.byteLength > 4096) {
    return new Response('Invalid DNS message', { status: 400 });
  }

  try {
    const upstream = await fetch('https://1.1.1.1/dns-query', {
      method: 'POST',
      headers: {
        Accept: 'application/dns-message',
        'Content-Type': 'application/dns-message',
      },
      body: query,
    });

    if (!upstream.ok) {
      return new Response('DNS upstream failed', { status: 502 });
    }

    const answer = await upstream.arrayBuffer();
    if (answer.byteLength < 12 || answer.byteLength > 65535) {
      return new Response('Invalid DNS upstream response', { status: 502 });
    }

    return new Response(answer, {
      status: 200,
      headers: {
        'Content-Type': 'application/dns-message',
        'Cache-Control': 'no-store',
      },
    });
  } catch (error) {
    return new Response('DNS upstream unavailable', { status: 502 });
  }
}

function handleTunnel(request) {
  if (request.headers.get('Upgrade') !== 'websocket') {
    return new Response('Expected WebSocket', { status: 426 });
  }

  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair);
  server.accept();

  let targetWriter = null;
  let opening = false;

  const closeTarget = () => {
    if (targetWriter) {
      try { targetWriter.close(); } catch (e) { /* already gone */ }
      targetWriter = null;
    }
  };

  const failAndClose = (message, code) => {
    try { server.send(JSON.stringify({ status: 'error', msg: message })); } catch (e) { /* closed */ }
    try { server.close(code, message); } catch (e) { /* closed */ }
    closeTarget();
  };

  server.addEventListener('message', async (event) => {
    try {
      if (!targetWriter) {
        if (opening) return; // ignore anything sent before the target is up
        opening = true;

        const command = JSON.parse(event.data);

        if (command.cmd !== 'connect' || !isValidHostname(command.host)) {
          opening = false;
          failAndClose('invalid host', 1008);
          return;
        }

        const port = Number(command.port);
        if (!ALLOWED_PORTS.has(port)) {
          opening = false;
          failAndClose('port not allowed', 1008);
          return;
        }

        // Connect by resolved address so the reachability check above is the
        // one that actually applies to the socket we open.
        const resolved = await resolveHost(command.host);
        const address = resolved.a[0] || resolved.aaaa[0];
        if (!address) {
          opening = false;
          failAndClose('unresolvable host', 1008);
          return;
        }

        const targetSocket = connect({ hostname: address, port: port });
        targetWriter = targetSocket.writable.getWriter();
        opening = false;

        const reader = targetSocket.readable.getReader();
        (async () => {
          try {
            for (;;) {
              const { done, value } = await reader.read();
              if (done) break;
              if (server.readyState !== 1) break;
              server.send(value);
            }
          } catch (e) {
            try { server.send(JSON.stringify({ status: 'error', msg: 'target read failed' })); }
            catch (ignored) { /* closed */ }
          } finally {
            try { server.close(1000, 'target closed'); } catch (e) { /* closed */ }
          }
        })();

        server.send(JSON.stringify({ status: 'connected' }));
        return;
      }

      const data = typeof event.data === 'string'
        ? new TextEncoder().encode(event.data)
        : event.data;
      await targetWriter.write(data);
    } catch (e) {
      opening = false;
      failAndClose('relay error', 1011);
    }
  });

  server.addEventListener('close', closeTarget);
  server.addEventListener('error', closeTarget);

  return new Response(null, { status: 101, webSocket: client });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === '/' || path === '/health') {
      return new Response('ok', {
        status: 200,
        headers: { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' },
      });
    }

    if (path !== '/resolve' && path !== '/dns-query' && path !== '/tunnel') {
      return new Response('Not Found', { status: 404 });
    }

    if (!isAuthorized(request, env)) {
      return new Response('Unauthorized', {
        status: 401,
        headers: { 'WWW-Authenticate': 'Bearer' },
      });
    }

    if (await isRateLimited(request, env)) {
      return new Response('Too Many Requests', {
        status: 429,
        headers: { 'Retry-After': '60' },
      });
    }

    if (path === '/resolve') return handleResolve(url);
    if (path === '/dns-query') return handleDnsQuery(request);
    return handleTunnel(request);
  },
};
