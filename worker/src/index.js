// SplitHello Worker - single source of truth.
//
// This exact file is embedded into the client binary at build time
// (see cmake/EmbedWorker.cmake) and is what `--setup` / `--redeploy` upload.
// Editing it here is enough; there is no second copy in the C++ sources.
// `wrangler deploy` from the worker/ directory uploads the same code.
//
// Endpoints
//   GET  /health     - unauthenticated liveness probe, leaks nothing
//   GET  /resolve    - DNS-over-HTTPS lookup (A + AAAA) for one hostname.
//                      200 always carries "rcode" (the real DNS RCODE, so the
//                      client can answer NXDOMAIN/NODATA instead of SERVFAIL);
//                      "partial": true means one address family's lookup
//                      failed and the answer must not be cached for a full TTL.
//                      502 only when both lookups failed.
//   POST /dns-query  - RFC 8484 wire-format relay (any record type)
//   GET  /tunnel     - WebSocket-to-TCP relay, used only as a fallback
//
// /resolve, /dns-query and /tunnel all require
// `Authorization: Bearer <SHARED_SECRET>`.
// SHARED_SECRET is a secret_text binding written at deploy time. If it is
// missing the Worker fails closed: an unauthenticated deployment is an open
// DNS proxy and an open TCP relay against the account's quota.
//
// Rate limiting: the account-wide RATE_LIMITER binding is consulted only AFTER
// authentication (each binding call is billed work; unauthenticated floods are
// cut off earlier by the cheap per-isolate failed-auth counter below).
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
// Per-isolate, so it is a backstop rather than a guarantee. Sized like the
// binding (600/min): one client legitimately sends A + AAAA + HTTPS per name.
const LOCAL_WINDOW_MS = 60000;
const LOCAL_MAX_REQUESTS = 600;
const LOCAL_MAX_KEYS = 5000;
const localHits = new Map();

// Cheap pre-auth brake: a client that keeps presenting a wrong secret is
// refused before any further work (secret comparison, binding call).
const AUTH_FAIL_WINDOW_MS = 60000;
const AUTH_FAIL_MAX = 30;
const authFailures = new Map();

// /tunnel limits. Generous for real use (TLS to a handful of sites), but a
// leaked secret can no longer pin a socket open or move unbounded data.
const TUNNEL_IDLE_MS = 120000;
const TUNNEL_MAX_BYTES = 512 * 1024 * 1024;
const TUNNEL_MAX_PENDING_BYTES = 4 * 1024 * 1024;

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

function authBlocked(key, now) {
  const entry = authFailures.get(key);
  return !!entry && now - entry.start <= AUTH_FAIL_WINDOW_MS && entry.count >= AUTH_FAIL_MAX;
}

function noteAuthFailure(key, now) {
  const entry = authFailures.get(key);
  if (!entry || now - entry.start > AUTH_FAIL_WINDOW_MS) {
    if (authFailures.size > LOCAL_MAX_KEYS) authFailures.clear();
    authFailures.set(key, { start: now, count: 1 });
    return;
  }
  entry.count += 1;
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

// `status` is the upstream DNS RCODE. `errored` marks a lookup that did not
// really complete (fetch failure, bad payload, SERVFAIL): it must never be read
// as "this name has no records", nor cached like an answer.
async function queryDoh(hostname, recordType) {
  const url = 'https://1.1.1.1/dns-query?name=' + encodeURIComponent(hostname) +
    '&type=' + recordType;
  const failed = { addresses: [], ttl: 0, status: 2, errored: true };

  try {
    const response = await fetch(url, { headers: { Accept: 'application/dns-json' } });
    if (!response.ok) return failed;

    const payload = await response.json();
    if (!payload || typeof payload !== 'object') return failed;

    const status = Number.isInteger(payload.Status) ? payload.Status : 0;
    if (status === 2) return failed;
    if (!Array.isArray(payload.Answer)) {
      return { addresses: [], ttl: 0, status, errored: false };
    }

    const wanted = recordType === 'AAAA' ? 28 : 1;
    const family = recordType === 'AAAA' ? 6 : 4;

    const answers = payload.Answer.filter((entry) => entry.type === wanted);
    const addresses = answers
      .map((entry) => entry.data)
      .filter((address) => typeof address === 'string' && isPublicAddress(address, family));

    const ttls = answers.map((entry) => entry.TTL).filter((ttl) => Number.isInteger(ttl));
    const ttl = ttls.length > 0 ? Math.min.apply(null, ttls) : 0;

    return { addresses, ttl, status, errored: false };
  } catch (e) {
    return failed;
  }
}

async function resolveHost(hostname) {
  const [v4, v6] = await Promise.all([queryDoh(hostname, 'A'), queryDoh(hostname, 'AAAA')]);

  const ttls = [v4.ttl, v6.ttl].filter((ttl) => ttl > 0);
  const ttl = ttls.length > 0 ? Math.min.apply(null, ttls) : MIN_TTL;

  const hasAddresses = v4.addresses.length > 0 || v6.addresses.length > 0;
  const failed = v4.errored && v6.errored;
  // Real RCODE when there is nothing to connect to: NXDOMAIN (3), or 0 for
  // NODATA / "every address was filtered as private". A family that errored
  // says nothing about the name, so take the status of the one that answered.
  let rcode = 0;
  if (!hasAddresses) rcode = failed ? 2 : (v4.errored ? v6.status : v4.status);

  return {
    a: v4.addresses,
    aaaa: v6.addresses,
    ttl: Math.max(MIN_TTL, Math.min(MAX_TTL, ttl)),
    rcode: rcode,
    partial: v4.errored !== v6.errored,
    failed: failed,
  };
}

async function handleResolve(url) {
  const hostname = url.searchParams.get('host');

  if (!isValidHostname(hostname)) {
    return jsonResponse({ error: 'invalid host' }, 400);
  }

  const result = await resolveHost(hostname);
  if (result.failed) {
    return jsonResponse({ error: 'upstream unavailable', host: hostname }, 502);
  }

  const body = {
    host: hostname,
    a: result.a,
    aaaa: result.aaaa,
    ttl: result.ttl,
    rcode: result.rcode,
  };
  if (result.partial) body.partial = true;
  return jsonResponse(body);
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

  // Refuse before buffering the body when the declared size is already too big.
  if (Number(request.headers.get('Content-Length')) > 4096) {
    return new Response('Invalid DNS message', { status: 413 });
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
  let idleTimer = null;
  let transferred = 0;     // bytes moved in both directions
  let pendingBytes = 0;    // client data accepted but not yet written to the target

  const clearIdle = () => {
    if (idleTimer !== null) {
      clearTimeout(idleTimer);
      idleTimer = null;
    }
  };

  const closeTarget = () => {
    clearIdle();
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

  // Any traffic in either direction restarts the idle clock.
  const touch = () => {
    clearIdle();
    idleTimer = setTimeout(() => failAndClose('idle timeout', 1001), TUNNEL_IDLE_MS);
  };
  const countBytes = (size) => {
    transferred += size;
    if (transferred > TUNNEL_MAX_BYTES) {
      failAndClose('byte limit reached', 1008);
      return false;
    }
    return true;
  };
  touch();

  server.addEventListener('message', async (event) => {
    touch();
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
              touch();
              if (!countBytes(value.byteLength)) break;
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
      const size = data.byteLength;
      if (!countBytes(size)) return;
      // The WebSocket cannot be paused, so bound what queues up behind a slow target.
      if (pendingBytes + size > TUNNEL_MAX_PENDING_BYTES) {
        failAndClose('target too slow', 1013);
        return;
      }
      pendingBytes += size;
      try {
        await targetWriter.write(data);
      } finally {
        pendingBytes -= size;
      }
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

    const key = clientKey(request);
    const now = Date.now();
    if (authBlocked(key, now)) {
      return new Response('Too Many Requests', {
        status: 429,
        headers: { 'Retry-After': '60' },
      });
    }

    if (!isAuthorized(request, env)) {
      noteAuthFailure(key, now);
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
