const SUPPORTED = new Set(['vless', 'trojan', 'vmess', 'hysteria2', 'hy2', 'ss', 'tuic']);

export function decodeBase64Safe(input) {
  if (!input) return null;
  try {
    let normalized = String(input).trim().replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
    while (normalized.length % 4) normalized += '=';
    const binary = atob(normalized);
    const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    return null;
  }
}

function safeDecode(value) {
  try { return decodeURIComponent(value || ''); } catch { return value || ''; }
}

function boolParam(value) {
  if (value == null) return false;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

function normalizeTransport(raw = '') {
  const v = String(raw).toLowerCase();
  if (v === 'httpupgrade') return 'httpupgrade';
  if (v === 'xhttp') return 'xhttp';
  if (v === 'grpc') return 'grpc';
  if (v === 'ws' || v === 'websocket') return 'ws';
  if (v === 'http' || v === 'h2') return 'http';
  if (v === 'quic') return 'quic';
  return v || 'tcp';
}

function baseConfig(raw, protocol) {
  return {
    raw,
    protocol,
    address: '',
    port: 443,
    auth: '',
    tag: `${protocol.toUpperCase()} Node`,
    security: 'none',
    tls: false,
    sni: '',
    alpn: '',
    fingerprint: '',
    insecure: false,
    reality: false,
    publicKey: '',
    shortId: '',
    spiderX: '',
    flow: '',
    transport: 'tcp',
    host: '',
    path: '/',
    serviceName: '',
    mode: '',
    method: '',
    sourceId: '',
    sourceName: '',
    status: 'pending',
    latency: null,
    reason: '',
    probeType: '',
    testedAt: 0,
    score: null,
    verification: null,
    fingerprintId: ''
  };
}

function parseVmess(raw) {
  const decoded = decodeBase64Safe(raw.slice('vmess://'.length));
  if (!decoded) return null;
  let data;
  try { data = JSON.parse(decoded); } catch { return null; }
  if (!data.add) return null;
  const cfg = baseConfig(raw, 'vmess');
  cfg.address = String(data.add).trim();
  cfg.port = Number(data.port || 443);
  cfg.auth = String(data.id || '');
  cfg.tag = String(data.ps || 'VMess Node');
  cfg.transport = normalizeTransport(data.net || data.type || 'tcp');
  cfg.host = String(data.host || '');
  cfg.path = String(data.path || '/');
  cfg.serviceName = String(data.path || data.serviceName || '');
  cfg.security = String(data.tls || 'none').toLowerCase();
  cfg.tls = cfg.security === 'tls' || cfg.security === 'reality';
  cfg.reality = cfg.security === 'reality';
  cfg.sni = String(data.sni || data.serverName || data.host || '');
  cfg.alpn = String(data.alpn || '');
  cfg.fingerprint = String(data.fp || '');
  cfg.flow = String(data.flow || '');
  cfg.insecure = boolParam(data.allowInsecure);
  return cfg;
}

function decodeShadowsocksUserInfo(rawUser) {
  if (!rawUser) return { method: '', password: '' };
  let text = safeDecode(rawUser);
  if (!text.includes(':')) {
    const decoded = decodeBase64Safe(text);
    if (decoded) text = decoded;
  }
  const idx = text.indexOf(':');
  if (idx < 1) return { method: '', password: text };
  return { method: text.slice(0, idx), password: text.slice(idx + 1) };
}

function parseShadowsocks(raw) {
  let candidate = raw;
  const body = raw.slice(5);
  if (!body.includes('@')) {
    const hashIndex = body.indexOf('#');
    const payload = hashIndex >= 0 ? body.slice(0, hashIndex) : body;
    const decoded = decodeBase64Safe(payload);
    if (decoded && decoded.includes('@')) {
      const suffix = hashIndex >= 0 ? body.slice(hashIndex) : '';
      candidate = `ss://${decoded}${suffix}`;
    }
  }
  let url;
  try { url = new URL(candidate); } catch { return null; }
  if (!url.hostname) return null;
  const cfg = baseConfig(raw, 'ss');
  cfg.address = url.hostname;
  cfg.port = Number(url.port || 8388);
  const creds = decodeShadowsocksUserInfo(url.username);
  cfg.method = creds.method;
  cfg.auth = creds.password;
  cfg.tag = safeDecode(url.hash.slice(1)) || 'Shadowsocks Node';
  cfg.transport = 'tcp';
  cfg.security = 'none';
  return cfg;
}

function parseStandard(raw) {
  let url;
  try { url = new URL(raw); } catch { return null; }
  let protocol = url.protocol.replace(':', '').toLowerCase();
  if (!SUPPORTED.has(protocol)) return null;
  if (protocol === 'hy2') protocol = 'hysteria2';
  if (protocol === 'ss') return parseShadowsocks(raw);
  if (!url.hostname) return null;

  const p = Object.fromEntries(url.searchParams.entries());
  const cfg = baseConfig(raw, protocol);
  cfg.address = url.hostname;
  cfg.port = Number(url.port || 443);
  cfg.auth = safeDecode(url.username || '');
  cfg.tag = safeDecode(url.hash.slice(1)) || `${protocol.toUpperCase()} Node`;
  cfg.security = String(p.security || (protocol === 'trojan' || protocol === 'hysteria2' ? 'tls' : 'none')).toLowerCase();
  cfg.tls = cfg.security === 'tls' || cfg.security === 'reality' || protocol === 'trojan' || protocol === 'hysteria2';
  cfg.reality = cfg.security === 'reality';
  cfg.sni = String(p.sni || p.serverName || p.peer || '');
  cfg.alpn = String(p.alpn || '');
  cfg.fingerprint = String(p.fp || p.fingerprint || '');
  cfg.insecure = boolParam(p.allowInsecure || p.insecure);
  cfg.publicKey = String(p.pbk || p.publicKey || '');
  cfg.shortId = String(p.sid || p.shortId || '');
  cfg.spiderX = String(p.spx || p.spiderX || '');
  cfg.flow = String(p.flow || '');
  cfg.transport = normalizeTransport(p.type || p.net || (protocol === 'hysteria2' ? 'quic' : 'tcp'));
  cfg.host = String(p.host || '');
  cfg.path = safeDecode(p.path || '/');
  cfg.serviceName = safeDecode(p.serviceName || p.service || (cfg.transport === 'grpc' ? p.path || '' : ''));
  cfg.mode = String(p.mode || '');

  if (protocol === 'trojan' && !cfg.auth) cfg.auth = safeDecode(url.username || '');
  if (protocol === 'hysteria2') cfg.auth = safeDecode(url.username || p.password || p.auth || '');
  if (protocol === 'tuic') cfg.auth = safeDecode(url.username || '');
  return cfg;
}

export function parseProxyURI(rawInput) {
  const raw = String(rawInput || '').trim();
  if (!raw || !raw.includes('://')) return null;
  if (raw.startsWith('vmess://')) return parseVmess(raw);
  return parseStandard(raw);
}

export function decodeSubscriptionText(text) {
  let body = String(text || '').trim();
  if (!body) return [];
  if (!body.includes('://')) {
    const decoded = decodeBase64Safe(body);
    if (decoded && decoded.includes('://')) body = decoded;
  }
  return body
    .split(/\r?\n/)
    .map(v => v.trim())
    .filter(v => v && !v.startsWith('#'));
}

export function canonicalConfigKey(cfg) {
  const parts = [
    cfg.protocol,
    cfg.address.toLowerCase(),
    Number(cfg.port),
    cfg.transport,
    cfg.security,
    cfg.sni.toLowerCase(),
    cfg.host.toLowerCase(),
    cfg.path,
    cfg.serviceName,
    cfg.flow,
    cfg.publicKey,
    cfg.shortId,
    cfg.fingerprint,
    cfg.alpn,
    cfg.method
  ];
  return parts.join('|');
}

export async function sha256Hex(text) {
  if (globalThis.crypto?.subtle) {
    const data = new TextEncoder().encode(text);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join('');
  }
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return `fnv-${(h >>> 0).toString(16).padStart(8, '0')}`;
}

export async function addFingerprints(configs) {
  return Promise.all(configs.map(async cfg => ({ ...cfg, fingerprintId: await sha256Hex(canonicalConfigKey(cfg)) })));
}

export function deduplicateConfigs(configs) {
  const seen = new Set();
  const unique = [];
  for (const cfg of configs) {
    const key = canonicalConfigKey(cfg);
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(cfg);
  }
  return unique;
}

export function browserProbeCapability(cfg) {
  if (!cfg) return { testable: false, reason: 'Invalid config' };
  if (cfg.reality) return { testable: false, reason: 'Reality handshake قابل شبیه‌سازی در Browser نیست' };
  if (['hysteria2', 'tuic'].includes(cfg.protocol) || cfg.transport === 'quic') {
    return { testable: false, reason: 'QUIC/UDP از Browser قابل تست مستقیم نیست' };
  }
  if (!cfg.tls) return { testable: false, reason: 'Browser امکان raw TCP probe ندارد' };

  const address = cfg.address.toLowerCase();
  const sni = (cfg.sni || cfg.address).toLowerCase();
  const host = (cfg.host || cfg.address).toLowerCase();
  if (sni && sni !== address) return { testable: false, reason: 'SNI با endpoint متفاوت است' };
  if (cfg.transport === 'ws' && host && host !== address) return { testable: false, reason: 'Host header با endpoint متفاوت است' };
  return { testable: true, reason: '' };
}
