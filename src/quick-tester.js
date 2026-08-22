import { browserProbeCapability } from './parser.js';

function formatHost(host) {
  return host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
}

function portSuffix(port) {
  return Number(port) === 443 ? '' : `:${Number(port)}`;
}

function wsProbe(cfg, timeoutMs, parentSignal) {
  return new Promise(resolve => {
    const path = cfg.path?.startsWith('/') ? cfg.path : `/${cfg.path || ''}`;
    const url = `wss://${formatHost(cfg.address)}${portSuffix(cfg.port)}${path || '/'}`;
    const started = performance.now();
    let settled = false;
    let opened = false;
    let ws;
    const finish = result => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      parentSignal?.removeEventListener('abort', onAbort);
      try { ws?.close(1000); } catch {}
      resolve(result);
    };
    const onAbort = () => finish({ ok: false, aborted: true, reason: 'Aborted' });
    const timer = setTimeout(() => finish({ ok: false, reason: 'WebSocket timeout' }), timeoutMs);
    if (parentSignal?.aborted) return onAbort();
    parentSignal?.addEventListener('abort', onAbort, { once: true });
    try {
      ws = new WebSocket(url);
      ws.onopen = () => {
        opened = true;
        finish({ ok: true, latency: Math.round(performance.now() - started), probeType: 'websocket' });
      };
      ws.onerror = () => finish({ ok: false, reason: 'WebSocket error' });
      ws.onclose = () => {
        if (!opened) finish({ ok: false, reason: 'WebSocket closed before open' });
      };
    } catch (error) {
      finish({ ok: false, reason: error?.message || 'WebSocket init failed' });
    }
  });
}

async function httpsProbe(cfg, timeoutMs, parentSignal) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(new DOMException('Timeout', 'AbortError')), timeoutMs);
  const onAbort = () => controller.abort(parentSignal?.reason || new DOMException('Aborted', 'AbortError'));
  parentSignal?.addEventListener('abort', onAbort, { once: true });
  const started = performance.now();
  try {
    const url = `https://${formatHost(cfg.address)}${portSuffix(cfg.port)}/?_tt=${Date.now()}`;
    await fetch(url, {
      method: 'HEAD',
      mode: 'no-cors',
      cache: 'no-store',
      redirect: 'follow',
      credentials: 'omit',
      signal: controller.signal
    });
    return { ok: true, latency: Math.round(performance.now() - started), probeType: 'https' };
  } catch (error) {
    if (parentSignal?.aborted) return { ok: false, aborted: true, reason: 'Aborted' };
    if (controller.signal.aborted) return { ok: false, reason: 'HTTPS timeout' };
    return { ok: false, reason: error?.message || 'HTTPS network error' };
  } finally {
    clearTimeout(timeout);
    parentSignal?.removeEventListener('abort', onAbort);
  }
}

async function firstValidSuccess(probes) {
  if (!probes.length) return { ok: false, reason: 'No valid browser probe' };
  const contenders = probes.map(promise => Promise.resolve(promise).then(result => {
    if (result?.ok) return result;
    throw result || { ok: false, reason: 'Probe failed' };
  }));
  try {
    return await Promise.any(contenders);
  } catch (aggregate) {
    const errors = aggregate?.errors || [];
    return errors.find(v => v?.aborted) || errors[0] || { ok: false, reason: 'All probes failed' };
  }
}

export async function quickProbe(cfg, timeoutMs, signal) {
  if (signal?.aborted) return { status: 'pending', latency: null, reason: 'Aborted', testedAt: Date.now() };
  const capability = browserProbeCapability(cfg);
  if (!capability.testable) {
    return {
      status: 'uncertain', latency: null, reason: capability.reason,
      probeType: 'browser-limited', testedAt: Date.now(), score: null
    };
  }
  const probes = [];
  if (cfg.transport === 'ws') probes.push(wsProbe(cfg, timeoutMs, signal));
  probes.push(httpsProbe(cfg, timeoutMs, signal));
  const result = await firstValidSuccess(probes);
  if (result.ok) {
    return {
      status: 'reachable', latency: result.latency,
      reason: 'Endpoint پاسخ داد؛ اتصال واقعی پروکسی هنوز تأیید نشده است',
      probeType: result.probeType, testedAt: Date.now(), score: null
    };
  }
  if (result.aborted) return { status: 'pending', latency: null, reason: 'Aborted', probeType: '', testedAt: Date.now(), score: null };
  return {
    status: 'failed', latency: null, reason: result.reason || 'Valid browser probes failed',
    probeType: cfg.transport === 'ws' ? 'websocket/https' : 'https', testedAt: Date.now(), score: null
  };
}
