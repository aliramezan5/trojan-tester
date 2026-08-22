const DB_NAME = 'trojan-tester-v11';
const DB_VERSION = 1;
const STORES = { settings: 'settings', cache: 'cache', history: 'history' };

function openDb() {
  return new Promise((resolve, reject) => {
    if (!('indexedDB' in globalThis)) return reject(new Error('IndexedDB unavailable'));
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORES.settings)) db.createObjectStore(STORES.settings);
      if (!db.objectStoreNames.contains(STORES.cache)) db.createObjectStore(STORES.cache);
      if (!db.objectStoreNames.contains(STORES.history)) db.createObjectStore(STORES.history, { keyPath: 'id' });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error('IndexedDB open failed'));
  });
}

function reqP(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error('IndexedDB request failed'));
  });
}

export async function getSetting(key, fallback = null) {
  try {
    const db = await openDb();
    const tx = db.transaction(STORES.settings, 'readonly');
    const value = await reqP(tx.objectStore(STORES.settings).get(key));
    db.close();
    return value ?? fallback;
  } catch {
    try {
      const raw = localStorage.getItem(`tt-setting:${key}`);
      return raw == null ? fallback : JSON.parse(raw);
    } catch { return fallback; }
  }
}

export async function setSetting(key, value) {
  try {
    const db = await openDb();
    const tx = db.transaction(STORES.settings, 'readwrite');
    tx.objectStore(STORES.settings).put(value, key);
    await new Promise((resolve, reject) => { tx.oncomplete = resolve; tx.onerror = () => reject(tx.error); tx.onabort = () => reject(tx.error); });
    db.close();
  } catch {
    try { localStorage.setItem(`tt-setting:${key}`, JSON.stringify(value)); } catch {}
  }
}

export async function deleteSetting(key) {
  try {
    const db = await openDb();
    const tx = db.transaction(STORES.settings, 'readwrite');
    tx.objectStore(STORES.settings).delete(key);
    await new Promise(resolve => { tx.oncomplete = resolve; tx.onerror = resolve; tx.onabort = resolve; });
    db.close();
  } catch {}
  try { localStorage.removeItem(`tt-setting:${key}`); } catch {}
}

const TTL = { verified: 30 * 60_000, reachable: 30 * 60_000, failed: 10 * 60_000, uncertain: 0 };

export async function getCachedResult(fingerprintId) {
  if (!fingerprintId) return null;
  try {
    const db = await openDb();
    const tx = db.transaction(STORES.cache, 'readonly');
    const entry = await reqP(tx.objectStore(STORES.cache).get(fingerprintId));
    db.close();
    if (!entry) return null;
    const ttl = TTL[entry.status] ?? 0;
    if (!ttl || Date.now() - entry.testedAt > ttl) return null;
    return entry;
  } catch { return null; }
}

export async function putCachedResult(fingerprintId, result) {
  if (!fingerprintId || !result || result.status === 'uncertain') return;
  const entry = {
    status: result.status, latency: result.latency ?? null, reason: result.reason || '',
    probeType: result.probeType || '', score: result.score ?? null,
    verification: result.verification || null, testedAt: result.testedAt || Date.now()
  };
  try {
    const db = await openDb();
    const tx = db.transaction(STORES.cache, 'readwrite');
    tx.objectStore(STORES.cache).put(entry, fingerprintId);
    await new Promise(resolve => { tx.oncomplete = resolve; tx.onerror = resolve; tx.onabort = resolve; });
    db.close();
  } catch {}
}

export async function clearCache() {
  try {
    const db = await openDb();
    const tx = db.transaction(STORES.cache, 'readwrite');
    tx.objectStore(STORES.cache).clear();
    await new Promise(resolve => { tx.oncomplete = resolve; tx.onerror = resolve; tx.onabort = resolve; });
    db.close();
  } catch {}
}

export async function addHistoryRun(run) {
  const entry = { ...run, id: run.id || `${Date.now()}-${Math.random().toString(36).slice(2, 8)}` };
  try {
    const db = await openDb();
    const tx = db.transaction(STORES.history, 'readwrite');
    tx.objectStore(STORES.history).put(entry);
    await new Promise(resolve => { tx.oncomplete = resolve; tx.onerror = resolve; tx.onabort = resolve; });
    db.close();
    await trimHistory(50);
  } catch {}
}

export async function getHistoryRuns(limit = 20) {
  try {
    const db = await openDb();
    const tx = db.transaction(STORES.history, 'readonly');
    const all = await reqP(tx.objectStore(STORES.history).getAll());
    db.close();
    return (all || []).sort((a, b) => (b.startedAt || 0) - (a.startedAt || 0)).slice(0, limit);
  } catch { return []; }
}

async function trimHistory(limit) {
  const all = await getHistoryRuns(500);
  if (all.length <= limit) return;
  const remove = all.slice(limit);
  try {
    const db = await openDb();
    const tx = db.transaction(STORES.history, 'readwrite');
    const store = tx.objectStore(STORES.history);
    remove.forEach(item => store.delete(item.id));
    await new Promise(resolve => { tx.oncomplete = resolve; tx.onerror = resolve; tx.onabort = resolve; });
    db.close();
  } catch {}
}
