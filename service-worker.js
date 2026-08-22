const CACHE = 'trojan-tester-v1.1.0';
const REQUIRED_SHELL = [
  './',
  './index.html',
  './styles/app.css',
  './src/main.js',
  './src/parser.js',
  './src/quick-tester.js',
  './src/scheduler.js',
  './src/storage.js',
  './manifest.webmanifest',
  './icons/icon-192.png',
  './icons/icon-512.png'
];
const OPTIONAL_SHELL = ['./vendor/qrcode.js'];

self.addEventListener('install', event => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE);
    await cache.addAll(REQUIRED_SHELL);
    await Promise.allSettled(OPTIONAL_SHELL.map(asset => cache.add(asset)));
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(key => key !== CACHE).map(key => caches.delete(key))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', event => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin || url.pathname.includes('/api/')) return;
  event.respondWith(
    caches.match(req).then(cached => cached || fetch(req).then(response => {
      if (response.ok && response.type === 'basic') {
        const copy = response.clone();
        caches.open(CACHE).then(cache => cache.put(req, copy));
      }
      return response;
    }))
  );
});
