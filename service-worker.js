const CACHE='trojan-tester-v11-20260822-3';
const APP=['./','./index.html','./styles/app.css','./styles/v11-extra.css','./src/main.js','./src/parser.js','./src/quick-tester.js','./src/scheduler.js','./src/storage.js','./vendor/qrcode.js','./manifest.webmanifest','./icons/icon.svg','./icons/icon-192.png','./icons/icon-512.png'];
self.addEventListener('install',e=>e.waitUntil(caches.open(CACHE).then(c=>c.addAll(APP)).then(()=>self.skipWaiting())));
self.addEventListener('activate',e=>e.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim())));
self.addEventListener('fetch',e=>{const u=new URL(e.request.url);if(e.request.method!=='GET'||u.origin!==location.origin)return;e.respondWith((async()=>{try{const fresh=await fetch(e.request);if(fresh.ok){const c=await caches.open(CACHE);c.put(e.request,fresh.clone())}return fresh}catch{return (await caches.match(e.request))||caches.match('./index.html')}})())});
