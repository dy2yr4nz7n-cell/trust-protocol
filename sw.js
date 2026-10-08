/* TRUST:// service worker — offline shell for the demo.
 * Bump CACHE_VERSION on every change to index.html or engine.js, otherwise an
 * installed app keeps serving the old files (a bug this repo already knows from
 * the scanner app).
 */
const CACHE_VERSION = "trust-cache-v1";
const ASSETS = ["./", "./index.html", "./engine.js", "./manifest.webmanifest"];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE_VERSION).then((c) => c.addAll(ASSETS)));
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE_VERSION).map((k) => caches.delete(k))))
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  if (event.request.method !== "GET") return;
  event.respondWith(
    caches.match(event.request).then((hit) => hit || fetch(event.request))
  );
});
