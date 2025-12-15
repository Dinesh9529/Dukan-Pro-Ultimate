const CACHE_NAME = 'dukan-pro-offline-v1';
const ASSETS_TO_CACHE = [
    '/',
    '/index.html', // अपनी HTML फाइल का सही नाम यहाँ लिखें
    'https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css',
    'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css',
    'https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js',
    'https://cdn.jsdelivr.net/npm/chart.js'
];

// 1. इंस्टॉल होते ही फाइलों को सेव (Cache) कर लो
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => {
            console.log('Opened cache');
            return cache.addAll(ASSETS_TO_CACHE);
        })
    );
});

// 2. जब इंटरनेट न हो, तो सेव की हुई फाइलें दिखाओ
self.addEventListener('fetch', (event) => {
    // API कॉल्स को नेटवर्क पर ही जाने दें (इन्हें हम अलग से हैंडल करेंगे)
    if (event.request.url.includes('/api/')) {
        return; 
    }

    event.respondWith(
        caches.match(event.request).then((response) => {
            return response || fetch(event.request);
        })
    );
});
