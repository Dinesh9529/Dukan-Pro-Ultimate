const CACHE_NAME = 'dukan-pro-offline-v2'; // वर्जन बदल दिया ताकि अपडेट हो जाए

const ASSETS_TO_CACHE = [
    '/',
    '/index.html',
    '/garments.html',      // ✅ अब Garments भी ऑफलाइन चलेगा
    '/manifest.json',      // (अगर है तो)
    
    // --- जरुरी डिजाईन फाइल्स ---
    'https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css',
    'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css',
    'https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js',
    
    // --- जरुरी टूल्स (बिलिंग और अलर्ट के लिए) ---
    'https://cdn.jsdelivr.net/npm/chart.js',
    'https://cdn.jsdelivr.net/npm/sweetalert2@11', // ✅ अलर्ट के लिए
    'https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js', // ✅ PDF बिल के लिए
    'https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js'
];

// 1. इंस्टॉल: सारी फाइलें डाउनलोड करके सेव करो
self.addEventListener('install', (event) => {
    console.log('👷 Service Worker: Installing...');
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => {
            console.log('📦 Caching all App files');
            return cache.addAll(ASSETS_TO_CACHE);
        })
    );
});

// 2. एक्टिवेट: पुराना कचरा (Old Cache) साफ़ करो
self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((keyList) => {
            return Promise.all(keyList.map((key) => {
                if (key !== CACHE_NAME) {
                    console.log('🧹 Removing old cache:', key);
                    return caches.delete(key);
                }
            }));
        })
    );
    return self.clients.claim();
});

// 3. फेच: नेट हो तो नेट से, नहीं तो कैश (Cache) से चलाओ
self.addEventListener('fetch', (event) => {
    // API कॉल्स को मत छेड़ो (इन्हें लाइव सर्वर पर जाने दो)
    if (event.request.url.includes('/api/')) {
        return; 
    }

    event.respondWith(
        caches.match(event.request).then((response) => {
            // अगर फाइल कैश में मिली, तो वहीं से दे दो (Super Fast)
            if (response) {
                return response;
            }
            // नहीं तो इंटरनेट से लाओ
            return fetch(event.request).catch(() => {
                // अगर नेट भी नहीं है और फाइल भी नहीं है (Error)
                console.log("❌ Offline: File not found in cache -> " + event.request.url);
            });
        })
    );
});
