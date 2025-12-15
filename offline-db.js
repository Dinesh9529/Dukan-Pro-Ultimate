// 1. डेटाबेस खोलें (IndexedDB)
let db;
const request = indexedDB.open("DukanProOfflineDB", 1);

request.onupgradeneeded = function(event) {
    db = event.target.result;
    // 'pending_requests' नाम का स्टोर बनाएं
    if (!db.objectStoreNames.contains("pending_requests")) {
        db.createObjectStore("pending_requests", { keyPath: "id", autoIncrement: true });
    }
};

request.onsuccess = function(event) {
    db = event.target.result;
    console.log("Offline Database Ready ✅");
    // ऐप खुलते ही चेक करें कि क्या कोई पुराना डेटा पेंडिंग है?
    syncOfflineData();
};

// 2. ऑफलाइन डेटा सेव करने का फंक्शन
function saveOfflineRequest(url, method, body) {
    const transaction = db.transaction(["pending_requests"], "readwrite");
    const store = transaction.objectStore("pending_requests");
    const requestData = {
        url: url,
        method: method,
        body: body,
        timestamp: new Date().getTime()
    };
    store.add(requestData);
    showMessage("ऑफलाइन मोड", "⚠️ इंटरनेट नहीं है। डेटा लोकल सेव कर लिया गया है। नेट आते ही यह अपलोड हो जाएगा।", "warning");
}

// 3. डेटा सिंक करने का फंक्शन (जब नेट वापस आए)
async function syncOfflineData() {
    if (!navigator.onLine) return; // अगर अभी भी नेट नहीं है तो रुक जाओ

    const transaction = db.transaction(["pending_requests"], "readwrite");
    const store = transaction.objectStore("pending_requests");
    const getAllRequest = store.getAll();

    getAllRequest.onsuccess = async function() {
        const requests = getAllRequest.result;
        if (requests.length === 0) return; // कुछ भी पेंडिंग नहीं है

        showMessage("Syncing...", `🔄 ${requests.length} ऑफलाइन रिकॉर्ड्स सर्वर पर भेजे जा रहे हैं...`, "info");

        for (const req of requests) {
            try {
                // असली सर्वर कॉल
                await fetchApi(req.url, {
                    method: req.method,
                    body: req.body
                }, null); // लोडर न दिखाएं

                // सफल होने पर लोकल DB से हटा दें
                const deleteTx = db.transaction(["pending_requests"], "readwrite");
                deleteTx.objectStore("pending_requests").delete(req.id);
            } catch (err) {
                console.error("Sync Failed for ID " + req.id, err);
                // अगर फिर फेल हुआ, तो उसे रहने दें, अगली बार कोशिश करेंगे
            }
        }
        showMessage("सफलता", "✅ सारा ऑफलाइन डेटा सिंक हो गया!", "success");
    };
}

// 4. इंटरनेट आने-जाने पर नजर रखें
window.addEventListener('online', syncOfflineData);
window.addEventListener('offline', () => showMessage("चेतावनी", "🔌 इंटरनेट चला गया है। आप काम जारी रख सकते हैं।", "danger"));
