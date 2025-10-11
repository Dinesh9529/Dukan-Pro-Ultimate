// script.js (Professional, Corrected & Fully Functional)

const RENDER_URL = "https://dukan-pro-ultimate.onrender.com"; // Your Render.com server URL
const API_BASE_URL = RENDER_URL;

// --- DOM Elements & State ---
const DOM = {
    licenseContainer: document.getElementById('license-input-container'),
    mainApp: document.getElementById('main-app'),
    licenseKeyInput: document.getElementById('license-key'),
    validateBtn: document.getElementById('validate-key-btn'),
    licenseMsg: document.getElementById('license-msg'),
    sidebarLinks: document.querySelectorAll('#sidebar .nav-link'),
    paneContainer: document.getElementById('pane-container'),
    headerTitle: document.getElementById('header-title'),
    welcomeUser: document.getElementById('welcome-user'),
    expiryBar: document.getElementById('expiry-notification-bar'),
    stockModal: new bootstrap.Modal(document.getElementById('stock-modal')),
};

let AppState = {
    stock: [],
    settings: {
        shopName: 'आपकी दुकान का नाम',
        shopAddress: 'आपका पता यहाँ',
        shopGstin: 'आपका GSTIN',
        logoDataUrl: null,
        qrDataUrl: null,
    },
    currentInvoice: {
        items: [],
        customerName: 'ग्राहक',
        notes: 'आपकी खरीदारी के लिए धन्यवाद!'
    }
};

// --- API Helper ---
async function apiCall(endpoint, method = 'GET', body = null) {
    try {
        const options = { method, headers: { 'Content-Type': 'application/json' } };
        if (body) options.body = JSON.stringify(body);
        const response = await fetch(`${API_BASE_URL}${endpoint}`, options);
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || 'Server error');
        return data;
    } catch (error) {
        console.error(`API Call Failed: ${endpoint}`, error);
        alert(`सर्वर से संपर्क करने में विफल: ${error.message}`);
        return null;
    }
}

// --- Initialization & License ---
document.addEventListener('DOMContentLoaded', () => {
    DOM.validateBtn.addEventListener('click', () => handleValidation(false));
    const savedKey = localStorage.getItem('licenseKey');
    if (savedKey) {
        DOM.licenseKeyInput.value = savedKey;
        handleValidation(true);
    }
});

async function handleValidation(silent = false) {
    const key = DOM.licenseKeyInput.value.trim();
    if (!key) {
        if (!silent) showLicenseMessage('कृपया कुंजी दर्ज करें।', true);
        return;
    }
    DOM.validateBtn.disabled = true;
    DOM.validateBtn.innerHTML = `<span class="spinner-border spinner-border-sm"></span> जाँच हो रही है...`;

    const data = await apiCall('/api/validate-key', 'POST', { key });

    if (data && data.valid) {
        localStorage.setItem('licenseKey', key);
        initializeApp(data);
    } else {
        if (!silent) showLicenseMessage(data ? data.message : 'कनेक्शन त्रुटि', true);
        DOM.validateBtn.disabled = false;
        DOM.validateBtn.innerText = 'ऐप सक्रिय करें';
    }
}

function initializeApp(licenseData) {
    DOM.licenseContainer.classList.add('d-none');
    DOM.mainApp.classList.remove('d-none');
    DOM.welcomeUser.innerText = `स्वागत है, ${licenseData.name}!`;
    loadSettings();
    setupNavigation();
    apiCall('/api/stock').then(data => {
        if (data) AppState.stock = data;
        DOM.sidebarLinks[0].click(); // Load initial pane
    });
}

function showLicenseMessage(message, isError) {
    DOM.licenseMsg.textContent = message;
    DOM.licenseMsg.className = `mt-3 fw-bold ${isError ? 'text-danger' : 'text-success'}`;
}

// --- Navigation & Pane Rendering ---
function setupNavigation() {
    DOM.sidebarLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            DOM.sidebarLinks.forEach(l => l.classList.remove('active'));
            link.classList.add('active');
            const paneName = link.getAttribute('data-pane');
            DOM.headerTitle.innerHTML = link.innerHTML;
            renderPane(paneName);
        });
    });
}

function renderPane(paneName) {
    let html = '';
    switch (paneName) {
        case 'dashboard': html = getDashboardHTML(); break;
        case 'invoice': html = getInvoiceHTML(); break;
        case 'stock': html = getStockHTML(); break;
        case 'settings': html = getSettingsHTML(); break;
        default: html = `<h2>Page not found</h2>`;
    }
    DOM.paneContainer.innerHTML = html;
    attachPaneEventListeners(paneName);
}

// --- HTML Templates for Panes ---
function getDashboardHTML() {
    return `<div class="row g-4">
                <div class="col-md-4"><div class="card p-3 text-center stat-card bg-success text-white"><h5>कुल बिक्री</h5><h3 id="dash-total-sales">लोड हो रहा है...</h3></div></div>
                <div class="col-md-4"><div class="card p-3 text-center stat-card bg-primary text-white"><h5>स्टॉक मूल्य</h5><h3 id="dash-stock-value">लोड हो रहा है...</h3></div></div>
            </div>`;
}

function getInvoiceHTML() {
    return `
    <div class="row g-4">
        <div class="col-lg-4 no-print">
            <div class="card">
                <div class="card-body">
                    <h5 class="card-title mb-3">आइटम जोड़ें</h5>
                    <input class="form-control" list="stock-datalist" id="invoice-item-search" placeholder="प्रोडक्ट खोजें...">
                    <datalist id="stock-datalist"></datalist>
                </div>
            </div>
        </div>
        <div class="col-lg-8">
            <div class="d-flex gap-2 mb-3 no-print">
                <button class="btn btn-primary" onclick="downloadInvoicePDF()"><i class="fas fa-file-pdf me-2"></i>PDF डाउनलोड करें</button>
                <button class="btn btn-secondary" onclick="window.print()"><i class="fas fa-print me-2"></i>प्रिंट करें</button>
                <button class="btn btn-success" onclick="recordSale()"><i class="fas fa-save me-2"></i>सेल रिकॉर्ड करें</button>
            </div>
            <div id="invoice-preview-container">
                </div>
        </div>
    </div>`;
}

function getStockHTML() {
    return `
    <div class="card">
        <div class="card-body">
            <div class="d-flex justify-content-between align-items-center mb-3">
                <h5 class="card-title mb-0">स्टॉक मैनेजमेंट</h5>
                <button class="btn btn-primary" onclick="openStockModal()"><i class="fas fa-plus me-2"></i>नया प्रोडक्ट जोड़ें</button>
            </div>
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead><tr><th>SKU</th><th>नाम</th><th>खरीद मूल्य</th><th>बिक्री मूल्य</th><th>मात्रा</th></tr></thead>
                    <tbody id="stock-table-body"></tbody>
                </table>
            </div>
        </div>
    </div>`;
}

function getSettingsHTML() {
    return `
    <div class="card">
        <div class="card-body">
            <h5 class="card-title mb-4">दुकान की सेटिंग्स</h5>
            <div class="row g-3">
                <div class="col-md-6"><label class="form-label">दुकान का नाम</label><input type="text" id="setting-shop-name" class="form-control"></div>
                <div class="col-md-6"><label class="form-label">GSTIN</label><input type="text" id="setting-shop-gstin" class="form-control"></div>
                <div class="col-12"><label class="form-label">पता</label><textarea id="setting-shop-address" class="form-control" rows="2"></textarea></div>
                <div class="col-md-6">
                    <label class="form-label">दुकान का लोगो</label>
                    <input type="file" class="form-control" id="logo-upload" accept="image/*">
                    <img id="logo-preview" class="mt-2" style="max-height: 80px; display: none;">
                </div>
                <div class="col-md-6">
                    <label class="form-label">पेमेंट QR कोड</label>
                    <input type="file" class="form-control" id="qr-upload" accept="image/*">
                    <img id="qr-preview" class="mt-2" style="max-height: 80px; display: none;">
                </div>
            </div>
            <button class="btn btn-primary mt-4" onclick="saveSettings()">सेटिंग्स सेव करें</button>
        </div>
    </div>`;
}

// --- Event Listeners for Dynamic Panes ---
function attachPaneEventListeners(paneName) {
    switch (paneName) {
        case 'dashboard': updateDashboardStats(); break;
        case 'invoice':
            updateStockDatalist();
            updateInvoicePreview();
            document.getElementById('invoice-item-search').addEventListener('change', handleAddItemToInvoice);
            break;
        case 'stock': renderStockTable(); break;
        case 'settings': loadSettingsIntoForm(); break;
    }
}

// --- Dashboard Logic ---
async function updateDashboardStats() {
    const data = await apiCall('/api/dashboard-stats');
    if (data) {
        document.getElementById('dash-total-sales').innerText = `₹${data.totalSales.toFixed(2)}`;
        document.getElementById('dash-stock-value').innerText = `₹${data.stockValue.toFixed(2)}`;
    }
}

// --- Invoice Logic ---
function updateStockDatalist() {
    const datalist = document.getElementById('stock-datalist');
    if (!datalist) return;
    datalist.innerHTML = AppState.stock.map(item => `<option value="${item['Item Name']}" data-id="${item.ID}"></option>`).join('');
}

function handleAddItemToInvoice(e) {
    const selectedOption = Array.from(e.target.list.options).find(opt => opt.value === e.target.value);
    if (selectedOption) {
        const stockId = parseInt(selectedOption.dataset.id);
        const stockItem = AppState.stock.find(item => item.ID === stockId);
        if (stockItem) {
            const existingItem = AppState.currentInvoice.items.find(item => item.id === stockId);
            if(existingItem){
                existingItem.quantity++;
            } else {
                 AppState.currentInvoice.items.push({
                    id: stockItem.ID,
                    name: stockItem['Item Name'],
                    quantity: 1,
                    price: parseFloat(stockItem['Sale Price']),
                    gstPercent: 0,
                });
            }
            updateInvoicePreview();
        }
    }
    e.target.value = ''; // Clear input
}

function updateInvoiceItem(index, field, value) {
    const item = AppState.currentInvoice.items[index];
    if (field === 'quantity' || field === 'price' || field === 'gstPercent') {
        item[field] = parseFloat(value) || 0;
    }
    updateInvoicePreview();
}

function removeInvoiceItem(index) {
    AppState.currentInvoice.items.splice(index, 1);
    updateInvoicePreview();
}

function updateInvoicePreview() {
    const container = document.getElementById('invoice-preview-container');
    if (!container) return;

    let subtotal = 0;
    let totalCgst = 0;
    let totalSgst = 0;

    const itemsHTML = AppState.currentInvoice.items.map((item, index) => {
        const taxableAmount = item.quantity * item.price;
        const gstAmount = taxableAmount * item.gstPercent / 100;
        totalCgst += gstAmount / 2;
        totalSgst += gstAmount / 2;
        subtotal += taxableAmount;
        const finalAmount = taxableAmount + gstAmount;

        return `<tr>
            <td>${index + 1}</td>
            <td class="text-start">${item.name}</td>
            <td><input type="number" class="form-control form-control-sm" value="${item.quantity}" oninput="updateInvoiceItem(${index}, 'quantity', this.value)"></td>
            <td><input type="number" class="form-control form-control-sm" value="${item.price.toFixed(2)}" oninput="updateInvoiceItem(${index}, 'price', this.value)"></td>
            <td><input type="number" class="form-control form-control-sm" value="${item.gstPercent}" oninput="updateInvoiceItem(${index}, 'gstPercent', this.value)">%</td>
            <td>₹${finalAmount.toFixed(2)}</td>
            <td><button class="btn btn-sm btn-danger" onclick="removeInvoiceItem(${index})"><i class="fa fa-times"></i></button></td>
        </tr>`;
    }).join('') || `<tr><td colspan="7" class="text-center p-4">कोई आइटम नहीं जोड़ा गया है</td></tr>`;
    
    const grandTotal = subtotal + totalCgst + totalSgst;
    const logoImg = AppState.settings.logoDataUrl ? `<img src="${AppState.settings.logoDataUrl}" alt="Shop Logo">` : '';
    const qrImg = AppState.settings.qrDataUrl ? `<img src="${AppState.settings.qrDataUrl}" alt="Payment QR">` : '';

    container.innerHTML = `
        <div class="invoice-header">
            <div class="shop-logo">${logoImg}</div>
            <div class="shop-details">
                <h3>${AppState.settings.shopName}</h3>
                <p>${AppState.settings.shopAddress}</p>
                <p><strong>GSTIN:</strong> ${AppState.settings.shopGstin}</p>
            </div>
            <div class="invoice-meta">
                <h2>INVOICE</h2>
                <p><strong>Invoice #:</strong> INV-${Date.now().toString().slice(-6)}</p>
                <p><strong>Date:</strong> ${new Date().toLocaleDateString('hi-IN')}</p>
            </div>
        </div>
        <div class="customer-details">
             <input type="text" class="form-control" placeholder="ग्राहक का नाम" value="${AppState.currentInvoice.customerName}" oninput="AppState.currentInvoice.customerName=this.value">
        </div>
        <table class="table invoice-table">
            <thead><tr><th>#</th><th class="text-start">आइटम</th><th>मात्रा</th><th>दर</th><th>GST</th><th>कुल</th><th></th></tr></thead>
            <tbody>${itemsHTML}</tbody>
        </table>
        <div class="invoice-summary">
            <div class="notes-and-qr">
                <h6>नोट्स:</h6>
                <textarea class="form-control" oninput="AppState.currentInvoice.notes=this.value">${AppState.currentInvoice.notes}</textarea>
                <div class="mt-3">${qrImg}</div>
            </div>
            <table class="table totals-table">
                <tr><td>Subtotal:</td><td class="text-end">₹${subtotal.toFixed(2)}</td></tr>
                <tr><td>CGST:</td><td class="text-end">+ ₹${totalCgst.toFixed(2)}</td></tr>
                <tr><td>SGST:</td><td class="text-end">+ ₹${totalSgst.toFixed(2)}</td></tr>
                <tr class="grand-total"><td>Grand Total:</td><td class="text-end">₹${grandTotal.toFixed(2)}</td></tr>
            </table>
        </div>
        <div class="invoice-footer">यह एक कंप्यूटर जनित चालान है।</div>
    `;
}

function downloadInvoicePDF() {
    const invoice = document.getElementById('invoice-preview-container');
    html2canvas(invoice, { scale: 2 }).then(canvas => {
        const imgData = canvas.toDataURL('image/png');
        const { jsPDF } = window.jspdf;
        const pdf = new jsPDF('p', 'mm', 'a4');
        const pdfWidth = pdf.internal.pageSize.getWidth();
        const pdfHeight = (canvas.height * pdfWidth) / canvas.width;
        pdf.addImage(imgData, 'PNG', 0, 0, pdfWidth, pdfHeight);
        pdf.save(`invoice-${Date.now()}.pdf`);
    });
}

async function recordSale() {
    if(AppState.currentInvoice.items.length === 0) {
        alert("कृपया बिल में कम से कम एक आइटम जोड़ें।");
        return;
    }
    // Calculate final totals before sending
    let subtotal = 0, totalTax = 0;
    AppState.currentInvoice.items.forEach(item => {
        const taxableAmount = item.quantity * item.price;
        totalTax += taxableAmount * item.gstPercent / 100;
        subtotal += taxableAmount;
    });
    const grandTotal = subtotal + totalTax;

    const saleData = {
        invoice_number: `INV-${Date.now().toString().slice(-6)}`,
        customer_name: AppState.currentInvoice.customerName,
        total_amount: grandTotal,
        total_tax: totalTax,
        items: AppState.currentInvoice.items
    };

    const result = await apiCall('/api/sales', 'POST', saleData);
    if(result && result.success) {
        alert("सेल सफलतापूर्वक रिकॉर्ड हो गई!");
        AppState.currentInvoice.items = []; // Clear items
        updateInvoicePreview();
        // Refresh stock data
        const data = await apiCall('/api/stock');
        if (data) AppState.stock = data;
    }
}

// --- Stock Logic ---
function renderStockTable() {
    const tbody = document.getElementById('stock-table-body');
    if (!tbody) return;
    tbody.innerHTML = AppState.stock.map(item => `
        <tr>
            <td>${item.SKU || ''}</td>
            <td>${item['Item Name']}</td>
            <td>₹${parseFloat(item['Purchase Price']).toFixed(2)}</td>
            <td>₹${parseFloat(item['Sale Price']).toFixed(2)}</td>
            <td class="fw-bold ${item.Quantity <= 10 ? 'text-danger' : ''}">${item.Quantity}</td>
        </tr>
    `).join('');
}

function openStockModal() {
    document.getElementById('stock-form').reset();
    document.getElementById('stock-id').value = '';
    document.getElementById('stock-modal-title').innerText = 'नया प्रोडक्ट जोड़ें';
    document.getElementById('save-stock-btn').onclick = handleSaveStock;
    DOM.stockModal.show();
}

async function handleSaveStock() {
    const data = {
        name: document.getElementById('stock-item-name').value,
        sku: document.getElementById('stock-sku').value,
        purchase_price: document.getElementById('stock-purchase-price').value,
        sale_price: document.getElementById('stock-sale-price').value,
        quantity: document.getElementById('stock-quantity').value
    };
    if(!data.name || !data.purchase_price || !data.sale_price || !data.quantity) {
        alert("कृपया सभी * चिह्नित फ़ील्ड भरें।");
        return;
    }
    const result = await apiCall('/api/stock', 'POST', data);
    if(result) {
        AppState.stock.push(result);
        renderStockTable();
        DOM.stockModal.hide();
    }
}

// --- Settings Logic ---
function saveSettings() {
    AppState.settings.shopName = document.getElementById('setting-shop-name').value;
    AppState.settings.shopAddress = document.getElementById('setting-shop-address').value;
    AppState.settings.shopGstin = document.getElementById('setting-shop-gstin').value;
    localStorage.setItem('dukanProSettings', JSON.stringify(AppState.settings));
    alert('सेटिंग्स सेव हो गईं!');
}

function loadSettings() {
    const saved = localStorage.getItem('dukanProSettings');
    if (saved) {
        AppState.settings = JSON.parse(saved);
    }
}

function loadSettingsIntoForm() {
    document.getElementById('setting-shop-name').value = AppState.settings.shopName;
    document.getElementById('setting-shop-address').value = AppState.settings.shopAddress;
    document.getElementById('setting-shop-gstin').value = AppState.settings.shopGstin;
    
    const logoPreview = document.getElementById('logo-preview');
    if (AppState.settings.logoDataUrl) {
        logoPreview.src = AppState.settings.logoDataUrl;
        logoPreview.style.display = 'block';
    }
    document.getElementById('logo-upload').addEventListener('change', (e) => handleFileUpload(e, 'logoDataUrl', 'logo-preview'));

    const qrPreview = document.getElementById('qr-preview');
    if (AppState.settings.qrDataUrl) {
        qrPreview.src = AppState.settings.qrDataUrl;
        qrPreview.style.display = 'block';
    }
    document.getElementById('qr-upload').addEventListener('change', (e) => handleFileUpload(e, 'qrDataUrl', 'qr-preview'));
}

function handleFileUpload(event, settingKey, previewId) {
    const file = event.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
        AppState.settings[settingKey] = e.target.result;
        document.getElementById(previewId).src = e.target.result;
        document.getElementById(previewId).style.display = 'block';
    };
    reader.readAsDataURL(file);
}
