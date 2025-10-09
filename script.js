// script.js
const RENDER_URL = "https://dukan-pro.onrender.com"; // 💡 यहाँ अपने Render Service का URL डालें
const API_BASE_URL = RENDER_URL;

// --- DOM Elements ---
const licenseInputContainer = document.getElementById('license-input-container');
const mainApp = document.getElementById('main-app');
const validateButton = document.getElementById('validate-key-btn');
const licenseKeyInput = document.getElementById('license-key');
const licenseMsgDisplay = document.getElementById('license-msg');
const itemsContainer = document.getElementById('items-container');
const finalTotalDisplay = document.getElementById('final-total');
const welcomeUserDisplay = document.getElementById('welcome-user');
const notificationBar = document.getElementById('notification-bar');
const stockTableBody = document.getElementById('stock-table-body');
const addStockForm = document.getElementById('add-stock-form');
const purchaseForm = document.getElementById('purchase-form');
const addStockModal = new bootstrap.Modal(document.getElementById('addStockModal'));

let currentItems = [];
let trialTimerInterval = null;
let appState = {
    stock: [],
    sales: [],
    purchases: [],
};

// --- INITIALIZATION ---
document.addEventListener('DOMContentLoaded', () => {
    const savedKey = localStorage.getItem('licenseKey');
    if (savedKey) {
        validateKey(savedKey, true);
    } else {
        licenseInputContainer.classList.remove('d-none');
        licenseInputContainer.classList.add('d-flex');
        mainApp.classList.add('d-none');
    }
});

if (validateButton) {
    validateButton.addEventListener('click', () => {
        const key = licenseKeyInput.value.trim();
        validateKey(key, false);
    });
}

// Attach event listeners for new forms
addStockForm.addEventListener('submit', handleAddStock);
purchaseForm.addEventListener('submit', handleAddPurchase);


// --- CORE VALIDATION LOGIC (UNCHANGED) ---
async function validateKey(key, silent = false) {
    if (!key) {
        if (!silent) updateLicenseMessage("कृपया एक लाइसेंस कुंजी दर्ज करें।", true);
        return;
    }
    if (!silent) {
        updateLicenseMessage('कुंजी की जाँच हो रही है...', false);
        validateButton.disabled = true;
        validateButton.innerHTML = `<span class="spinner-border spinner-border-sm"></span> जाँच हो रही है...`;
    }
    try {
        const response = await fetch(`${API_BASE_URL}/validate-key`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ key: key }),
        });
        const data = await response.json();
        if (data.isValid) {
            handleValidationSuccess(key, data, silent);
        } else {
            handleValidationFailure(data, silent);
        }
    } catch (error) {
        handleValidationFailure({ message: `सर्वर से कनेक्ट नहीं हो सका: ${error.message}` }, silent);
    } finally {
        if (!silent) {
            validateButton.disabled = false;
            validateButton.innerText = 'ऐप सक्रिय करें';
        }
    }
}

function handleValidationSuccess(key, data, silent) {
    localStorage.setItem('licenseKey', key);
    localStorage.setItem('customerName', data.name || 'Customer');

    if (data.expiryDate) {
        const expiryTime = new Date(data.expiryDate).getTime();
        localStorage.setItem('trialExpiry', expiryTime);
        startTrialTimer();
    } else {
        localStorage.removeItem('trialExpiry');
        clearInterval(trialTimerInterval);
        notificationBar.innerHTML = `✅ लाइसेंस स्थायी रूप से सक्रिय है।`;
        notificationBar.style.display = 'block';
    }

    licenseInputContainer.classList.add('d-none');
    mainApp.classList.remove('d-none');
    const userName = data.name || 'User';
    if (welcomeUserDisplay) welcomeUserDisplay.innerText = `Welcome, ${userName}`;
    if (document.getElementById('header-title')) document.getElementById('header-title').innerText = `Dukan Pro (User: ${userName})`;

    // Load all initial data after successful login
    loadInitialData();
}

function handleValidationFailure(data, silent) {
    localStorage.removeItem('licenseKey');
    localStorage.removeItem('trialExpiry');
    localStorage.removeItem('customerName');
    clearInterval(trialTimerInterval);
    mainApp.classList.add('d-none');
    licenseInputContainer.classList.remove('d-none');
    licenseInputContainer.classList.add('d-flex');
    if (notificationBar) notificationBar.style.display = 'none';
    if (!silent) {
        const errorMessage = data.message || "अमान्य लाइसेंस कुंजी।";
        updateLicenseMessage(errorMessage, true);
    }
}

// --- NEW: Data Loading and Rendering ---
async function loadInitialData() {
    await fetchStock();
    await fetchDashboardData(); // Fetch dashboard data which includes sales and purchases
    renderAll();
}

async function fetchStock() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/stock`);
        if (!response.ok) throw new Error('Network response was not ok');
        appState.stock = await response.json();
    } catch (error) {
        console.error("Failed to fetch stock:", error);
        alert("स्टॉक डेटा लोड करने में विफल।");
    }
}

async function fetchDashboardData() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/dashboard-data`);
        if (!response.ok) throw new Error('Network response was not ok');
        const data = await response.json();
        appState.sales = data.sales;
        appState.purchases = data.purchases;
    } catch (error) {
        console.error("Failed to fetch dashboard data:", error);
        alert("डैशबोर्ड डेटा लोड करने में विफल।");
    }
}

function renderAll() {
    renderStockTable();
    renderDashboard();
}

function renderStockTable() {
    stockTableBody.innerHTML = '';
    if (appState.stock.length === 0) {
        stockTableBody.innerHTML = '<tr><td colspan="6" class="text-center">कोई स्टॉक आइटम नहीं मिला।</td></tr>';
        return;
    }
    appState.stock.forEach(item => {
        const row = `
            <tr>
                <td>${item.sku}</td>
                <td>${item.itemname}</td>
                <td>₹${parseFloat(item.purchaseprice).toFixed(2)}</td>
                <td>₹${parseFloat(item.saleprice).toFixed(2)}</td>
                <td>${item.quantity}</td>
                <td>${new Date(item.lastupdated).toLocaleString()}</td>
            </tr>
        `;
        stockTableBody.innerHTML += row;
    });
}

function renderDashboard() {
    const totalSales = appState.sales.reduce((sum, sale) => sum + parseFloat(sale.totalamount), 0);
    const totalPurchases = appState.purchases.reduce((sum, p) => sum + parseFloat(p.totalamount), 0);
    const estimatedProfit = totalSales - totalPurchases;
    const stockValue = appState.stock.reduce((sum, item) => sum + (parseFloat(item.purchaseprice) * parseInt(item.quantity)), 0);

    document.getElementById('dash-total-sales').innerText = `₹${totalSales.toFixed(2)}`;
    document.getElementById('dash-total-purchases').innerText = `₹${totalPurchases.toFixed(2)}`;
    document.getElementById('dash-estimated-profit').innerText = `₹${estimatedProfit.toFixed(2)}`;
    document.getElementById('dash-stock-value').innerText = `₹${stockValue.toFixed(2)}`;

    document.getElementById('pl-sales').innerText = `₹${totalSales.toFixed(2)}`;
    document.getElementById('pl-purchases').innerText = `- ₹${totalPurchases.toFixed(2)}`;
    document.getElementById('pl-profit').innerText = `₹${estimatedProfit.toFixed(2)}`;

    document.getElementById('bs-stock').innerText = `₹${stockValue.toFixed(2)}`;
    document.getElementById('bs-total-assets').innerText = `₹${stockValue.toFixed(2)}`;
}

// --- NEW: Form Handlers ---
async function handleAddStock(event) {
    event.preventDefault();
    const stockData = {
        sku: document.getElementById('stock-sku').value,
        itemName: document.getElementById('stock-item-name').value,
        purchasePrice: document.getElementById('stock-purchase-price').value,
        salePrice: document.getElementById('stock-sale-price').value,
        quantity: document.getElementById('stock-quantity').value
    };

    try {
        const response = await fetch(`${API_BASE_URL}/api/stock`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(stockData),
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.message);
        
        alert(result.message);
        addStockForm.reset();
        addStockModal.hide();
        await fetchStock();
        renderStockTable();
    } catch (error) {
        console.error("Failed to add stock:", error);
        alert(`Error: ${error.message}`);
    }
}

async function handleAddPurchase(event) {
    event.preventDefault();
    const purchaseData = {
        itemName: document.getElementById('purchase-item-name').value,
        sku: document.getElementById('purchase-item-sku').value,
        quantity: document.getElementById('purchase-quantity').value,
        purchasePrice: document.getElementById('purchase-price').value,
        supplier: document.getElementById('purchase-supplier').value,
    };

    try {
        const response = await fetch(`${API_BASE_URL}/api/purchases`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(purchaseData),
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.message);

        alert(result.message);
        purchaseForm.reset();
        await loadInitialData(); // Reload all data as purchase affects stock and dashboard
    } catch (error) {
        console.error("Failed to add purchase:", error);
        alert(`Error: ${error.message}`);
    }
}

// --- UI & Message Helpers ---
function updateLicenseMessage(message, isError = false) {
    if (licenseMsgDisplay) {
        licenseMsgDisplay.innerText = message;
        licenseMsgDisplay.className = `mt-3 fw-bold text-center ${isError ? 'text-danger' : 'text-success'}`;
    }
}

// --- POS Functionality (MODIFIED for stock deduction) ---
async function logAndClearInvoice() {
    const invoiceData = {
        invoiceNumber: document.getElementById('invoice-number').value,
        customerName: document.getElementById('customer-name').value,
        totalAmount: calculateTotal(),
        items: currentItems,
        date: new Date().toISOString()
    };
    
    if (invoiceData.items.length === 0) {
        alert("कृपया बिल में कम से कम एक आइटम जोड़ें।");
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/api/sales`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(invoiceData)
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.message);
        
        alert(`Invoice ${invoiceData.invoiceNumber} सफलतापूर्वक सेव हो गया!`);
        await loadInitialData(); // Reload data to reflect stock changes and new sale
        clearBill();
    } catch (error) {
        console.error("Failed to log invoice:", error);
        alert(`Error: ${error.message}`);
    }
}


function addItemRow() {
    if (!itemsContainer) return;
    const newRow = document.createElement('div');
    newRow.className = 'row g-2 mb-2 item-row';
    newRow.innerHTML = `
        <div class="col-4"><input type="text" class="form-control item-name" placeholder="आइटम का नाम/विवरण" oninput="updateAll()"></div>
        <div class="col-2"><input type="number" class="form-control item-quantity" placeholder="Qty" value="1" min="1" oninput="updateAll()"></div>
        <div class="col-2"><input type="number" class="form-control item-price" placeholder="Rate" value="0" min="0" oninput="updateAll()"></div>
        <div class="col-2"><input type="number" class="form-control item-gst" placeholder="GST %" value="0" min="0" oninput="updateAll()"></div>
        <div class="col-2 d-flex align-items-center"><button type="button" class="btn btn-danger btn-sm" onclick="removeItemRow(this)">X</button></div>
    `;
    itemsContainer.appendChild(newRow);
    updateAll();
}

function removeItemRow(button) {
    button.closest('.item-row').remove();
    updateAll();
}

function updateAll() {
    calculateTotal();
    updateInvoicePreview();
}

function calculateTotal() {
    let subtotalBeforeTax = 0;
    let totalTax = 0;
    currentItems = [];

    const itemRows = itemsContainer ? itemsContainer.querySelectorAll('.item-row') : [];
    itemRows.forEach(row => {
        const name = row.querySelector('.item-name')?.value || '';
        const qty = parseInt(row.querySelector('.item-quantity')?.value) || 0;
        const price = parseFloat(row.querySelector('.item-price')?.value) || 0.0;
        const gstRate = parseFloat(row.querySelector('.item-gst')?.value) || 0.0;
        
        const taxableAmount = qty * price;
        const itemTax = taxableAmount * (gstRate / 100);
        
        subtotalBeforeTax += taxableAmount;
        totalTax += itemTax;
        
        currentItems.push({
            itemName: name,
            quantity: qty,
            price: price,
            gstRate: gstRate,
            total: taxableAmount + itemTax
        });
    });

    const globalDiscountRate = parseFloat(document.getElementById('globalDiscount')?.value) || 0;
    let globalDiscount = subtotalBeforeTax * (globalDiscountRate / 100);
    let totalAfterGlobalDiscount = subtotalBeforeTax - globalDiscount + totalTax;
    const roundOffValue = parseFloat(document.getElementById('roundOff')?.value) || 0.00;
    let finalTotal = totalAfterGlobalDiscount + roundOffValue;
    
    window.invoiceTotals = { subtotalBeforeTax, globalDiscount, totalTax, roundOffValue, finalTotal };
    if (finalTotalDisplay) finalTotalDisplay.innerText = finalTotal.toFixed(2);
    return finalTotal.toFixed(2);
}

function updateInvoicePreview() {
    const totals = window.invoiceTotals || {};
    const previewElement = document.getElementById('invoice-preview');
    if (!previewElement) return;

    const shopName = document.getElementById('shopName')?.value || 'आपकी दुकान का नाम';
    const customerName = document.getElementById('customer-name')?.value || 'ग्राहक (Walk-in)';
    const invoiceNumber = document.getElementById('invoice-number')?.value || 'INV-0000';
    const notes = document.getElementById('notes')?.value || 'बिक्री का सामान वापस नहीं लिया जाएगा।';
    
    let itemRowsHTML = currentItems.map((item, index) => {
        if (!item.itemName.trim() && item.quantity === 0) return '';
        return `
            <tr>
                <td>${index + 1}</td>
                <td style="text-align: left;">${item.itemName}</td>
                <td style="text-align: center;">${item.quantity}</td>
                <td>₹${item.price.toFixed(2)}</td>
                <td>${item.gstRate.toFixed(1)}%</td>
                <td>₹${item.total.toFixed(2)}</td>
            </tr>
        `;
    }).join('');
    
    previewElement.innerHTML = `
        <div class="invoice-header"> ... </div>
        <table class="invoice-table">
            <thead>
                <tr><th>S.No</th><th>Item Name</th><th>Qty</th><th>Rate</th><th>GST</th><th>Total</th></tr>
            </thead>
            <tbody>${itemRowsHTML}</tbody>
        </table>
        <div class="invoice-footer">
            <div class="terms"><small><strong>Notes:</strong> ${notes}</small></div>
            <table class="totals-table">
                <tr><td>Subtotal:</td><td>₹${(totals.subtotalBeforeTax || 0).toFixed(2)}</td></tr>
                <tr><td>Discount:</td><td>- ₹${(totals.globalDiscount || 0).toFixed(2)}</td></tr>
                <tr><td>GST:</td><td>+ ₹${(totals.totalTax || 0).toFixed(2)}</td></tr>
                <tr><td>Round Off:</td><td>± ₹${(totals.roundOffValue || 0).toFixed(2)}</td></tr>
                <tr class="fw-bold"><td>Grand Total:</td><td>₹${(totals.finalTotal || 0).toFixed(2)}</td></tr>
            </table>
        </div>
    `;
}

function clearBill() {
    document.getElementById('customer-name').value = '';
    document.getElementById('globalDiscount').value = '0';
    document.getElementById('roundOff').value = '0.00';
    itemsContainer.innerHTML = '';
    addItemRow();
    updateAll();
}

function printInvoice() { window.print(); }
function handleQrCodeUpload() { /* Implement QR upload logic if needed */ }
function startTrialTimer() { /* Implement trial timer UI if needed */ }