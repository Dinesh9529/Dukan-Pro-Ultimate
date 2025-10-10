// script.js
const RENDER_URL = "https://dukan-pro-ultimate.onrender.com";
const API_BASE_URL = RENDER_URL;

// --- DOM Elements ---
const licenseInputContainer = document.getElementById('license-input-container');
const mainApp = document.getElementById('main-app');
const validateButton = document.getElementById('validate-key-btn');
const licenseKeyInput = document.getElementById('license-key');
const licenseMsgDisplay = document.getElementById('license-msg');
const itemsContainer = document.getElementById('items-container');
const welcomeUserDisplay = document.getElementById('welcome-user');
const expiryNotificationBar = document.getElementById('expiry-notification-bar');

let expiryTimerInterval = null;
let appState = { stock: [], sales: [], purchases: [], customers: [], expenses: [] };

// --- INITIALIZATION ---
document.addEventListener('DOMContentLoaded', () => {
    const savedKey = localStorage.getItem('licenseKey');
    if (savedKey) {
        validateKey(savedKey, true);
    } else {
        licenseInputContainer.classList.remove('d-none');
    }

    validateButton.addEventListener('click', () => validateKey(licenseKeyInput.value.trim(), false));
    
    // Attach event listeners for new forms
    document.getElementById('add-stock-form').addEventListener('submit', handleAddStock);
    document.getElementById('purchase-form').addEventListener('submit', handleAddPurchase);
    document.getElementById('add-customer-form').addEventListener('submit', handleAddCustomer);
    document.getElementById('add-expense-form').addEventListener('submit', handleAddExpense);

    // Event listeners for invoice auto-update
    document.getElementById('shopName').addEventListener('input', updateInvoicePreview);
    document.getElementById('shopGstin').addEventListener('input', updateInvoicePreview);
    document.getElementById('shopAddress').addEventListener('input', updateInvoicePreview);
    document.getElementById('invoice-number').addEventListener('input', updateInvoicePreview);
    document.getElementById('customer-name').addEventListener('input', updateInvoicePreview);
    document.getElementById('notes').addEventListener('input', updateInvoicePreview);
    document.getElementById('shopLogo').addEventListener('change', updateInvoicePreview);
    document.getElementById('qrCode').addEventListener('change', updateInvoicePreview);
});

// --- CORE VALIDATION & DATA LOADING ---
async function validateKey(key, silent = false) {
    if (!key) {
        if (!silent) updateLicenseMessage("कृपया एक लाइसेंस कुंजी दर्ज करें।", true);
        return;
    }
    if (!silent) {
        validateButton.disabled = true;
        validateButton.innerHTML = `<span class="spinner-border spinner-border-sm"></span> जाँच हो रही है...`;
    }
    try {
        const response = await fetch(`${API_BASE_URL}/validate-key`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ key: key }),
        });
        const data = await response.json();
        if (data.isValid) {
            handleValidationSuccess(key, data);
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

function handleValidationSuccess(key, data) {
    localStorage.setItem('licenseKey', key);
    localStorage.setItem('customerName', data.name || 'Customer');
    localStorage.setItem('licenseExpiry', data.expiryDate);

    licenseInputContainer.classList.add('d-none');
    mainApp.classList.remove('d-none');
    welcomeUserDisplay.innerText = `Welcome, ${data.name || 'User'}`;
    
    startExpiryTimer(data.expiryDate);
    loadInitialData();
}

function handleValidationFailure(data, silent) {
    localStorage.clear();
    clearInterval(expiryTimerInterval);
    mainApp.classList.add('d-none');
    licenseInputContainer.classList.remove('d-none');
    if (!silent) {
        updateLicenseMessage(data.message || "अमान्य लाइसेंस कुंजी।", true);
    }
}

async function loadInitialData() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/initial-data`);
        if (!response.ok) throw new Error('Failed to load app data.');
        const data = await response.json();
        appState = data;
        renderAll();
    } catch (error) {
        alert("Error loading data: " + error.message);
    }
}

// --- RENDER FUNCTIONS ---
function renderAll() {
    renderDashboard();
    renderStockTable();
    renderCustomersTable();
    renderExpensesTable();
    addItemRow(); // Add one item row by default in invoice
}

function renderDashboard() {
    const totalSales = appState.sales.reduce((sum, s) => sum + parseFloat(s.totalamount || 0), 0);
    const totalPurchases = appState.purchases.reduce((sum, p) => sum + parseFloat(p.totalamount || 0), 0);
    const totalExpenses = appState.expenses.reduce((sum, e) => sum + parseFloat(e.amount || 0), 0);
    const netProfit = totalSales - totalPurchases - totalExpenses;

    document.getElementById('dash-total-sales').innerText = `₹${totalSales.toFixed(2)}`;
    document.getElementById('dash-total-purchases').innerText = `₹${totalPurchases.toFixed(2)}`;
    document.getElementById('dash-total-expenses').innerText = `₹${totalExpenses.toFixed(2)}`;
    document.getElementById('dash-net-profit').innerText = `₹${netProfit.toFixed(2)}`;
}

function renderStockTable() {
    const body = document.getElementById('stock-table-body');
    body.innerHTML = appState.stock.map(item => `
        <tr><td>${item.sku}</td><td>${item.itemname}</td><td>₹${item.purchaseprice}</td><td>₹${item.saleprice}</td><td>${item.quantity}</td></tr>
    `).join('');
}

function renderCustomersTable() {
    const body = document.getElementById('customers-table-body');
    body.innerHTML = appState.customers.map(c => `
        <tr><td>${c.customerid}</td><td>${c.name}</td><td>${c.phone}</td><td>${c.address}</td></tr>
    `).join('');
    // For autocomplete in invoice
    const dataList = document.getElementById('customer-list');
    dataList.innerHTML = appState.customers.map(c => `<option value="${c.name}">`).join('');
}

function renderExpensesTable() {
    const body = document.getElementById('expenses-table-body');
    body.innerHTML = appState.expenses.map(e => `
        <tr><td>${new Date(e.date).toLocaleDateString()}</td><td>${e.category}</td><td>₹${e.amount}</td><td>${e.description}</td></tr>
    `).join('');
}

// --- FORM HANDLERS ---
async function apiPost(endpoint, data, successMessage) {
    try {
        const response = await fetch(`${API_BASE_URL}${endpoint}`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.message);
        alert(successMessage);
        return true;
    } catch (error) {
        alert(`Error: ${error.message}`);
        return false;
    }
}

async function handleAddStock(e) {
    e.preventDefault();
    const data = {
        sku: e.target.elements['stock-sku'].value,
        itemName: e.target.elements['stock-item-name'].value,
        purchasePrice: e.target.elements['stock-purchase-price'].value,
        salePrice: e.target.elements['stock-sale-price'].value,
        quantity: e.target.elements['stock-quantity'].value
    };
    if (await apiPost('/api/stock', data, 'Stock added successfully!')) {
        e.target.reset();
        bootstrap.Modal.getInstance(document.getElementById('addStockModal')).hide();
        loadInitialData();
    }
}

async function handleAddPurchase(e) {
    e.preventDefault();
    const data = {
        itemName: e.target.elements['purchase-item-name'].value,
        sku: e.target.elements['purchase-item-sku'].value,
        quantity: e.target.elements['purchase-quantity'].value,
        purchasePrice: e.target.elements['purchase-price'].value,
        supplier: e.target.elements['purchase-supplier'].value
    };
    if (await apiPost('/api/purchases', data, 'Purchase logged successfully!')) {
        e.target.reset();
        loadInitialData();
    }
}

async function handleAddCustomer(e) {
    e.preventDefault();
    const data = {
        name: e.target.elements['customer-form-name'].value,
        phone: e.target.elements['customer-form-phone'].value,
        address: e.target.elements['customer-form-address'].value
    };
    if (await apiPost('/api/customers', data, 'Customer added successfully!')) {
        e.target.reset();
        loadInitialData();
    }
}

async function handleAddExpense(e) {
    e.preventDefault();
    const data = {
        category: e.target.elements['expense-category'].value,
        amount: e.target.elements['expense-amount'].value,
        description: e.target.elements['expense-description'].value
    };
    if (await apiPost('/api/expenses', data, 'Expense added successfully!')) {
        e.target.reset();
        loadInitialData();
    }
}

// --- INVOICE LOGIC ---
function addItemRow() {
    const newRow = document.createElement('div');
    newRow.className = 'row g-2 mb-2 item-row';
    newRow.innerHTML = `
        <div class="col-5"><input type="text" class="form-control item-name" list="stock-item-list" placeholder="Item Name"></div>
        <div class="col-2"><input type="number" class="form-control item-quantity" placeholder="Qty" value="1" min="1"></div>
        <div class="col-2"><input type="number" class="form-control item-price" placeholder="Rate" value="0"></div>
        <div class="col-2"><input type="number" class="form-control item-gst" placeholder="GST %" value="0"></div>
        <div class="col-1"><button type="button" class="btn btn-danger btn-sm" onclick="this.closest('.item-row').remove(); updateInvoicePreview();">X</button></div>
    `;
    itemsContainer.appendChild(newRow);
    newRow.querySelector('.item-name').focus();
    // Add event listeners to all inputs in the new row
    newRow.querySelectorAll('input').forEach(input => input.addEventListener('input', updateInvoicePreview));
}

function calculateTotals() {
    let subtotal = 0, totalGst = 0, currentItems = [];
    document.querySelectorAll('.item-row').forEach(row => {
        const name = row.querySelector('.item-name').value;
        const qty = parseFloat(row.querySelector('.item-quantity').value) || 0;
        const rate = parseFloat(row.querySelector('.item-price').value) || 0;
        const gstPercent = parseFloat(row.querySelector('.item-gst').value) || 0;
        if (name && qty && rate) {
            const itemTotal = qty * rate;
            const itemGst = itemTotal * (gstPercent / 100);
            subtotal += itemTotal;
            totalGst += itemGst;
            currentItems.push({ itemName: name, quantity: qty, price: rate, gstRate: gstPercent, total: itemTotal + itemGst });
        }
    });
    const grandTotal = subtotal + totalGst;
    return { subtotal, totalGst, grandTotal, currentItems };
}

async function updateInvoicePreview() {
    const totals = calculateTotals();
    const preview = document.getElementById('invoice-preview');
    
    const logoFile = document.getElementById('shopLogo').files[0];
    const qrFile = document.getElementById('qrCode').files[0];
    const logoUrl = logoFile ? URL.createObjectURL(logoFile) : null;
    const qrUrl = qrFile ? URL.createObjectURL(qrFile) : null;

    const itemRowsHTML = totals.currentItems.map((item, i) => `
        <tr>
            <td>${i + 1}</td>
            <td style="text-align: left;">${item.itemName}</td>
            <td>${item.quantity}</td>
            <td>${item.price.toFixed(2)}</td>
            <td>${item.gstRate}%</td>
            <td>${(item.total).toFixed(2)}</td>
        </tr>`).join('');
    
    preview.innerHTML = `
        <div class="invoice-header">
            <div>
                ${logoUrl ? `<img src="${logoUrl}" alt="Logo" style="max-width: 120px; max-height: 60px; margin-bottom: 10px;">` : ''}
                <h4>${document.getElementById('shopName').value}</h4>
                <p class="mb-0">${document.getElementById('shopAddress').value}</p>
                <p><strong>GSTIN:</strong> ${document.getElementById('shopGstin').value}</p>
            </div>
            <div>
                <h3>INVOICE</h3>
                <p><strong>No:</strong> ${document.getElementById('invoice-number').value}</p>
                <p><strong>Date:</strong> ${new Date().toLocaleDateString()}</p>
            </div>
        </div>
        <p><strong>Bill To:</strong> ${document.getElementById('customer-name').value}</p>
        <table class="invoice-table">
            <thead><tr><th>#</th><th style="text-align: left;">Item</th><th>Qty</th><th>Rate</th><th>GST</th><th>Total (₹)</th></tr></thead>
            <tbody>${itemRowsHTML}</tbody>
        </table>
        <div class="invoice-footer">
            <div class="notes-section">
                <p><strong>Notes:</strong><br>${document.getElementById('notes').value}</p>
                ${qrUrl ? `<img src="${qrUrl}" alt="QR Code" style="width: 100px; height: 100px;">` : ''}
            </div>
            <table class="totals-table">
                <tr><td>Subtotal:</td><td>${totals.subtotal.toFixed(2)}</td></tr>
                <tr><td>Total GST:</td><td>${totals.totalGst.toFixed(2)}</td></tr>
                <tr class="grand-total"><td>GRAND TOTAL:</td><td>₹${totals.grandTotal.toFixed(2)}</td></tr>
            </table>
        </div>`;
}

async function logAndClearInvoice() {
    const totals = calculateTotals();
    if (totals.currentItems.length === 0) {
        alert("Please add at least one item to the invoice.");
        return;
    }
    const data = {
        invoiceNumber: document.getElementById('invoice-number').value,
        customerName: document.getElementById('customer-name').value,
        totalAmount: totals.grandTotal,
        items: totals.currentItems,
    };
    if (await apiPost('/api/sales', data, `Invoice ${data.invoiceNumber} saved!`)) {
        clearBill();
        loadInitialData();
    }
}

function clearBill() {
    const fieldsToClear = ['customer-name', 'notes'];
    fieldsToClear.forEach(id => document.getElementById(id).value = '');
    document.getElementById('items-container').innerHTML = '';
    // Increment invoice number
    let invNum = document.getElementById('invoice-number').value;
    let newInvNum = invNum.replace(/(\d+)$/, (n) => (+n + 1).toString().padStart(n.length, '0'));
    document.getElementById('invoice-number').value = newInvNum;
    addItemRow();
    updateInvoicePreview();
}

function printInvoice() { window.print(); }

function downloadInvoice() {
    const { jsPDF } = window.jspdf;
    const invoice = document.getElementById('invoice-preview');
    const invoiceNumber = document.getElementById('invoice-number').value || 'invoice';
    html2canvas(invoice, { scale: 2 }).then(canvas => {
        const imgData = canvas.toDataURL('image/png');
        const pdf = new jsPDF('p', 'mm', 'a4');
        const pdfWidth = pdf.internal.pageSize.getWidth();
        const pdfHeight = (canvas.height * pdfWidth) / canvas.width;
        pdf.addImage(imgData, 'PNG', 0, 0, pdfWidth, pdfHeight);
        pdf.save(`${invoiceNumber}.pdf`);
    });
}

// --- UTILITY FUNCTIONS ---
function startExpiryTimer(expiryDateISO) {
    const expiryTime = new Date(expiryDateISO).getTime();
    clearInterval(expiryTimerInterval);
    expiryTimerInterval = setInterval(() => {
        const now = new Date().getTime();
        const distance = expiryTime - now;
        const days = Math.floor(distance / (1000 * 60 * 60 * 24));
        const hours = Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
        const minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
        
        expiryNotificationBar.style.display = 'block';
        if (distance < 0) {
            expiryNotificationBar.className = 'alert alert-danger mb-0 text-center fw-bold no-print';
            expiryNotificationBar.innerHTML = 'Your license has expired. Please renew to continue using the app.';
            mainApp.style.pointerEvents = 'none'; // Lock the app
            mainApp.style.opacity = '0.5';
            clearInterval(expiryTimerInterval);
        } else {
            let message = `License expires in: ${days}d ${hours}h ${minutes}m`;
            expiryNotificationBar.className = (days < 7) 
                ? 'alert alert-danger mb-0 text-center fw-bold no-print' 
                : 'alert alert-warning mb-0 text-center fw-bold no-print';
            expiryNotificationBar.innerHTML = `<i class="fas fa-clock me-2"></i>${message}`;
        }
    }, 60000); // Update every minute
}

function updateLicenseMessage(message, isError) {
    licenseMsgDisplay.innerText = message;
    licenseMsgDisplay.className = `mt-3 fw-bold text-center ${isError ? 'text-danger' : 'text-success'}`;
}

function exportToCSV() {
    let csvContent = "data:text/csv;charset=utf-8,";
    // Example for exporting stock
    csvContent += "SKU,Item Name,Purchase Price,Sale Price,Quantity\r\n";
    appState.stock.forEach(item => {
        csvContent += `${item.sku},${item.itemname},${item.purchaseprice},${item.saleprice},${item.quantity}\r\n`;
    });
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", "dukan_pro_stock_export.csv");
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

