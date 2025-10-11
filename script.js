// script.js
// RENDER URL UPDATED FOR NEW SERVICE
const RENDER_URL = "https://dukan-pro-ultimate.onrender.com";
const API_BASE_URL = RENDER_URL;

// --- DOM Elements ---
const licenseInputContainer = document.getElementById('license-input-container');
// FIX: Corrected the main app container ID
const mainApp = document.getElementById('main-app'); 
const validateButton = document.getElementById('validate-key-btn');
const licenseKeyInput = document.getElementById('license-key');
const licenseMsgDisplay = document.getElementById('license-msg');
const itemsContainer = document.getElementById('items-container');
const welcomeUserDisplay = document.getElementById('welcome-user');
const expiryNotificationBar = document.getElementById('expiry-notification-bar');
const invoicePreviewDiv = document.getElementById('invoice-preview');

let expiryTimerInterval = null;
let appState = { stock: [], sales: [], purchases: [], customers: [], expenses: [] };

// --- HELPER FUNCTION: PostgreSQL Key Transformation ---
// This is important to convert DB columns like "Item Name" to JS-friendly keys like "itemname"
function transformDataKeys(data) {
    if (!Array.isArray(data)) return data;
    return data.map(item => {
        const newItem = {};
        for (const key in item) {
            if (item.hasOwnProperty(key)) {
                let newKey = key.replace(/\s+/g, '').toLowerCase();
                if (key === "Item Name") newKey = "itemname";
                if (key === "Purchase Price") newKey = "purchaseprice";
                if (key === "Sale Price") newKey = "saleprice";
                if (key === "Last Updated") newKey = "lastupdated";
                if (key === "Date Added") newKey = "dateadded";
                if (key === "Total Value") newKey = "totalvalue";
                if (key === "Invoice Number") newKey = "invoicenumber";
                if (key === "Customer Name") newKey = "customername";
                if (key === "Total Amount") newKey = "totalamount";
                if (key === "Total Tax") newKey = "totaltax";
                newItem[newKey] = item[key];
            }
        }
        return newItem;
    });
}

// --- API CALLS ---
async function fetchData(sheetName, autoLoad = false) {
    try {
        const response = await fetch(`${API_BASE_URL}/api/data/${sheetName}`);
        if (!response.ok) throw new Error(`Failed to fetch ${sheetName}.`);
        
        const data = await response.json();
        const transformedData = transformDataKeys(data);

        appState[sheetName.toLowerCase()] = transformedData;

        // Auto-render data if needed
        if (autoLoad) {
            if (sheetName === 'Stock') renderStockTable();
            if (sheetName === 'Expenses') renderExpensesTable();
            // Add other render calls as needed
        }
        updateDashboard(); // Update dashboard on any data fetch
    } catch (error) {
        console.error(`Error fetching ${sheetName}:`, error);
        if (!autoLoad) alert(`डेटा लोड करने में विफल: ${sheetName}`);
    }
}

async function handleAddStock(event) {
    event.preventDefault();
    const sku = document.getElementById('stock-sku').value.trim();
    const itemName = document.getElementById('stock-item-name').value.trim();
    const purchasePrice = parseFloat(document.getElementById('stock-purchase-price').value);
    const salePrice = parseFloat(document.getElementById('stock-sale-price').value);
    const quantity = parseInt(document.getElementById('stock-quantity').value);

    if (!sku || !itemName || isNaN(purchasePrice) || isNaN(salePrice) || isNaN(quantity)) {
        alert("Please fill all fields correctly.");
        return;
    }

    const body = { sku, itemName, purchasePrice, salePrice, quantity };

    try {
        const response = await fetch(`${API_BASE_URL}/api/stock`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        if (response.ok) {
            alert('स्टॉक सफलतापूर्वक अपडेट किया गया!');
            document.getElementById('add-stock-form').reset();
            const modal = bootstrap.Modal.getInstance(document.getElementById('addStockModal'));
            modal.hide();
            await fetchData('Stock', true);
        } else {
            const errorData = await response.json();
            alert(`स्टॉक अपडेट विफल: ${errorData.message}`);
        }
    } catch (error) {
        alert('नेटवर्क एरर। स्टॉक अपडेट नहीं हो सका।');
        console.error("Stock API Error:", error);
    }
}

async function handleAddExpense(event) {
    event.preventDefault();
    const category = document.getElementById('expense-category').value;
    const amount = parseFloat(document.getElementById('expense-amount').value);
    const description = document.getElementById('expense-description').value;

    const body = { category, amount, description };

    try {
        const response = await fetch(`${API_BASE_URL}/api/expenses`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        if (response.ok) {
            alert('खर्चा सफलतापूर्वक दर्ज किया गया!');
            document.getElementById('add-expense-form').reset();
            const modal = bootstrap.Modal.getInstance(document.getElementById('addExpenseModal'));
            modal.hide();
            await fetchData('Expenses', true);
        } else {
            const errorData = await response.json();
            alert(`खर्चा दर्ज विफल: ${errorData.message}`);
        }
    } catch (error) {
        alert('नेटवर्क एरर। खर्चा दर्ज नहीं हो सका।');
        console.error("Expense API Error:", error);
    }
}

// --- UI RENDERING & LOGIC ---

function renderStockTable() {
    const stockTableBody = document.getElementById('stock-table-body');
    if (!stockTableBody) return;
    stockTableBody.innerHTML = '';
    
    appState.stock.forEach(item => {
        const row = stockTableBody.insertRow();
        row.innerHTML = `
            <td>${item.sku}</td>
            <td>${item.itemname}</td>
            <td>₹${parseFloat(item.purchaseprice).toFixed(2)}</td>
            <td>₹${parseFloat(item.saleprice).toFixed(2)}</td>
            <td class="fw-bold ${item.quantity <= 10 ? 'text-danger' : ''}">${item.quantity}</td>
            <td>${new Date(item.lastupdated).toLocaleString('hi-IN')}</td>
        `;
    });
}

function renderExpensesTable() {
    const expenseTableBody = document.getElementById('expense-table-body');
    if (!expenseTableBody) return;
    expenseTableBody.innerHTML = '';
    
    const sortedExpenses = [...appState.expenses].sort((a, b) => new Date(b.date) - new Date(a.date));

    sortedExpenses.forEach(exp => {
        const row = expenseTableBody.insertRow();
        row.innerHTML = `
            <td>${new Date(exp.date).toLocaleDateString('hi-IN')}</td>
            <td>${exp.category || 'Other'}</td>
            <td>₹${parseFloat(exp.amount).toFixed(2)}</td>
            <td>${exp.description || 'N/A'}</td>
        `;
    });
}

function updateDashboard() {
    const totalSales = appState.sales.reduce((sum, sale) => sum + parseFloat(sale.totalamount), 0);
    const totalPurchases = appState.purchases.reduce((sum, pur) => sum + parseFloat(pur.totalvalue), 0);
    const totalExpenses = appState.expenses.reduce((sum, exp) => sum + parseFloat(exp.amount), 0);
    
    // Simple profit calculation (Sales - Expenses)
    // A more accurate calculation would involve cost of goods sold (COGS)
    const netProfit = totalSales - totalExpenses;

    document.getElementById('dash-total-sales').innerText = `₹${totalSales.toFixed(2)}`;
    document.getElementById('dash-total-purchases').innerText = `₹${totalPurchases.toFixed(2)}`;
    document.getElementById('dash-total-expenses').innerText = `₹${totalExpenses.toFixed(2)}`;
    document.getElementById('dash-net-profit').innerText = `₹${netProfit.toFixed(2)}`;
}

// --- INVOICE SPECIFIC FUNCTIONS (Placeholder/Simplified) ---
function addItemRow() { alert('This feature is under development.'); }
function printInvoice() { window.print(); }
function downloadInvoice() { alert('This feature is under development.'); }
function clearBill() { 
    document.getElementById('customer-name').value = '';
    document.getElementById('items-container').innerHTML = '';
    generateInvoicePreview(); // Update preview to be empty
    alert('Bill cleared.');
}

// FIX: New function to handle Save & New logic
async function logAndClearInvoice() {
    // This function needs to be fully implemented
    // 1. Collect all items from the items-container
    // 2. Calculate totals
    // 3. Call a function similar to handleRecordSale from your old code
    // 4. On success, call clearBill()
    alert('"Save & New" feature is under development.');
}

function generateInvoicePreview() {
    const template = document.getElementById('invoice-template');
    const clone = template.content.cloneNode(true);
    
    // Update basic details
    clone.getElementById('inv-shop-name').innerText = document.getElementById('shopName').value;
    clone.getElementById('inv-shop-address').innerText = document.getElementById('shopAddress').value;
    clone.querySelector('.gstin-val').innerText = document.getElementById('shopGstin').value;
    clone.getElementById('inv-number').innerText = document.getElementById('invoice-number').value;
    clone.getElementById('inv-date').innerText = new Date().toLocaleDateString('hi-IN');
    clone.getElementById('inv-customer-name').innerText = document.getElementById('customer-name').value || "Guest Customer";
    clone.getElementById('inv-notes').innerText = document.getElementById('notes').value;
    clone.getElementById('inv-shop-signature').innerText = document.getElementById('shopName').value;
    
    // Clear previous preview and append new one
    invoicePreviewDiv.innerHTML = '';
    invoicePreviewDiv.appendChild(clone);
}


// --- LICENSE VALIDATION LOGIC ---

async function validateKey(key, silent = false) {
    if (!key) return;
    if (!silent) updateLicenseMessage('Validating key...', false);
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/validate-key`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ key })
        });
        const result = await response.json();

        if (result.valid) {
            // FIX: Use `result.name` instead of `result.user`
            if (!silent) updateLicenseMessage(`Activation successful! Welcome, ${result.name}.`, false);
            localStorage.setItem('licenseKey', key);
            activateApp(result.name, result.expiry);
        } else {
            if (!silent) updateLicenseMessage(result.message, true);
            deactivateApp();
        }
    } catch (error) {
        if (!silent) updateLicenseMessage('Network error. Could not reach activation server.', true);
        console.error("Validation Error:", error);
        deactivateApp();
    }
}

function activateApp(userName, expiryDateString) {
    licenseInputContainer.classList.add('d-none');
    mainApp.classList.remove('d-none');
    welcomeUserDisplay.innerText = `Welcome, ${userName}!`;
    
    // Load all data after activation
    Promise.all([
        fetchData('Stock', true),
        fetchData('Customers'),
        fetchData('Sales'),
        fetchData('Purchases'),
        fetchData('Expenses', true)
    ]).then(() => {
        console.log("All initial data loaded.");
        generateInvoicePreview(); // Generate initial empty invoice
    });
    
    startExpiryTimer(expiryDateString);
}

function deactivateApp() {
    mainApp.classList.add('d-none');
    licenseInputContainer.classList.remove('d-none');
    localStorage.removeItem('licenseKey');
    if (expiryTimerInterval) clearInterval(expiryTimerInterval);
}

function startExpiryTimer(expiryDateString) {
    const expiryDate = new Date(expiryDateString);
    expiryNotificationBar.style.display = 'block';

    const checkExpiry = () => {
        const now = new Date();
        const diff = expiryDate - now;
        const days = Math.floor(diff / (1000 * 60 * 60 * 24));
        
        if (diff < 0) {
            expiryNotificationBar.innerHTML = `<i class="fas fa-exclamation-triangle me-2"></i>License Expired. Please renew.`;
            expiryNotificationBar.className = 'alert alert-danger mb-0 text-center fw-bold no-print';
            mainApp.style.pointerEvents = 'none';
            mainApp.style.opacity = '0.5';
            clearInterval(expiryTimerInterval);
        } else {
            let message = `License expires in ${days} day(s).`;
            expiryNotificationBar.className = (days < 7) 
                ? 'alert alert-danger mb-0 text-center fw-bold no-print' 
                : 'alert alert-warning mb-0 text-center fw-bold no-print';
            expiryNotificationBar.innerHTML = `<i class="fas fa-clock me-2"></i>${message}`;
        }
    };
    
    checkExpiry();
    if (expiryTimerInterval) clearInterval(expiryTimerInterval);
    expiryTimerInterval = setInterval(checkExpiry, 60 * 60 * 1000); // Check every hour
}

function updateLicenseMessage(message, isError) {
    licenseMsgDisplay.innerText = message;
    licenseMsgDisplay.className = `mt-3 fw-bold text-center ${isError ? 'text-danger' : 'text-success'}`;
}

function exportToCSV() {
    let csvContent = "data:text/csv;charset=utf-8,";
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


// --- INITIALIZATION ---
document.addEventListener('DOMContentLoaded', () => {
    // Check for saved key on load
    const savedKey = localStorage.getItem('licenseKey');
    if (savedKey) {
        validateKey(savedKey, true);
    } else {
        licenseInputContainer.classList.remove('d-none');
    }

    validateButton.addEventListener('click', () => validateKey(licenseKeyInput.value.trim()));
    
    // Attach form submit listeners safely
    document.getElementById('add-stock-form')?.addEventListener('submit', handleAddStock);
    document.getElementById('add-expense-form')?.addEventListener('submit', handleAddExpense);
    document.getElementById('export-stock-btn')?.addEventListener('click', exportToCSV);
    
    // Attach listeners to invoice form inputs to update preview live
    const invoiceInputs = ['shopName', 'shopAddress', 'shopGstin', 'invoice-number', 'customer-name', 'notes'];
    invoiceInputs.forEach(id => {
        document.getElementById(id)?.addEventListener('input', generateInvoicePreview);
    });
    
    // Handle tab switching to update header title and fetch data
    document.querySelectorAll('#main-tabs .nav-link').forEach(tab => {
        tab.addEventListener('click', (e) => {
            const headerTitle = document.getElementById('header-title');
            headerTitle.innerHTML = e.target.innerHTML; // Set header title to tab content
            
            // Fetch data when a tab is shown for the first time
            const targetPaneId = e.target.getAttribute('data-bs-target');
            if (targetPaneId === '#stock-pane') fetchData('Stock', true);
            if (targetPaneId === '#expenses-pane') fetchData('Expenses', true);
        });
    });
});
