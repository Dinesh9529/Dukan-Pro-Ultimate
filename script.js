// script.js
// RENDER URL UPDATED FOR NEW SERVICE
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
let appState = { stock: [], sales: [], purchases: [], customers: [], expenses: [], cart: [] };

// --- HELPER FUNCTION: PostgreSQL Key Transformation ---
// This function converts PostgreSQL column names (e.g., "Item Name")
// to the lowercase keys expected by the frontend (e.g., "itemname").
function transformDataKeys(data) {
    if (!Array.isArray(data)) return data;
    
    return data.map(item => {
        const newItem = {};
        for (const key in item) {
            if (item.hasOwnProperty(key)) {
                // Default conversion to lowercase, removing spaces
                let newKey = key.replace(/\s+/g, '').toLowerCase();
                
                // Specific mappings for complex keys used by the frontend
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
        if (!response.ok) throw new Error('Failed to fetch data.');
        
        const data = await response.json();
        const transformedData = transformDataKeys(data); // Apply transformation

        if (sheetName === 'Stock') {
            appState.stock = transformedData;
            if (autoLoad) renderStock();
        } else if (sheetName === 'Customers') {
            appState.customers = transformedData;
        } else if (sheetName === 'Sales') {
            appState.sales = transformedData;
            if (autoLoad) renderInvoices(); // Render invoices after fetching sales
        } else if (sheetName === 'Purchases') {
            appState.purchases = transformedData;
        } else if (sheetName === 'Expenses') {
            appState.expenses = transformedData;
            if (autoLoad) renderExpenses();
        }

    } catch (error) {
        console.error(`Error fetching ${sheetName}:`, error);
        if (!autoLoad) alert(`डेटा लोड करने में विफल: ${sheetName}`);
    }
}

async function handleAddStock(event) {
    event.preventDefault();
    const sku = document.getElementById('stock-sku').value;
    const itemName = document.getElementById('stock-item-name').value;
    const purchasePrice = parseFloat(document.getElementById('stock-purchase-price').value);
    const salePrice = parseFloat(document.getElementById('stock-sale-price').value);
    const quantity = parseInt(document.getElementById('stock-quantity').value);

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

async function handleAddCustomer(event) {
    event.preventDefault();
    const id = document.getElementById('customer-id').value.trim();
    const name = document.getElementById('customer-name').value.trim();
    const phone = document.getElementById('customer-phone').value.trim();
    const address = document.getElementById('customer-address').value.trim();

    const body = { id, name, phone, address };

    try {
        const response = await fetch(`${API_BASE_URL}/api/customers`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        if (response.ok) {
            alert('ग्राहक सफलतापूर्वक जोड़ा/अपडेट किया गया!');
            document.getElementById('add-customer-form').reset();
            const modal = bootstrap.Modal.getInstance(document.getElementById('addCustomerModal'));
            modal.hide();
            await fetchData('Customers');
        } else {
            const errorData = await response.json();
            alert(`ग्राहक अपडेट विफल: ${errorData.message}`);
        }
    } catch (error) {
        alert('नेटवर्क एरर। ग्राहक अपडेट नहीं हो सका।');
        console.error("Customer API Error:", error);
    }
}

async function handleAddPurchase(event) {
    event.preventDefault();
    const sku = document.getElementById('purchase-sku').value;
    const itemName = document.getElementById('purchase-item-name').value;
    const quantity = parseInt(document.getElementById('purchase-quantity').value);
    const purchasePrice = parseFloat(document.getElementById('purchase-price').value);
    const totalValue = quantity * purchasePrice;
    const supplier = document.getElementById('purchase-supplier').value;

    const stockBody = { sku, itemName, purchasePrice, salePrice: 0, quantity: quantity }; 
    const purchaseBody = { sku, itemName, quantity, purchasePrice, totalValue, supplier };

    try {
        // 1. Update Stock (will use ON CONFLICT in server.js)
        const stockResponse = await fetch(`${API_BASE_URL}/api/stock`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(stockBody)
        });

        if (!stockResponse.ok) {
            const errorData = await stockResponse.json();
            throw new Error(`स्टॉक अपडेट विफल: ${errorData.message}`);
        }

        // 2. Add Purchase Record
        const purchaseResponse = await fetch(`${API_BASE_URL}/api/purchases`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(purchaseBody)
        });

        if (!purchaseResponse.ok) {
            const errorData = await purchaseResponse.json();
            throw new Error(`खरीद रिकॉर्ड विफल: ${errorData.message}`);
        }

        alert('खरीद और स्टॉक सफलतापूर्वक अपडेट किए गए!');
        document.getElementById('purchase-form').reset();
        const modal = bootstrap.Modal.getInstance(document.getElementById('addPurchaseModal'));
        modal.hide();
        await fetchData('Stock', true); 
        await fetchData('Purchases'); 

    } catch (error) {
        alert(`त्रुटि: ${error.message}`);
        console.error("Purchase/Stock Error:", error);
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

async function handleRecordSale(invoiceNumber, customerName, totalAmount, totalTax, cartItems) {
    const saleBody = {
        invoiceNumber,
        customerName,
        totalAmount,
        totalTax,
        items: cartItems.map(item => ({ 
            sku: item.sku, 
            itemName: item.itemname, 
            quantity: item.quantity, 
            salePrice: item.saleprice 
        }))
    };

    try {
        // 1. Record Sale
        const saleResponse = await fetch(`${API_BASE_URL}/api/sales`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(saleBody)
        });

        if (!saleResponse.ok) {
            const errorData = await saleResponse.json();
            throw new Error(`बिक्री रिकॉर्ड विफल: ${errorData.message}`);
        }
        
        // 2. Stock Deduction (Simple logic: decrease stock quantity for each item)
        // Send negative quantity to the stock endpoint for deduction
        
        for (const item of cartItems) {
            const stockDeductionBody = { 
                sku: item.sku, 
                itemName: item.itemname, 
                purchasePrice: item.purchaseprice, // Must send original data
                salePrice: item.saleprice,     // Must send original data
                quantity: -item.quantity // Send negative quantity to deduct
            };
            await fetch(`${API_BASE_URL}/api/stock`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(stockDeductionBody)
            });
        }


        alert(`बिक्री (${invoiceNumber}) सफलतापूर्वक दर्ज की गई!`);
        appState.cart = []; // Clear cart after successful sale
        renderCart(); 
        await fetchData('Sales', true); // Refresh sales and invoices
        await fetchData('Stock', true); // Refresh stock display

    } catch (error) {
        alert(`बिक्री रिकॉर्ड करते समय त्रुटि: ${error.message}`);
        console.error("Sale Record Error:", error);
    }
}


// --- UI RENDERING & LOGIC ---

function renderStock() {
    itemsContainer.innerHTML = '';
    const search = document.getElementById('search-item').value.toLowerCase();
    
    appState.stock.filter(item => 
        (item.sku && item.sku.toLowerCase().includes(search)) || 
        (item.itemname && item.itemname.toLowerCase().includes(search))
    ).forEach(item => {
        const card = document.createElement('div');
        card.className = 'col-md-3 mb-4';
        card.innerHTML = `
            <div class="card h-100 shadow-sm item-card" data-sku="${item.sku}">
                <div class="card-body">
                    <h5 class="card-title text-primary">${item.itemname}</h5>
                    <p class="card-text mb-1">SKU: ${item.sku}</p>
                    <p class="card-text mb-1 text-success">Price: ₹${parseFloat(item.saleprice).toFixed(2)}</p>
                    <p class="card-text fw-bold ${item.quantity <= 10 ? 'text-danger' : 'text-success'}">Stock: ${item.quantity}</p>
                    <button class="btn btn-sm btn-outline-primary w-100 add-to-cart-btn" data-sku="${item.sku}">कार्ट में जोड़ें</button>
                </div>
            </div>
        `;
        itemsContainer.appendChild(card);
    });
}

function renderCart() {
    const cartItemsList = document.getElementById('cart-items-list');
    const cartTotalDisplay = document.getElementById('cart-total');
    cartItemsList.innerHTML = '';
    let total = 0;
    
    appState.cart.forEach((item, index) => {
        const itemTotal = item.saleprice * item.quantity;
        total += itemTotal;

        const li = document.createElement('li');
        li.className = 'list-group-item d-flex justify-content-between align-items-center';
        li.innerHTML = `
            <div>
                ${item.itemname} (${item.sku}) <br>
                <small class="text-muted">₹${parseFloat(item.saleprice).toFixed(2)} x ${item.quantity}</small>
            </div>
            <span class="badge bg-primary rounded-pill">₹${itemTotal.toFixed(2)}</span>
            <button class="btn btn-sm btn-danger remove-item-btn" data-index="${index}"><i class="fas fa-trash"></i></button>
        `;
        cartItemsList.appendChild(li);
    });

    cartTotalDisplay.innerText = `₹${total.toFixed(2)}`;
    document.getElementById('checkout-btn').disabled = appState.cart.length === 0;
}

function renderInvoices() {
    const invoiceTableBody = document.getElementById('invoice-table-body');
    invoiceTableBody.innerHTML = '';

    // Sort sales by date descending
    const sortedSales = [...appState.sales].sort((a, b) => {
        return new Date(b.date) - new Date(a.date);
    });

    sortedSales.forEach(sale => {
        const row = invoiceTableBody.insertRow();
        row.insertCell().textContent = sale.invoicenumber || 'N/A';
        row.insertCell().textContent = sale.customername || 'N/A';
        row.insertCell().textContent = `₹${parseFloat(sale.totalamount).toFixed(2)}`;
        row.insertCell().textContent = new Date(sale.date).toLocaleDateString('hi-IN');
        
        const actionCell = row.insertCell();
        const viewBtn = document.createElement('button');
        viewBtn.className = 'btn btn-sm btn-info';
        viewBtn.textContent = 'देखें';
        viewBtn.addEventListener('click', () => viewInvoice(sale));
        actionCell.appendChild(viewBtn);
    });
}

// Function to handle showing the detailed invoice modal
function viewInvoice(sale) {
    // PostgreSQL stores items as a JSON string
    const items = typeof sale.items === 'string' ? JSON.parse(sale.items) : sale.items;
    
    let itemsHtml = items.map(item => `
        <tr>
            <td>${item.itemName || item.itemname}</td>
            <td class="text-end">${item.quantity}</td>
            <td class="text-end">₹${parseFloat(item.salePrice || item.saleprice).toFixed(2)}</td>
            <td class="text-end">₹${(item.quantity * parseFloat(item.salePrice || item.saleprice)).toFixed(2)}</td>
        </tr>
    `).join('');

    document.getElementById('invoice-preview-details').innerHTML = `
        <div class="invoice-header">
            <div>
                <h3 class="text-primary">INVOICE</h3>
                <p>Date: ${new Date(sale.date).toLocaleDateString('hi-IN')}</p>
                <p>Invoice No: ${sale.invoicenumber}</p>
            </div>
            <div>
                <h4>Customer</h4>
                <p>${sale.customername || 'Cash Customer'}</p>
            </div>
        </div>

        <table class="invoice-table">
            <thead>
                <tr><th>Item</th><th class="text-end">Qty</th><th class="text-end">Price</th><th class="text-end">Total</th></tr>
            </thead>
            <tbody>${itemsHtml}</tbody>
        </table>

        <div class="invoice-footer">
            <div class="totals-left">
                <p class="fw-bold">Tax: ₹${parseFloat(sale.totaltax).toFixed(2)}</p>
            </div>
            <div class="totals-right">
                <h4 class="text-primary">Grand Total: ₹${parseFloat(sale.totalamount).toFixed(2)}</h4>
            </div>
        </div>
    `;

    const invoiceModal = new bootstrap.Modal(document.getElementById('invoiceModal'));
    invoiceModal.show();
}

function renderExpenses() {
    const expenseTableBody = document.getElementById('expense-table-body');
    expenseTableBody.innerHTML = '';

    const sortedExpenses = [...appState.expenses].sort((a, b) => {
        return new Date(b.date) - new Date(a.date);
    });

    sortedExpenses.forEach(exp => {
        const row = expenseTableBody.insertRow();
        row.insertCell().textContent = new Date(exp.date).toLocaleDateString('hi-IN');
        row.insertCell().textContent = exp.category || 'Other';
        row.insertCell().textContent = `₹${parseFloat(exp.amount).toFixed(2)}`;
        row.insertCell().textContent = exp.description || 'N/A';
    });
}

function getUniqueInvoiceNumber() {
    const now = new Date();
    const datePart = now.getFullYear().toString().slice(2) + 
                     (now.getMonth() + 1).toString().padStart(2, '0') + 
                     now.getDate().toString().padStart(2, '0');
    // Find the max sequence number for today
    const salesToday = appState.sales.filter(sale => 
        new Date(sale.date).toLocaleDateString() === now.toLocaleDateString()
    );
    let maxSequence = 0;
    salesToday.forEach(sale => {
        const parts = (sale.invoicenumber || "").split('-');
        if (parts.length === 2 && !isNaN(parseInt(parts[1]))) {
            maxSequence = Math.max(maxSequence, parseInt(parts[1]));
        }
    });
    const sequence = (maxSequence + 1).toString().padStart(3, '0');
    return `${datePart}-${sequence}`;
}

function handleAddToCart(sku) {
    const stockItem = appState.stock.find(item => item.sku === sku);
    if (!stockItem || stockItem.quantity <= 0) {
        alert("यह आइटम स्टॉक में नहीं है।");
        return;
    }

    const cartItem = appState.cart.find(item => item.sku === sku);

    if (cartItem) {
        if (cartItem.quantity < stockItem.quantity) {
            cartItem.quantity++;
        } else {
            alert("अधिकतम स्टॉक मात्रा तक पहुँच गया।");
            return;
        }
    } else {
        // Find the full item details from stock for adding to cart
        const fullItem = { ...stockItem, quantity: 1 };
        appState.cart.push(fullItem);
    }
    renderCart();
}

function handleRemoveFromCart(index) {
    appState.cart.splice(index, 1);
    renderCart();
}

function handleCheckout() {
    if (appState.cart.length === 0) {
        alert("कृपया पहले कार्ट में आइटम जोड़ें।");
        return;
    }

    const invoiceNumber = getUniqueInvoiceNumber();
    const customerName = prompt("Enter Customer Name (Optional, leave blank for Cash):") || "Cash Customer";
    let totalAmount = appState.cart.reduce((sum, item) => sum + (item.saleprice * item.quantity), 0);
    let totalTax = 0; // Keeping tax at 0 for simplicity

    // Confirm checkout
    const confirmation = confirm(`Confirm sale for Invoice ${invoiceNumber}:\nCustomer: ${customerName}\nTotal: ₹${totalAmount.toFixed(2)}`);

    if (confirmation) {
        handleRecordSale(invoiceNumber, customerName, totalAmount, totalTax, appState.cart);
    }
}

// --- LICENSE VALIDATION LOGIC ---

async function validateKey(key, silent = false) {
    if (!silent) updateLicenseMessage('Key validating...', false);
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/validate-key`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ key })
        });
        
        const result = await response.json();

        if (result.valid) {
            if (!silent) updateLicenseMessage(`Activation successful! Welcome, ${result.user}.`, false);
            localStorage.setItem('licenseKey', key);
            activateApp(result.user, result.expiry);
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
    fetchData('Stock', true); 
    fetchData('Customers');
    fetchData('Sales', true); 
    fetchData('Purchases');
    fetchData('Expenses', true); 
    
    startExpiryTimer(expiryDateString);
}

function deactivateApp() {
    mainApp.classList.add('d-none');
    licenseInputContainer.classList.remove('d-none');
    mainApp.style.pointerEvents = 'none'; 
    mainApp.style.opacity = '0.5';
    localStorage.removeItem('licenseKey');
    if (expiryTimerInterval) clearInterval(expiryTimerInterval);
}

function startExpiryTimer(expiryDateString) {
    const expiryDate = new Date(expiryDateString);
    
    const checkExpiry = () => {
        const now = new Date();
        const diff = expiryDate - now;
        
        const days = Math.floor(diff / (1000 * 60 * 60 * 24));
        const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
        const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
        
        if (diff < 0) {
            expiryNotificationBar.innerHTML = `<i class="fas fa-exclamation-triangle me-2"></i>License Expired. Please renew your license key to continue using the app.`;
            expiryNotificationBar.className = 'alert alert-danger mb-0 text-center fw-bold no-print';
            mainApp.style.pointerEvents = 'none';
            mainApp.style.opacity = '0.5';
            clearInterval(expiryTimerInterval);
        } else {
            let message = `License expires in: ${days}d ${hours}h ${minutes}m`;
            expiryNotificationBar.className = (days < 7) 
                ? 'alert alert-danger mb-0 text-center fw-bold no-print' 
                : 'alert alert-warning mb-0 text-center fw-bold no-print';
            expiryNotificationBar.innerHTML = `<i class="fas fa-clock me-2"></i>${message}`;
        }
    };
    
    checkExpiry();
    if (expiryTimerInterval) clearInterval(expiryTimerInterval);
    expiryTimerInterval = setInterval(checkExpiry, 60000);
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


// --- INITIALIZATION (Safeguarded) ---
document.addEventListener('DOMContentLoaded', () => {
    const savedKey = localStorage.getItem('licenseKey');
    if (savedKey) {
        validateKey(savedKey, true);
    } else {
        licenseInputContainer.classList.remove('d-none');
    }

    validateButton.addEventListener('click', () => validateKey(licenseKeyInput.value.trim(), false));
    
    // Attach event listeners for forms (using safe check 'el && el.addEventListener')
    const addStockForm = document.getElementById('add-stock-form');
    addStockForm && addStockForm.addEventListener('submit', handleAddStock);
    
    const purchaseForm = document.getElementById('purchase-form');
    purchaseForm && purchaseForm.addEventListener('submit', handleAddPurchase);
    
    const addCustomerForm = document.getElementById('add-customer-form');
    addCustomerForm && addCustomerForm.addEventListener('submit', handleAddCustomer);
    
    const addExpenseForm = document.getElementById('add-expense-form');
    addExpenseForm && addExpenseForm.addEventListener('submit', handleAddExpense);
    
    // Attach event listener for search
    const searchItem = document.getElementById('search-item');
    searchItem && searchItem.addEventListener('input', renderStock);
    
    // Attach event listener for export
    const exportStockBtn = document.getElementById('export-stock-btn');
    exportStockBtn && exportStockBtn.addEventListener('click', exportToCSV);
    
    // Attach event listeners for navigation
    document.getElementById('stock-tab-btn') && document.getElementById('stock-tab-btn').addEventListener('click', () => fetchData('Stock', true));
    document.getElementById('invoice-tab-btn') && document.getElementById('invoice-tab-btn').addEventListener('click', () => fetchData('Sales', true));
    document.getElementById('purchase-tab-btn') && document.getElementById('purchase-tab-btn').addEventListener('click', () => fetchData('Purchases'));
    document.getElementById('customer-tab-btn') && document.getElementById('customer-tab-btn').addEventListener('click', () => fetchData('Customers'));
    document.getElementById('expense-tab-btn') && document.getElementById('expense-tab-btn').addEventListener('click', () => fetchData('Expenses', true));

    // Cart management listeners
    itemsContainer.addEventListener('click', (e) => {
        if (e.target.classList.contains('add-to-cart-btn')) {
            const sku = e.target.getAttribute('data-sku');
            handleAddToCart(sku);
        }
    });

    const cartItemsListElement = document.getElementById('cart-items-list');
    cartItemsListElement && cartItemsListElement.addEventListener('click', (e) => {
        if (e.target.closest('.remove-item-btn')) {
            const index = e.target.closest('.remove-item-btn').getAttribute('data-index');
            handleRemoveFromCart(parseInt(index));
        }
    });
    
    const checkoutBtn = document.getElementById('checkout-btn');
    checkoutBtn && checkoutBtn.addEventListener('click', handleCheckout);
});
