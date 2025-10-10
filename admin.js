// admin.js

// URL यहाँ बदलें
const RENDER_URL = "https://dukan-pro-ultimate.onrender.com"; 
const API_BASE_URL = RENDER_URL;

// --- DOM Elements ---
const loginContainer = document.getElementById('login-container');
const dashboardContainer = document.getElementById('admin-dashboard');
const loginForm = document.getElementById('admin-login-form');
const passwordInput = document.getElementById('admin-password');
const loginMsg = document.getElementById('login-msg');
const customersTableBody = document.getElementById('customers-table-body');
const salesTableBody = document.getElementById('sales-table-body');

// --- State ---
let adminToken = null;

// --- Functions ---

// 1. Handle Admin Login
async function handleAdminLogin(event) {
    event.preventDefault();
    const password = passwordInput.value;
    
    loginMsg.textContent = 'Logging in...';

    try {
        const response = await fetch(`${API_BASE_URL}/api/admin/auth`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password })
        });

        const result = await response.json();

        if (result.success) {
            adminToken = result.token;
            localStorage.setItem('adminToken', adminToken);
            localStorage.setItem('adminLoggedIn', 'true');
            
            loginMsg.textContent = 'Login Successful!';
            showDashboard();
            fetchAdminData();
        } else {
            loginMsg.textContent = result.message;
            loginMsg.className = 'text-danger mt-3 fw-bold';
        }
    } catch (error) {
        loginMsg.textContent = 'Network Error. Could not connect to server.';
        loginMsg.className = 'text-danger mt-3 fw-bold';
        console.error("Login Error:", error);
    }
}

// 2. Toggle View
function showDashboard() {
    loginContainer.classList.add('d-none');
    dashboardContainer.classList.remove('d-none');
}
function showLogin() {
    dashboardContainer.classList.add('d-none');
    loginContainer.classList.remove('d-none');
}

// 3. Fetch Data for Dashboard
async function fetchAdminData() {
    // Note: For simplicity, we are not using the token in the GET request yet.
    // In a real app, this request would require the adminToken in the headers.
    try {
        const response = await fetch(`${API_BASE_URL}/api/admin/all-data`);
        const data = await response.json();

        if (response.ok) {
            renderCustomerData(data.customers);
            renderSalesData(data.sales);
            // Stock data is also available in data.stock
        } else {
             alert('Failed to load admin data: ' + data.message);
        }

    } catch (error) {
        alert('Error fetching data.');
        console.error("Fetch Data Error:", error);
    }
}

// 4. Render Customer Table
function renderCustomerData(customers) {
    customersTableBody.innerHTML = '';
    customers.forEach(cust => {
        const row = customersTableBody.insertRow();
        // ध्यान दें: PostgreSQL से आने वाले keys UPPERCASE में होंगे
        row.insertCell().textContent = cust.Name || 'N/A'; 
        row.insertCell().textContent = cust.Phone || 'N/A';
        row.insertCell().textContent = cust.Address || 'N/A';
        row.insertCell().textContent = cust.ID; 
    });
}

// 5. Render Sales Table
function renderSalesData(sales) {
    salesTableBody.innerHTML = '';
    sales.forEach(sale => {
        const row = salesTableBody.insertRow();
        row.insertCell().textContent = sale["Invoice Number"] || 'N/A'; 
        row.insertCell().textContent = sale["Customer Name"] || 'N/A';
        row.insertCell().textContent = sale["Total Amount"] ? parseFloat(sale["Total Amount"]).toFixed(2) : '0.00';
        row.insertCell().textContent = new Date(sale.Date).toLocaleDateString('hi-IN');
    });
}


// --- Initialization ---
document.addEventListener('DOMContentLoaded', () => {
    loginForm.addEventListener('submit', handleAdminLogin);
    
    // Check if admin is already logged in (simple check)
    if (localStorage.getItem('adminLoggedIn') === 'true' && localStorage.getItem('adminToken')) {
        adminToken = localStorage.getItem('adminToken');
        showDashboard();
        fetchAdminData();
    } else {
        showLogin();
    }
});