// server.cjs (Dukan Pro - FINAL & COMPLETE BACKEND)

const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;
const SECRET_KEY = process.env.SECRET_KEY || 'your_secret_key_change_it';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'default_admin_password_change_me';

app.use(cors());
app.use(express.json());

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Helper function to hash license keys
function hashKey(key) {
    return crypto.createHash('sha256').update(key).digest('hex');
}

// --- ALL API ROUTES ---

// 1. Verify License Key
app.get('/api/verify-license', async (req, res) => {
    const { key } = req.query;
    if (!key) return res.status(400).json({ success: false, message: 'कुंजी आवश्यक है।' });
    try {
        const result = await pool.query('SELECT expiry_date FROM licenses WHERE key_hash = $1', [hashKey(key)]);
        if (result.rows.length === 0) return res.json({ success: false, valid: false, message: 'अमान्य लाइसेंस कुंजी।' });
        const isValid = new Date(result.rows[0].expiry_date) > new Date();
        if (isValid) res.json({ success: true, valid: true, message: 'लाइसेंस सत्यापित है।' });
        else res.json({ success: false, valid: false, message: 'लाइसेंस की समय सीमा समाप्त हो गई है।' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'सत्यापन विफल: सर्वर त्रुटि।' });
    }
});

// 2. Admin Login
app.post('/api/admin-login', (req, res) => {
    if (req.body.password === ADMIN_PASSWORD) res.json({ success: true, message: 'एडमिन लॉगिन सफल।' });
    else res.status(401).json({ success: false, message: 'अमान्य एडमिन पासवर्ड।' });
});

// 3. Stock Management - Add/Update
app.post('/api/stock', async (req, res) => {
    const { sku, name, quantity, unit, purchase_price, sale_price, gst } = req.body;
    try {
        const result = await pool.query(
            `INSERT INTO stock (sku, name, quantity, unit, purchase_price, sale_price, gst)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (sku) DO UPDATE SET 
                quantity = stock.quantity + EXCLUDED.quantity, 
                purchase_price = EXCLUDED.purchase_price,
                sale_price = EXCLUDED.sale_price,
                gst = EXCLUDED.gst,
                updated_at = CURRENT_TIMESTAMP
             RETURNING *;`,
            [sku, name, quantity, unit, purchase_price, sale_price, gst]
        );
        res.json({ success: true, stock: result.rows[0], message: 'स्टॉक सफलतापूर्वक जोड़ा/अपडेट किया गया।' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'स्टॉक जोड़ने में विफल: ' + err.message });
    }
});

// 4. Stock Management - Get All
app.get('/api/stock', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM stock ORDER BY updated_at DESC');
        res.json({ success: true, stock: result.rows });
    } catch (err) {
        res.status(500).json({ success: false, message: 'स्टॉक सूची प्राप्त करने में विफल।' });
    }
});

// 5. Dashboard - Main Stats
app.get('/api/get-dashboard-data', async (req, res) => {
    try {
        const salesRes = await pool.query("SELECT COALESCE(SUM(total_amount), 0) AS value FROM invoices");
        const stockValRes = await pool.query("SELECT COALESCE(SUM(purchase_price * quantity), 0) AS value FROM stock");
        const customerRes = await pool.query("SELECT COUNT(id) AS value FROM customers");
        const lowStockRes = await pool.query("SELECT COUNT(id) AS value FROM stock WHERE quantity < 10");
        res.json({
            success: true,
            totalSalesRevenue: parseFloat(salesRes.rows[0].value),
            totalStockValue: parseFloat(stockValRes.rows[0].value),
            totalCustomers: parseInt(customerRes.rows[0].value),
            lowStockCount: parseInt(lowStockRes.rows[0].value)
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'डैशबोर्ड डेटा लोड नहीं किया जा सका।' });
    }
});

// 6. Reports - P&L Data
app.get('/api/get-balance-sheet-data', async (req, res) => {
    try {
        const revenueRes = await pool.query("SELECT COALESCE(SUM(total_amount), 0) AS total_revenue FROM invoices;");
        const purchasesRes = await pool.query("SELECT COALESCE(SUM(total_cost), 0) AS total_purchases FROM purchases;");
        const expensesRes = await pool.query("SELECT COALESCE(SUM(amount), 0) AS total_expenses FROM expenses;");
        const totalRevenue = parseFloat(revenueRes.rows[0].total_revenue);
        const totalPurchases = parseFloat(purchasesRes.rows[0].total_purchases);
        const totalExpenses = parseFloat(expensesRes.rows[0].total_expenses);
        const netProfit = totalRevenue - totalPurchases - totalExpenses;
        res.json({
            success: true,
            profitAndLoss: { totalRevenue, totalPurchases, totalExpenses, netProfit }
        });
    } catch (err) {
        res.status(500).json({ success: false, message: 'विस्तृत वित्तीय डेटा प्राप्त करने में विफल।' });
    }
});

// 7. Customer (CRM) Routes
app.post('/api/customer', async (req, res) => {
    const { name, phone, email, address } = req.body;
    try {
        await pool.query('INSERT INTO customers (name, phone, email, address) VALUES ($1, $2, $3, $4)', [name, phone, email, address]);
        res.json({ success: true, message: 'ग्राहक सफलतापूर्वक जोड़ा गया।' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'ग्राहक जोड़ने में विफल रहा।' });
    }
});
app.get('/api/customer', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM customers ORDER BY created_at DESC;');
        res.json({ success: true, customers: result.rows });
    } catch (err) {
        res.status(500).json({ success: false, message: 'ग्राहक सूची प्राप्त करने में विफल।' });
    }
});

// 8. Purchase Routes
app.post('/api/purchase', async (req, res) => {
    const { supplier_name, item_details, total_cost } = req.body;
    try {
        await pool.query('INSERT INTO purchases (supplier_name, item_details, total_cost) VALUES ($1, $2, $3)', [supplier_name, item_details, total_cost]);
        res.json({ success: true, message: 'खरीद सफलतापूर्वक दर्ज की गई।' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'खरीद दर्ज करने में विफल रहा।' });
    }
});
app.get('/api/purchase', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM purchases ORDER BY created_at DESC;');
        res.json({ success: true, purchases: result.rows });
    } catch (err) {
        res.status(500).json({ success: false, message: 'खरीद सूची प्राप्त करने में विफल।' });
    }
});

// 9. Expense Routes
app.post('/api/expense', async (req, res) => {
    const { description, category, amount } = req.body;
    try {
        await pool.query('INSERT INTO expenses (description, category, amount) VALUES ($1, $2, $3)', [description, category, amount]);
        res.json({ success: true, message: 'खर्च सफलतापूर्वक दर्ज किया गया।' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'खर्च दर्ज करने में विफल रहा।' });
    }
});
app.get('/api/expense', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM expenses ORDER BY created_at DESC;');
        res.json({ success: true, expenses: result.rows });
    } catch (err) {
        res.status(500).json({ success: false, message: 'खर्च सूची प्राप्त करने में विफल।' });
    }
});


// ⭐ --- NEW API FOR DASHBOARD DETAILS --- ⭐
app.get('/api/dashboard-details', async (req, res) => {
    try {
        const lowStock = await pool.query('SELECT sku, name, quantity FROM stock WHERE quantity < 10 ORDER BY quantity ASC LIMIT 10');
        const recentSales = await pool.query('SELECT i.id, c.name as customer_name, i.total_amount, i.created_at FROM invoices i LEFT JOIN customers c ON i.customer_id = c.id ORDER BY i.created_at DESC LIMIT 10');
        const recentCustomers = await pool.query('SELECT name, phone, created_at FROM customers ORDER BY created_at DESC LIMIT 10');
        
        res.json({
            success: true,
            lowStock: lowStock.rows,
            recentSales: recentSales.rows,
            recentCustomers: recentCustomers.rows
        });
    } catch (error) {
        res.status(500).json({ success: false, message: 'डैशबोर्ड विवरण लोड करने में विफल।' });
    }
});


// ⭐ --- NEW API FOR POS & INVOICE SAVING --- ⭐
app.post('/api/invoices', async (req, res) => {
    const { customerName, totalAmount, items } = req.body;
    if (!items || items.length === 0) {
        return res.status(400).json({ success: false, message: "बिल में कोई आइटम नहीं है।" });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Step 1: Find or create customer
        let customerResult = await client.query('SELECT id FROM customers WHERE name = $1', [customerName]);
        let customerId;
        if (customerResult.rows.length > 0) {
            customerId = customerResult.rows[0].id;
        } else {
            customerResult = await client.query('INSERT INTO customers (name) VALUES ($1) RETURNING id', [customerName]);
            customerId = customerResult.rows[0].id;
        }

        // Step 2: Create invoice
        const invoiceResult = await client.query(
            'INSERT INTO invoices (customer_id, total_amount) VALUES ($1, $2) RETURNING id',
            [customerId, totalAmount]
        );
        const invoiceId = invoiceResult.rows[0].id;

        // Step 3: Insert invoice items and update stock
        for (const item of items) {
            // Insert item into invoice_items
            await client.query(
                'INSERT INTO invoice_items (invoice_id, item_name, quantity, sale_price) VALUES ($1, $2, $3, $4)',
                [invoiceId, item.name, item.quantity, item.sale_price]
            );
            // Decrease stock quantity
            await client.query(
                'UPDATE stock SET quantity = quantity - $1 WHERE sku = $2',
                [item.quantity, item.sku]
            );
        }

        await client.query('COMMIT');
        res.json({ success: true, message: 'बिक्री सफलतापूर्वक दर्ज की गई!', invoiceId: invoiceId });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error("Invoice saving error:", error.message);
        res.status(500).json({ success: false, message: 'बिक्री दर्ज करने में विफल: ' + error.message });
    } finally {
        client.release();
    }
});


// --- Server Initialization ---
app.listen(PORT, () => {
    console.log(`✅ Dukan Pro Server is running on port ${PORT}`);
});
