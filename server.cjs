// server.cjs (Dukan Pro - FINAL & COMPLETE BACKEND)

const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto');
const cors = require('cors');
require('dotenv').config(); // .env फ़ाइल से environment variables लोड करें

const app = express();
const PORT = process.env.PORT || 10000;
const SECRET_KEY = process.env.SECRET_KEY || 'your_secret_key_change_it'; 
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'default_admin_password_change_me'; 

// --- Encryption Constants (Not used in the final version, but kept for completeness) ---
const IV_LENGTH = 16;
const ENCRYPTION_KEY = crypto.createHash('sha256').update(SECRET_KEY).digest(); 

// --- Middlewares ---
app.use(cors());
app.use(express.json());

// --- Database Setup ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// --- License Utilities ---
function hashKey(key) {
    return crypto.createHash('sha256').update(key).digest('hex');
}

/**
 * सभी आवश्यक टेबल्स (8 टेबल्स) बनाता है, पुराने टेबल्स को DROP करके स्कीमा Consistency सुनिश्चित करता है।
 * WARNING: इससे पुराने डेटाबेस का सारा डेटा डिलीट हो जाएगा!
 */
/**
 * सभी आवश्यक टेबल्स (7 टेबल्स) बनाता है, पुराने टेबल्स को DROP करके स्कीमा Consistency सुनिश्चित करता है।
 * WARNING: इससे पुराने डेटाबेस का सारा डेटा डिलीट हो जाएगा!
 * FIX: 'syntax error' को हल करने के लिए SQL strings को साफ किया गया है।
 */
async function createTables() {
    const client = await pool.connect(); // एक ही कनेक्शन का उपयोग करें
    try {
        console.log('Attempting to reset schema...');
        
        // --- DROP TABLES ---
        await client.query('DROP TABLE IF EXISTS invoice_items CASCADE;');
        await client.query('DROP TABLE IF EXISTS invoices CASCADE;');
        await client.query('DROP TABLE IF EXISTS customers CASCADE;');
        await client.query('DROP TABLE IF EXISTS stock CASCADE;');
        await client.query('DROP TABLE IF EXISTS purchases CASCADE;');
        await client.query('DROP TABLE IF EXISTS expenses CASCADE;');
        await client.query('DROP TABLE IF EXISTS licenses CASCADE;');
        console.log('✅ Dropped existing tables (Schema Reset).');

        // --- CREATE TABLES (Cleaned SQL Strings) ---

        // 1. Licenses Table
        await client.query(`
CREATE TABLE licenses (
    key_hash TEXT PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expiry_date TIMESTAMP WITH TIME ZONE,
    is_trial BOOLEAN DEFAULT FALSE
);`);

        // 2. Stock Table
        await client.query(`
CREATE TABLE stock (
    id SERIAL PRIMARY KEY,
    sku TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    quantity NUMERIC NOT NULL,
    unit TEXT,
    purchase_price NUMERIC NOT NULL,
    sale_price NUMERIC NOT NULL,
    gst NUMERIC DEFAULT 0,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);`);
        
        // 3. Customers Table
        await client.query(`
CREATE TABLE customers (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    phone TEXT UNIQUE,
    email TEXT UNIQUE,
    address TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);`);

        // 4. Invoices Table
        await client.query(`
CREATE TABLE invoices (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER REFERENCES customers(id),
    total_amount NUMERIC NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);`);

        // 5. Invoice Items Table
        await client.query(`
CREATE TABLE invoice_items (
    id SERIAL PRIMARY KEY,
    invoice_id INTEGER REFERENCES invoices(id),
    item_name TEXT NOT NULL,
    quantity NUMERIC NOT NULL,
    sale_price NUMERIC NOT NULL,
    sku TEXT
);`);
        
        // 6. Purchases Table
        await client.query(`
CREATE TABLE purchases (
    id SERIAL PRIMARY KEY,
    supplier_name TEXT,
    item_details TEXT NOT NULL,
    total_cost NUMERIC NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);`);
        
        // 7. Expenses Table
        await client.query(`
CREATE TABLE expenses (
    id SERIAL PRIMARY KEY,
    description TEXT NOT NULL,
    category TEXT,
    amount NUMERIC NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);`);

        console.log('✅ All 7 tables created successfully.');
    } catch (err) {
        // सुनिश्चित करें कि error को console.error में प्रिंट किया गया है
        console.error('❌ Error creating database tables (FIXED):', err.message);
        process.exit(1);
    } finally {
        client.release(); // कनेक्शन वापस पूल में जारी करें
    }
}


// --- API Routes ---

// 1. Generate License Key (Admin Only)
app.post('/api/generate-key', async (req, res) => {
    const { password, days } = req.body;
    if (password !== ADMIN_PASSWORD) return res.status(401).json({ success: false, message: 'अमान्य एडमिन पासवर्ड।' });
    
    const rawKey = crypto.randomBytes(16).toString('hex');
    const keyHash = hashKey(rawKey);
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + (days || 30));

    try {
        await pool.query('INSERT INTO licenses (key_hash, expiry_date, is_trial) VALUES ($1, $2, $3)', [keyHash, expiryDate, days === 5]);
        res.json({ success: true, key: rawKey, message: 'लाइसेंस कुंजी सफलतापूर्वक बनाई गई।', valid_until: expiryDate.toISOString() });
    } catch (err) {
        console.error("Error generating key:", err.message);
        res.status(500).json({ success: false, message: 'कुंजी बनाने में विफल: डेटाबेस त्रुटि।' });
    }
});

// 2. Verify License Key 
app.get('/api/verify-license', async (req, res) => {
    const rawKey = req.query.key;
    if (!rawKey) return res.status(400).json({ success: false, message: 'कुंजी आवश्यक है।' });

    const keyHash = hashKey(rawKey);

    try {
        const result = await pool.query('SELECT expiry_date, is_trial FROM licenses WHERE key_hash = $1', [keyHash]);
        if (result.rows.length === 0) return res.json({ success: false, valid: false, message: 'अमान्य लाइसेंस कुंजी।' });

        const license = result.rows[0];
        const isValid = new Date(license.expiry_date) > new Date();

        if (isValid) {
            return res.json({
                success: true,
                valid: true,
                isTrial: license.is_trial,
                message: 'लाइसेंस सत्यापित और सक्रिय है।',
                expiryDate: license.expiry_date.toISOString()
            });
        } else {
            return res.json({ success: false, valid: false, message: 'लाइसेंस की समय सीमा समाप्त हो गई है।' });
        }
    } catch (err) {
        console.error("Error verifying license:", err.message);
        res.status(500).json({ success: false, message: 'सत्यापन विफल: सर्वर त्रुटि।' });
    }
});

// 3. Admin Login
app.post('/api/admin-login', (req, res) => {
    if (req.body.password === ADMIN_PASSWORD) return res.json({ success: true, message: 'एडमिन लॉगिन सफल।' });
    else return res.status(401).json({ success: false, message: 'अमान्य एडमिन पासवर्ड।' });
});

// 4. Stock Management - Add/Update (Upsert)
app.post('/api/stock', async (req, res) => {
    const { sku, name, quantity, unit, purchase_price, sale_price, gst } = req.body;
    try {
        const result = await pool.query(
            `INSERT INTO stock (sku, name, quantity, unit, purchase_price, sale_price, gst)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (sku) DO UPDATE
             SET 
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
        console.error("Error adding stock:", err.message);
        res.status(500).json({ success: false, message: 'स्टॉक जोड़ने में विफल: ' + err.message });
    }
});

// 5. Stock Management - Get All
app.get('/api/stock', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM stock ORDER BY updated_at DESC');
        res.json({ success: true, stock: result.rows });
    } catch (err) {
        console.error("Error fetching stock:", err.message);
        res.status(500).json({ success: false, message: 'स्टॉक सूची प्राप्त करने में विफल।' });
    }
});

// 6. Dashboard Data (Summary Metrics) - (Corrected for PostgreSQL)
app.get('/api/get-dashboard-data', async (req, res) => {
    try {
        const salesResult = await pool.query("SELECT COALESCE(SUM(total_amount), 0) AS value FROM invoices");
        const totalSalesRevenue = parseFloat(salesResult.rows[0].value);

        const stockValueResult = await pool.query("SELECT COALESCE(SUM(quantity * purchase_price), 0) AS value FROM stock");
        const totalStockValue = parseFloat(stockValueResult.rows[0].value);
        
        const customerResult = await pool.query("SELECT COUNT(DISTINCT customer_id) AS value FROM invoices WHERE customer_id IS NOT NULL");
        const totalCustomers = parseInt(customerResult.rows[0].value);

        const lowStockResult = await pool.query("SELECT COUNT(id) AS value FROM stock WHERE quantity < 10");
        const lowStockCount = parseInt(lowStockResult.rows[0].value);

        res.json({
            success: true,
            totalSalesRevenue: totalSalesRevenue,
            totalStockValue: totalStockValue,
            totalCustomers: totalCustomers,
            lowStockCount: lowStockCount
        });

    } catch (error) {
        console.error('डैशबोर्ड डेटा एरर:', error.message);
        res.status(500).json({ success: false, message: 'डैशबोर्ड डेटा लोड नहीं किया जा सका।' });
    }
});

// 7. Get Balance Sheet / Financials Data
app.get('/api/get-balance-sheet-data', async (req, res) => {
    try {
        // Revenue
        const revenueResult = await pool.query("SELECT COALESCE(SUM(total_amount), 0) AS total_revenue FROM invoices;");
        const totalRevenue = parseFloat(revenueResult.rows[0].total_revenue);

        // Purchases (Cost)
        const purchasesResult = await pool.query("SELECT COALESCE(SUM(total_cost), 0) AS total_purchases FROM purchases;");
        const totalPurchases = parseFloat(purchasesResult.rows[0].total_purchases);

        // Expenses (Cost)
        const expensesResult = await pool.query("SELECT COALESCE(SUM(amount), 0) AS total_expenses FROM expenses;");
        const totalExpenses = parseFloat(expensesResult.rows[0].total_expenses);
        
        // Inventory Value (Asset)
        const inventoryValueResult = await pool.query("SELECT COALESCE(SUM(quantity * purchase_price), 0) AS inventory_value FROM stock;");
        const currentInventoryValue = parseFloat(inventoryValueResult.rows[0].inventory_value);

        const netProfit = totalRevenue - totalPurchases - totalExpenses;
        
        res.json({
            success: true,
            balanceSheet: { currentAssets: currentInventoryValue, totalLiabilities: 0.00, netWorth: currentInventoryValue },
            profitAndLoss: { totalRevenue, totalPurchases, totalExpenses, netProfit }
        });

    } catch (err) {
        console.error("Error fetching balance sheet data:", err.message);
        return res.status(500).json({ success: false, message: 'विस्तृत वित्तीय डेटा प्राप्त करने में विफल।' });
    }
});

// ⭐ 8. NEW API: Dashboard Details (Low Stock, Recent Sales, Recent Customers)
app.get('/api/dashboard-details', async (req, res) => {
    try {
        const lowStock = await pool.query('SELECT sku, name, quantity FROM stock WHERE quantity < 10 ORDER BY quantity ASC LIMIT 10');
        // i.customer_id IS NOT NULL को हटा दिया गया क्योंकि customer_id FOREIGN KEY है और हमेशा एक मान (null या ID) होगा, लेकिन हम DISTINCT COUNT नहीं कर रहे हैं
        const recentSales = await pool.query('SELECT i.id, c.name as customer_name, i.total_amount, i.created_at FROM invoices i LEFT JOIN customers c ON i.customer_id = c.id ORDER BY i.created_at DESC LIMIT 10');
        const recentCustomers = await pool.query('SELECT name, phone, created_at FROM customers ORDER BY created_at DESC LIMIT 10');
        
        res.json({
            success: true,
            lowStock: lowStock.rows,
            recentSales: recentSales.rows,
            recentCustomers: recentCustomers.rows
        });
    } catch (error) {
        console.error("Error fetching dashboard details:", error.message);
        res.status(500).json({ success: false, message: 'डैशबोर्ड विवरण लोड करने में विफल।' });
    }
});


// 9. Add Customer
app.post('/api/customer', async (req, res) => {
    const { name, phone, email, address } = req.body;
    try {
        await pool.query(`INSERT INTO customers (name, phone, email, address) VALUES ($1, $2, $3, $4)`, [name, phone, email, address]);
        res.json({ success: true, message: 'ग्राहक सफलतापूर्वक जोड़ा गया।' });
    } catch (err) {
        console.error("Error adding customer:", err.message);
        res.status(500).json({ success: false, message: 'ग्राहक जोड़ने में विफल रहा।' });
    }
});

// 10. Get Customers
app.get('/api/customer', async (req, res) => {
    try {
        const result = await pool.query(`SELECT * FROM customers ORDER BY created_at DESC;`);
        res.json({ success: true, customers: result.rows });
    } catch (err) {
        console.error("Error fetching customers:", err.message);
        res.status(500).json({ success: false, message: 'ग्राहक सूची प्राप्त करने में विफल।' });
    }
});

// ⭐ 11. NEW API: POS & Invoice Saving (Atomic Transaction)
app.post('/api/invoices', async (req, res) => {
    const { customerName, totalAmount, items } = req.body;
    if (!items || items.length === 0) return res.status(400).json({ success: false, message: "बिल में कोई आइटम नहीं है।" });

    const client = await pool.connect(); // Acquire a client for transaction
    try {
        await client.query('BEGIN'); // Start Transaction

        // Step 1: Find or create customer
        let customerId;
        if (customerName) {
            let customerResult = await client.query('SELECT id FROM customers WHERE name = $1', [customerName]);
            if (customerResult.rows.length === 0) {
                // If not found, create a new customer
                customerResult = await client.query('INSERT INTO customers (name) VALUES ($1) RETURNING id', [customerName]);
            }
            customerId = customerResult.rows[0].id;
        } else {
            customerId = null; // Allow sales without a customer name
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
                'INSERT INTO invoice_items (invoice_id, item_name, quantity, sale_price, sku) VALUES ($1, $2, $3, $4, $5)',
                [invoiceId, item.name, item.quantity, item.sale_price, item.sku]
            );
            // Decrease stock quantity
            await client.query(
                'UPDATE stock SET quantity = quantity - $1 WHERE sku = $2',
                [item.quantity, item.sku]
            );
        }

        await client.query('COMMIT'); // All successful, commit changes
        res.json({ success: true, message: 'बिक्री सफलतापूर्वक दर्ज की गई!', invoiceId: invoiceId });

    } catch (error) {
        await client.query('ROLLBACK'); // Error occurred, revert all changes
        console.error("Invoice saving error:", error.message);
        res.status(500).json({ success: false, message: 'बिक्री दर्ज करने में विफल: ' + error.message });
    } finally {
        client.release(); // Release client back to the pool
    }
});

// 12. Add Purchase
app.post('/api/purchase', async (req, res) => {
    const { supplier_name, item_details, total_cost } = req.body;
    try {
        await pool.query(`INSERT INTO purchases (supplier_name, item_details, total_cost) VALUES ($1, $2, $3)`, [supplier_name, item_details, total_cost]);
        res.json({ success: true, message: 'खरीद सफलतापूर्वक दर्ज की गई।' });
    } catch (err) {
        console.error("Error adding purchase:", err.message);
        res.status(500).json({ success: false, message: 'खरीद दर्ज करने में विफल रहा।' });
    }
});

// 13. Get Purchases
app.get('/api/purchase', async (req, res) => {
    try {
        const result = await pool.query(`SELECT * FROM purchases ORDER BY created_at DESC;`);
        res.json({ success: true, purchases: result.rows });
    } catch (err) {
        console.error("Error fetching purchases:", err.message);
        res.status(500).json({ success: false, message: 'खरीद सूची प्राप्त करने में विफल।' });
    }
});

// 14. Add Expense
app.post('/api/expense', async (req, res) => {
    const { description, category, amount } = req.body;
    try {
        await pool.query(`INSERT INTO expenses (description, category, amount) VALUES ($1, $2, $3)`, [description, category, amount]);
        res.json({ success: true, message: 'खर्च सफलतापूर्वक दर्ज किया गया।' });
    } catch (err) {
        console.error("Error adding expense:", err.message);
        res.status(500).json({ success: false, message: 'खर्च दर्ज करने में विफल रहा।' });
    }
});

// 15. Get Expenses
app.get('/api/expense', async (req, res) => {
    try {
        const result = await pool.query(`SELECT * FROM expenses ORDER BY created_at DESC;`);
        res.json({ success: true, expenses: result.rows });
    } catch (err) {
        console.error("Error fetching expenses:", err.message);
        res.status(500).json({ success: false, message: 'खर्च सूची प्राप्त करने में विफल।' });
    }
});


// --- Server Initialization ---

pool.connect()
    .then(() => {
        console.log('PostgreSQL connection established.');
        // सुनिश्चित करें कि सर्वर शुरू होने से पहले सभी टेबल्स बन जाएँ
        return createTables();
    })
    .then(() => {
        app.listen(PORT, () => {
            console.log(`✅ Dukan Pro Server is running on port ${PORT}`);
        });
    })
    .catch(err => {
        console.error('Database connection failed or tables creation error:', err.message);
        process.exit(1);
    });

