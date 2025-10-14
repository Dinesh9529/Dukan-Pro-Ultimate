// server.cjs (Dukan Pro - Ultimate Backend)

const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto');
const cors = require('cors');
// सुरक्षा के लिए 'helmet' को जोड़ना एक अच्छा अभ्यास है, लेकिन हमने इसे minimal रखने के लिए छोड़ दिया है
require('dotenv').config(); // .env फ़ाइल से environment variables लोड करें

const app = express();
const PORT = process.env.PORT || 10000;
// 🚨 सुरक्षा सुविधा: यह सुनिश्चित करें कि आप .env में इन मानों को बदल दें
const SECRET_KEY = process.env.SECRET_KEY || 'your_secret_key_change_it'; 
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'default_admin_password_change_me'; 

// --- Encryption Constants ---
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

/**
 * ✅ सुरक्षा सुधार: यह फ़ंक्शन अब 'DROP TABLE' का उपयोग नहीं करता है।
 * 'CREATE TABLE IF NOT EXISTS' का उपयोग करके, यह सुनिश्चित करता है कि डेटा हमेशा सुरक्षित रहे।
 */
async function createTables() {
    const client = await pool.connect(); // बेहतर कनेक्शन प्रबंधन के लिए
    try {
        console.log('Attempting to ensure all tables exist (Data is safe)...');
        
        // ❌ पुराने DROP TABLE कमांड्स को हटा दिया गया है।

        // 1. Licenses Table
        await client.query(`
            CREATE TABLE IF NOT EXISTS licenses (
                key_hash TEXT PRIMARY KEY,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                expiry_date TIMESTAMP WITH TIME ZONE,
                is_trial BOOLEAN DEFAULT FALSE
            );
        `);

        // 2. Stock Table
        await client.query(`
            CREATE TABLE IF NOT EXISTS stock (
                id SERIAL PRIMARY KEY,
                sku TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                quantity NUMERIC NOT NULL,
                unit TEXT,
                purchase_price NUMERIC NOT NULL,
                sale_price NUMERIC NOT NULL,
                gst NUMERIC DEFAULT 0,
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        
        // 3. Customers Table
        await client.query(`
            CREATE TABLE IF NOT EXISTS customers (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                phone TEXT UNIQUE,
                email TEXT UNIQUE,
                address TEXT,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 4. Invoices Table
        await client.query(`
            CREATE TABLE IF NOT EXISTS invoices (
                id SERIAL PRIMARY KEY,
                customer_id INTEGER REFERENCES customers(id),
                total_amount NUMERIC NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 5. Invoice Items Table (ON DELETE CASCADE जोड़ा गया)
        await client.query(`
            CREATE TABLE IF NOT EXISTS invoice_items (
                id SERIAL PRIMARY KEY,
                invoice_id INTEGER REFERENCES invoices(id) ON DELETE CASCADE,
                item_name TEXT NOT NULL,
                quantity NUMERIC NOT NULL,
                sale_price NUMERIC NOT NULL
            );
        `);
        
        // 6. Purchases Table
        await client.query(`
            CREATE TABLE IF NOT EXISTS purchases (
                id SERIAL PRIMARY KEY,
                supplier_name TEXT,
                item_details TEXT NOT NULL,
                total_cost NUMERIC NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        
        // 7. Expenses Table
        await client.query(`
            CREATE TABLE IF NOT EXISTS expenses (
                id SERIAL PRIMARY KEY,
                description TEXT NOT NULL,
                category TEXT,
                amount NUMERIC NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        
        console.log('✅ All tables checked/created successfully (Data retained).');

    } catch (err) {
        console.error('❌ Error ensuring database tables:', err.message);
        process.exit(1);
    } finally {
        client.release(); // कनेक्शन वापस पूल में जारी करें
    }
}

// --- License Utilities ---

function hashKey(key) {
    return crypto.createHash('sha256').update(key).digest('hex');
}

// --- API Routes ---

// 1. Generate License Key
app.post('/api/generate-key', async (req, res) => {
    const { password, days } = req.body;
    
    // 🚨 सुरक्षा सुविधा: इनपुट सत्यापन
    if (password !== ADMIN_PASSWORD) {
        return res.status(401).json({ success: false, message: 'अमान्य एडमिन पासवर्ड।' });
    }
    if (typeof days !== 'number' || days < 1) {
         return res.status(400).json({ success: false, message: 'दिनों की संख्या मान्य होनी चाहिए।' });
    }

    // एक रैंडम Key जेनरेट करें
    const rawKey = crypto.randomBytes(16).toString('hex');
    const keyHash = hashKey(rawKey);

    // समाप्ति तिथि (Expiry Date) की गणना करें
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + days); // 'days' का उपयोग करें

    try {
        await pool.query(
            'INSERT INTO licenses (key_hash, expiry_date, is_trial) VALUES ($1, $2, $3)',
            [keyHash, expiryDate, days === 5]
        );
        
        // यूज़र को केवल Raw Key दिखाएं
        res.json({ 
            success: true, 
            key: rawKey, 
            message: 'लाइसेंस कुंजी सफलतापूर्वक बनाई गई।',
            duration_days: days,
            valid_until: expiryDate.toISOString() 
        });
    } catch (err) {
        console.error("Error generating key:", err.message);
        res.status(500).json({ success: false, message: 'कुंजी बनाने में विफल: डेटाबेस त्रुटि।' });
    }
});

// 2. Verify License Key 
app.get('/api/verify-license', async (req, res) => {
    const rawKey = req.query.key;
    if (!rawKey) {
        return res.status(400).json({ success: false, message: 'कुंजी आवश्यक है।' });
    }

    const keyHash = hashKey(rawKey);

    try {
        const result = await pool.query('SELECT expiry_date, is_trial FROM licenses WHERE key_hash = $1', [keyHash]);
        
        if (result.rows.length === 0) {
            return res.json({ success: false, valid: false, message: 'अमान्य लाइसेंस कुंजी।' });
        }

        const license = result.rows[0];
        const expiryDate = new Date(license.expiry_date);
        const now = new Date();
        const isValid = expiryDate > now;

        if (isValid) {
            return res.json({
                success: true,
                valid: true,
                isTrial: license.is_trial,
                message: 'लाइसेंस सत्यापित और सक्रिय है।',
                expiryDate: expiryDate.toISOString()
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
    const { password } = req.body;
    
    // 🚨 सुरक्षा सुविधा: इनपुट सत्यापन
    if (!password) {
        return res.status(400).json({ success: false, message: 'पासवर्ड आवश्यक है।' });
    }

    if (password === ADMIN_PASSWORD) {  
        return res.json({ success: true, message: 'एडमिन लॉगिन सफल।' });
    } else {
        return res.status(401).json({ success: false, message: 'अमान्य एडमिन पासवर्ड।' });
    }
});

// 4. Stock Management - Add/Update (Simplistic Upsert)
app.post('/api/stock', async (req, res) => {
    const { sku, name, quantity, unit, purchase_price, sale_price, gst } = req.body;
    
    // 🚨 सुरक्षा सुविधा: इनपुट सत्यापन और सैनिटाइजेशन (Input Validation & Sanitization)
    if (!sku || !name || typeof quantity === 'undefined' || typeof purchase_price === 'undefined' || typeof sale_price === 'undefined') {
        return res.status(400).json({ success: false, message: 'SKU, नाम, मात्रा, खरीद मूल्य और बिक्री मूल्य आवश्यक हैं।' });
    }
    
    // स्ट्रिंग इनपुट से बचने के लिए पार्सिंग
    const safeQuantity = parseFloat(quantity);
    const safePurchasePrice = parseFloat(purchase_price);
    const safeSalePrice = parseFloat(sale_price);
    const safeGst = parseFloat(gst || 0);

    if (isNaN(safeQuantity) || isNaN(safePurchasePrice) || isNaN(safeSalePrice)) {
        return res.status(400).json({ success: false, message: 'मात्रा, खरीद मूल्य और बिक्री मूल्य मान्य संख्याएँ होनी चाहिए।' });
    }

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
            [sku, name, safeQuantity, unit, safePurchasePrice, safeSalePrice, safeGst]
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

// 6. Dashboard Data (Summary Metrics) - PostgreSQL के लिए सुधारा गया
--- NEW API FOR DASHBOARD DETAILS --- ⭐
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

// 7. NEW API: Get Balance Sheet / Detailed Financials Data 
app.get('/api/get-balance-sheet-data', async (req, res) => {
    try {
        // --- 1. Current Inventory Value (Asset) ---
        const inventoryValueResult = await pool.query(`
            SELECT COALESCE(SUM(quantity * purchase_price), 0) AS inventory_value FROM stock;
        `);
        const currentInventoryValue = parseFloat(inventoryValueResult.rows[0].inventory_value);

        // --- 2. Total Revenue (P&L) ---
        const revenueResult = await pool.query(`
            SELECT COALESCE(SUM(total_amount), 0) AS total_revenue FROM invoices;
        `);
        const totalRevenue = parseFloat(revenueResult.rows[0].total_revenue);

        // --- 3. Total Purchases (P&L Cost) ---
        const purchasesResult = await pool.query(`
            SELECT COALESCE(SUM(total_cost), 0) AS total_purchases FROM purchases;
        `);
        const totalPurchases = parseFloat(purchasesResult.rows[0].total_purchases);

        // --- 4. Total Expenses (P&L Cost) ---
        const expensesResult = await pool.query(`
            SELECT COALESCE(SUM(amount), 0) AS total_expenses FROM expenses;
        `);
        const totalExpenses = parseFloat(expensesResult.rows[0].total_expenses);
        
        // --- 5. Calculation ---
        const grossProfit = totalRevenue - totalPurchases;
        const netProfit = grossProfit - totalExpenses;
        const totalAssets = currentInventoryValue; // Simplistic: Inventory is the main asset
        
        res.json({
            success: true,
            balanceSheet: {
                currentAssets: totalAssets,
                // Liabilities और Equity के लिए यहां placeholders हैं, आप बाद में जोड़ सकते हैं
                totalLiabilities: 0.00,
                netWorth: totalAssets, // Simplistic
            },
            profitAndLoss: {
                totalRevenue: totalRevenue,
                totalPurchases: totalPurchases,
                totalExpenses: totalExpenses,
                grossProfit: grossProfit,
                netProfit: netProfit
            }
        });

    } catch (err) {
        console.error("Error fetching balance sheet data:", err.message);
        return res.status(500).json({ success: false, message: 'विस्तृत वित्तीय डेटा प्राप्त करने में विफल।' });
    }
});


// --- CRM API Routes (New) ---

// 8. Add Customer
app.post('/api/customer', async (req, res) => {
    const { name, phone, email, address } = req.body;
    // 🚨 सुरक्षा सुविधा: इनपुट सत्यापन
    if (!name) {
        return res.status(400).json({ success: false, message: 'ग्राहक का नाम आवश्यक है।' });
    }
    try {
        await pool.query(
            `INSERT INTO customers (name, phone, email, address) VALUES ($1, $2, $3, $4)`,
            [name, phone, email, address]
        );
        res.json({ success: true, message: 'ग्राहक सफलतापूर्वक जोड़ा गया।' });
    } catch (err) {
        console.error("Error adding customer:", err.message);
        res.status(500).json({ success: false, message: 'ग्राहक जोड़ने में विफल रहा।' });
    }
});

// 9. Get Customers
app.get('/api/customer', async (req, res) => {
    try {
        const result = await pool.query(`SELECT * FROM customers ORDER BY created_at DESC;`);
        res.json({ success: true, customers: result.rows });
    } catch (err) {
        console.error("Error fetching customers:", err.message);
        res.status(500).json({ success: false, message: 'ग्राहक सूची प्राप्त करने में विफल।' });
    }
});


// --- Purchases API Routes (New) ---

// 10. Add Purchase
app.post('/api/purchase', async (req, res) => {
    const { supplier_name, item_details, total_cost } = req.body;
    // 🚨 सुरक्षा सुविधा: इनपुट सत्यापन
    if (!item_details || typeof total_cost === 'undefined') {
        return res.status(400).json({ success: false, message: 'खरीद विवरण और कुल लागत आवश्यक हैं।' });
    }
    const safeTotalCost = parseFloat(total_cost);
    if (isNaN(safeTotalCost) || safeTotalCost <= 0) {
        return res.status(400).json({ success: false, message: 'कुल लागत एक मान्य संख्या होनी चाहिए।' });
    }

    try {
        await pool.query(
            `INSERT INTO purchases (supplier_name, item_details, total_cost) VALUES ($1, $2, $3)`,
            [supplier_name, item_details, safeTotalCost]
        );
        res.json({ success: true, message: 'खरीद सफलतापूर्वक दर्ज की गई।' });
    } catch (err) {
        console.error("Error adding purchase:", err.message);
        res.status(500).json({ success: false, message: 'खरीद दर्ज करने में विफल रहा।' });
    }
});

// 11. Get Purchases
app.get('/api/purchase', async (req, res) => {
    try {
        const result = await pool.query(`SELECT * FROM purchases ORDER BY created_at DESC;`);
        res.json({ success: true, purchases: result.rows });
    } catch (err) {
        console.error("Error fetching purchases:", err.message);
        res.status(500).json({ success: false, message: 'खरीद सूची प्राप्त करने में विफल।' });
    }
});

// --- Expenses API Routes (New) ---

// 12. Add Expense
app.post('/api/expense', async (req, res) => {
    const { description, category, amount } = req.body;
    // 🚨 सुरक्षा सुविधा: इनपुट सत्यापन
    if (!description || typeof amount === 'undefined') {
        return res.status(400).json({ success: false, message: 'विवरण और राशि आवश्यक हैं।' });
    }
    const safeAmount = parseFloat(amount);
    if (isNaN(safeAmount) || safeAmount <= 0) {
        return res.status(400).json({ success: false, message: 'राशि एक मान्य संख्या होनी चाहिए।' });
    }

    try {
        await pool.query(
            `INSERT INTO expenses (description, category, amount) VALUES ($1, $2, $3)`,
            [description, category, safeAmount]
        );
        res.json({ success: true, message: 'खर्च सफलतापूर्वक दर्ज किया गया।' });
    } catch (err) {
        console.error("Error adding expense:", err.message);
        res.status(500).json({ success: false, message: 'खर्च दर्ज करने में विफल रहा।' });
    }
});

// 13. Get Expenses
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
        return createTables(); // ✅ अब यह डेटा को बरकरार रखेगा
    })
    .then(() => {
        app.listen(PORT, () => {
            console.log(`Server is running on port ${PORT}`);
        });
    })
    .catch(err => {
        console.error('Database connection failed:', err.message);
        process.exit(1);
    });


