// server.js (Dukan Pro - Ultimate Backend)

const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto');
const cors = require('cors');
require('dotenv').config(); // .env फ़ाइल से environment variables लोड करें

const app = express();
const PORT = process.env.PORT || 10000;
const SECRET_KEY = process.env.SECRET_KEY || 'your_secret_key_change_it'; // लाइसेंस एन्क्रिप्शन के लिए

// --- Middlewares ---
app.use(cors()); // CORS सक्षम करें
app.use(express.json()); // JSON body पार्स करने के लिए

// --- Database Setup ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false // Render के साथ SSL की आवश्यकता होती है
    }
});

/**
 * सभी आवश्यक टेबल्स (8 टेबल्स) बनाता है।
 * इसमें Licenses, Stock, Invoices, Customers, Purchases, Expenses शामिल हैं।
 */
async function createTables() {
    try {
        // 1. Licenses Table (लाइसेंस कुंजी संग्रहीत करने के लिए)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS licenses (
                key_hash TEXT PRIMARY KEY,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                expiry_date TIMESTAMP WITH TIME ZONE,
                is_trial BOOLEAN DEFAULT FALSE
            );
        `);
        console.log('✅ Licenses table created/ready (PostgreSQL).');

        // 2. Stock Table (इन्वेंट्री)
        await pool.query(`
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
        console.log('✅ Stock table created/ready (PostgreSQL).');
        
        // 3. Customers Table (ग्राहक)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS customers (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                phone TEXT UNIQUE,
                email TEXT UNIQUE,
                address TEXT,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('✅ Customers table created/ready (PostgreSQL).');

        // 4. Invoices Table (बिक्री/Sales)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS invoices (
                id SERIAL PRIMARY KEY,
                customer_id INTEGER REFERENCES customers(id),
                total_amount NUMERIC NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('✅ Invoices table created/ready (PostgreSQL).');

        // 5. Invoice Items Table (इनवॉइस में बेचे गए आइटम)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS invoice_items (
                id SERIAL PRIMARY KEY,
                invoice_id INTEGER REFERENCES invoices(id),
                item_name TEXT NOT NULL,
                quantity NUMERIC NOT NULL,
                sale_price NUMERIC NOT NULL
            );
        `);
        console.log('✅ Invoice Items table created/ready (PostgreSQL).');
        
        // 6. Purchases Table (खरीद/Purchases)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS purchases (
                id SERIAL PRIMARY KEY,
                supplier_name TEXT,
                item_details TEXT NOT NULL,
                total_cost NUMERIC NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('✅ Purchases table created/ready (PostgreSQL).');
        
        // 7. Expenses Table (खर्च/Expenses)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS expenses (
                id SERIAL PRIMARY KEY,
                description TEXT NOT NULL,
                category TEXT,
                amount NUMERIC NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log('✅ Expenses table created/ready (PostgreSQL).');

    } catch (err) {
        console.error('Error creating database tables:', err.message);
        process.exit(1); // यदि टेबल्स नहीं बन पाते हैं तो सर्वर बंद करें
    }
}

// --- License Utilities ---

function encryptLicenseKey(key) {
    const cipher = crypto.createCipher('aes-256-cbc', SECRET_KEY);
    let encrypted = cipher.update(key, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

function hashKey(key) {
    return crypto.createHash('sha256').update(key).digest('hex');
}

// --- API Routes ---

// 1. Generate License Key
app.post('/api/generate-key', async (req, res) => {
    const { durationDays, isTrial } = req.body;
    
    // एक रैंडम Key जेनरेट करें
    const rawKey = crypto.randomBytes(16).toString('hex');
    
    // एन्क्रिप्टेड key और hash तैयार करें
    const encryptedKey = encryptLicenseKey(rawKey);
    const keyHash = hashKey(rawKey);

    // समाप्ति तिथि (Expiry Date) की गणना करें
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + (durationDays || 30)); // डिफ़ॉल्ट 30 दिन

    try {
        await pool.query(
            'INSERT INTO licenses (key_hash, expiry_date, is_trial) VALUES ($1, $2, $3)',
            [keyHash, expiryDate, isTrial || false]
        );
        
        // यूज़र को केवल Raw Key दिखाएं (फ्रंट-एंड इसे एन्क्रिप्ट करेगा)
        res.json({ success: true, key: rawKey, message: 'लाइसेंस कुंजी सफलतापूर्वक बनाई गई।' });
    } catch (err) {
        console.error("Error generating key:", err.message);
        res.status(500).json({ success: false, message: 'कुंजी बनाने में विफल: डेटाबेस त्रुटि।' });
    }
});

// 2. Verify License Key (FIXED endpoint name)
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

// 3. Admin Login (Placeholder for Admin Key Generation access)
app.post('/api/admin-login', (req, res) => {
    const { password } = req.body;
    // Note: यहाँ एक सुरक्षित पासवर्ड हैशिंग विधि का उपयोग किया जाना चाहिए (जैसे bcrypt)
    if (password === 'admin123') { // **सुरक्षा के लिए इसे बदलें**
        return res.json({ success: true, message: 'एडमिन लॉगिन सफल।' });
    } else {
        return res.status(401).json({ success: false, message: 'अमान्य एडमिन पासवर्ड।' });
    }
});

// 4. Stock Management - Add/Update (Simplistic Upsert)
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

// 6. Dashboard Data (Summary Metrics)
app.get('/api/get-dashboard-data', async (req, res) => {
    try {
        const totalSalesResult = await pool.query('SELECT COALESCE(SUM(total_amount), 0) AS total_sales_revenue FROM invoices;');
        const totalStockValueResult = await pool.query('SELECT COALESCE(SUM(quantity * purchase_price), 0) AS total_stock_value FROM stock;');
        const totalCustomersResult = await pool.query('SELECT COUNT(*) AS total_customers FROM customers;');
        const lowStockCountResult = await pool.query('SELECT COUNT(*) AS low_stock_count FROM stock WHERE quantity < 10;'); // 10 से कम को Low Stock माना गया
        
        res.json({
            success: true,
            totalSalesRevenue: parseFloat(totalSalesResult.rows[0].total_sales_revenue),
            totalStockValue: parseFloat(totalStockValueResult.rows[0].total_stock_value),
            totalCustomers: parseInt(totalCustomersResult.rows[0].total_customers),
            lowStockCount: parseInt(lowStockCountResult.rows[0].low_stock_count),
        });
    } catch (err) {
        console.error("Error fetching dashboard data:", err.message);
        res.status(500).json({ success: false, message: 'डैशबोर्ड डेटा लोड करने में विफल।' });
    }
});

// 7. NEW API: Get Balance Sheet / Detailed Financials Data (MOST IMPORTANT FIX)
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
    try {
        await pool.query(
            `INSERT INTO purchases (supplier_name, item_details, total_cost) VALUES ($1, $2, $3)`,
            [supplier_name, item_details, total_cost]
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
    try {
        await pool.query(
            `INSERT INTO expenses (description, category, amount) VALUES ($1, $2, $3)`,
            [description, category, amount]
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
        return createTables(); // टेबल्स बनाएं/चेक करें
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
