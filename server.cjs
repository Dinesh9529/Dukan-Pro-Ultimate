// server.cjs (Dukan Pro - Ultimate Backend) - CRITICAL FINAL FIX (All SQL commands in single quotes)

const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto');
const cors = require('cors');
require('dotenv').config(); 

const app = express();
const PORT = process.env.PORT || 10000;
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

async function createTables() {
    const client = await pool.connect();
    try {
        console.log('Attempting to ensure all tables exist...');

        // 1. Licenses Table (CRITICAL FIX: Single-line string)
        await client.query('CREATE TABLE IF NOT EXISTS licenses (key_hash TEXT PRIMARY KEY, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, expiry_date TIMESTAMP WITH TIME ZONE, is_trial BOOLEAN DEFAULT FALSE);');

        // 2. Stock Table (Single-line string)
        await client.query('CREATE TABLE IF NOT EXISTS stock (id SERIAL PRIMARY KEY, sku TEXT UNIQUE NOT NULL, name TEXT NOT NULL, quantity NUMERIC NOT NULL, unit TEXT, purchase_price NUMERIC NOT NULL, sale_price NUMERIC NOT NULL, cost_price NUMERIC, category TEXT, gst NUMERIC DEFAULT 0, updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);');
        
        // 3. Customers Table (Single-line string)
        await client.query('CREATE TABLE IF NOT EXISTS customers (id SERIAL PRIMARY KEY, name TEXT NOT NULL, phone TEXT UNIQUE, email TEXT UNIQUE, address TEXT, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);');

        // 4. Invoices Table (Single-line string)
        await client.query('CREATE TABLE IF NOT EXISTS invoices (id SERIAL PRIMARY KEY, customer_id INTEGER REFERENCES customers(id), total_amount NUMERIC NOT NULL, total_cost NUMERIC, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);');

        // 5. Invoice Items Table (Single-line string)
        await client.query('CREATE TABLE IF NOT EXISTS invoice_items (id SERIAL PRIMARY KEY, invoice_id INTEGER REFERENCES invoices(id) ON DELETE CASCADE, item_name TEXT NOT NULL, item_sku TEXT, quantity NUMERIC NOT NULL, sale_price NUMERIC NOT NULL, purchase_price NUMERIC);');
        
        // 6. Purchases Table (Single-line string)
        await client.query('CREATE TABLE IF NOT EXISTS purchases (id SERIAL PRIMARY KEY, supplier_name TEXT, item_details TEXT NOT NULL, total_cost NUMERIC NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);');
        
        // 7. Expenses Table (Single-line string)
        await client.query('CREATE TABLE IF NOT EXISTS expenses (id SERIAL PRIMARY KEY, description TEXT NOT NULL, category TEXT, amount NUMERIC NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);');
        
        console.log('✅ All tables checked/created successfully.');

    } catch (err) {
        console.error('❌ Error ensuring database tables:', err.message);
        process.exit(1);
    } finally {
        client.release();
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
    
    if (password !== ADMIN_PASSWORD) {
        return res.status(401).json({ success: false, message: 'अमान्य एडमिन पासवर्ड।' });
    }
    if (typeof days !== 'number' || days < 1) {
          return res.status(400).json({ success: false, message: 'दिनों की संख्या मान्य होनी चाहिए।' });
    }

    const rawKey = crypto.randomBytes(16).toString('hex');
    const keyHash = hashKey(rawKey);

    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + days);

    try {
        await pool.query(
            'INSERT INTO licenses (key_hash, expiry_date, is_trial) VALUES ($1, $2, $3)',
            [keyHash, expiryDate, days === 5]
        );
        
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
    
    if (!password) {
        return res.status(400).json({ success: false, message: 'पासवर्ड आवश्यक है।' });
    }

    if (password === ADMIN_PASSWORD) {  
        return res.json({ success: true, message: 'एडमिन लॉगिन सफल।' });
    } else {
        return res.status(401).json({ success: false, message: 'अमान्य एडमिन पासवर्ड।' });
    }
});

// 4. Stock Management - Add/Update
app.post('/api/stock', async (req, res) => {
    const { sku, name, quantity, unit, purchase_price, sale_price, gst, cost_price, category } = req.body;
    
    if (!sku || !name || typeof quantity === 'undefined' || typeof purchase_price === 'undefined' || typeof sale_price === 'undefined') {
        return res.status(400).json({ success: false, message: 'SKU, नाम, मात्रा, खरीद मूल्य और बिक्री मूल्य आवश्यक हैं।' });
    }
    
    const safeQuantity = parseFloat(quantity);
    const safePurchasePrice = parseFloat(purchase_price);
    const safeSalePrice = parseFloat(sale_price);
    const safeGst = parseFloat(gst || 0);
    const safeCostPrice = parseFloat(cost_price || safePurchasePrice); 

    if (isNaN(safeQuantity) || isNaN(safePurchasePrice) || isNaN(safeSalePrice)) {
        return res.status(400).json({ success: false, message: 'मात्रा, खरीद मूल्य और बिक्री मूल्य मान्य संख्याएँ होनी चाहिए।' });
    }

    try {
        const result = await pool.query(
            `INSERT INTO stock (sku, name, quantity, unit, purchase_price, sale_price, gst, cost_price, category)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (sku) DO UPDATE
             SET 
                 quantity = stock.quantity + EXCLUDED.quantity, 
                 purchase_price = EXCLUDED.purchase_price,
                 sale_price = EXCLUDED.sale_price,
                 gst = EXCLUDED.gst,
                   cost_price = EXCLUDED.cost_price,
                   category = EXCLUDED.category,
                 updated_at = CURRENT_TIMESTAMP
             RETURNING *;`,
            [sku, name, safeQuantity, unit, safePurchasePrice, safeSalePrice, safeGst, safeCostPrice, category]
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
        const salesResult = await pool.query("SELECT COALESCE(SUM(total_amount), 0) AS value FROM invoices");
        const totalSalesRevenue = parseFloat(salesResult.rows[0].value);

        const stockValueResult = await pool.query("SELECT COALESCE(SUM(cost_price * quantity), 0) AS value FROM stock");
        const totalStockValue = parseFloat(stockValueResult.rows[0].value);
        
        const customerResult = await pool.query("SELECT COUNT(DISTINCT id) AS value FROM customers");
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
        console.error('डैशबोर्ड डेटा SQL/PostgreSQL एरर:', error.message);
        res.status(500).json({ success: false, message: 'डैशबोर्ड डेटा लोड नहीं किया जा सका: ' + error.message });
    }
});

// 7. Get Low Stock Items List for Dashboard
app.get('/api/get-low-stock-items', async (req, res) => {
    try {
        const result = await pool.query("SELECT sku, name, quantity FROM stock WHERE quantity < 10 ORDER BY quantity ASC");
        res.json({ success: true, items: result.rows });
    } catch (error) {
        console.error('Low stock items SQL/PostgreSQL एरर:', error.message);
        res.status(500).json({ success: false, message: 'कम स्टॉक वाले आइटम लोड नहीं किए जा सके।' });
    }
});

// 8. Get Recent Sales for Dashboard
app.get('/api/get-recent-sales', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                i.id AS invoice_id, 
                COALESCE(c.name, 'अनाम ग्राहक') AS customer_name, 
                i.total_amount, 
                i.created_at 
            FROM invoices i
            LEFT JOIN customers c ON i.customer_id = c.id
            ORDER BY i.created_at DESC 
            LIMIT 5
        `);
        res.json({ success: true, sales: result.rows });
    } catch (error) {
        console.error('Recent sales SQL/PostgreSQL एरर:', error.message);
        res.status(500).json({ success: false, message: 'हाल की बिक्री लोड नहीं की जा सकी।' });
    }
});

// 9. Get Recent Customers for Dashboard
app.get('/api/get-recent-customers', async (req, res) => {
    try {
        const result = await pool.query("SELECT name, phone, created_at FROM customers ORDER BY created_at DESC LIMIT 5");
        res.json({ success: true, customers: result.rows });
    } catch (error) {
        console.error('Recent customers SQL/PostgreSQL एरर:', error.message);
        res.status(500).json({ success: false, message: 'हाल के ग्राहक लोड नहीं किए जा सके।' });
    }
});

// 10. Get Balance Sheet / Detailed Financials Data 
app.get('/api/get-balance-sheet-data', async (req, res) => {
    try {
        const inventoryValueResult = await pool.query(`
            SELECT COALESCE(SUM(quantity * cost_price), 0) AS inventory_value FROM stock;
        `);
        const currentInventoryValue = parseFloat(inventoryValueResult.rows[0].inventory_value);

        const revenueResult = await pool.query(`
            SELECT COALESCE(SUM(total_amount), 0) AS total_revenue FROM invoices;
        `);
        const totalRevenue = parseFloat(revenueResult.rows[0].total_revenue);

        const purchasesResult = await pool.query(`
            SELECT COALESCE(SUM(total_cost), 0) AS total_purchases FROM purchases;
        `);
        const totalPurchases = parseFloat(purchasesResult.rows[0].total_purchases);

        const expensesResult = await pool.query(`
            SELECT COALESCE(SUM(amount), 0) AS total_expenses FROM expenses;
        `);
        const totalExpenses = parseFloat(expensesResult.rows[0].total_expenses);
        
        const grossProfit = totalRevenue - totalPurchases;
        const netProfit = grossProfit - totalExpenses;
        const totalAssets = currentInventoryValue; 
        
        res.json({
            success: true,
            balanceSheet: {
                currentAssets: totalAssets,
                totalLiabilities: 0.00,
                netWorth: totalAssets, 
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


// --- CRM API Routes ---

// 11. Add Customer
app.post('/api/customer', async (req, res) => {
    const { name, phone, email, address } = req.body;
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

// 12. Get Customers
app.get('/api/customer', async (req, res) => {
    try {
        const result = await pool.query(`SELECT * FROM customers ORDER BY created_at DESC;`);
        res.json({ success: true, customers: result.rows });
    } catch (err) {
        console.error("Error fetching customers:", err.message);
        res.status(500).json({ success: false, message: 'ग्राहक सूची प्राप्त करने में विफल।' });
    }
});


// --- Purchases API Routes ---

// 13. Add Purchase
app.post('/api/purchase', async (req, res) => {
    const { supplier_name, item_details, total_cost } = req.body;
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

// 14. Get Purchases
app.get('/api/purchase', async (req, res) => {
    try {
        const result = await pool.query(`SELECT * FROM purchases ORDER BY created_at DESC;`);
        res.json({ success: true, purchases: result.rows });
    } catch (err) {
        console.error("Error fetching purchases:", err.message);
        res.status(500).json({ success: false, message: 'खरीद सूची प्राप्त करने में विफल।' });
    }
});

// --- Expenses API Routes ---

// 15. Add Expense
app.post('/api/expense', async (req, res) => {
    const { description, category, amount } = req.body;
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

// 16. Get Expenses
app.get('/api/expense', async (req, res) => {
    try {
        const result = await pool.query(`SELECT * FROM expenses ORDER BY created_at DESC;`);
        res.json({ success: true, expenses: result.rows });
    } catch (err) {
        console.error("Error fetching expenses:", err.message);
        res.status(500).json({ success: false, message: 'खर्च सूची प्राप्त करने में विफल।' });
    }
});


// --- SALES / INVOICES API Routes ---

// 17. Get Invoices/Sales List (Resolves 404 for /api/invoices)
app.get('/api/invoices', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                i.id, i.total_amount, i.created_at, 
                COALESCE(c.name, 'अज्ञात ग्राहक') AS customer_name
            FROM invoices i
            LEFT JOIN customers c ON i.customer_id = c.id
            ORDER BY i.created_at DESC
            LIMIT 50
        `);
        res.json({ success: true, sales: result.rows, message: "चालान सफलतापूर्वक लोड किए गए।" });
    } catch (error) {
        console.error("Error fetching invoices:", error.message);
        res.status(500).json({ success: false, message: "चालान डेटा लोड करने में विफल।" });
    }
});

// 18. Process New Sale / Create Invoice (Core POS Logic)
app.post('/api/invoices', async (req, res) => {
    const { customer_id, total_amount, items } = req.body; 
    
    if (!total_amount || !items || items.length === 0) {
        return res.status(400).json({ success: false, message: 'कुल राशि और बिक्री आइटम आवश्यक हैं।' });
    }

    const client = await pool.connect();
    
    try {
        await client.query('BEGIN'); // Transaction Start
        
        const safeTotalAmount = parseFloat(total_amount);
        let calculatedTotalCost = 0;
        
        // 1. Create the Invoice header
        const invoiceResult = await client.query(
            `INSERT INTO invoices (customer_id, total_amount) VALUES ($1, $2) RETURNING id`,
            [customer_id || null, safeTotalAmount]
        );
        const invoiceId = invoiceResult.rows[0].id;
        
        // 2. Insert Invoice Items and Update Stock 
        for (const item of items) {
            const safeQuantity = parseFloat(item.quantity);
            const safeSalePrice = parseFloat(item.sale_price);
            const safePurchasePrice = parseFloat(item.purchase_price);

            calculatedTotalCost += safeQuantity * safePurchasePrice;

            // Insert into invoice_items
            await client.query(
                `INSERT INTO invoice_items (invoice_id, item_name, item_sku, quantity, sale_price, purchase_price) VALUES ($1, $2, $3, $4, $5, $6)`,
                [invoiceId, item.name, item.sku, safeQuantity, safeSalePrice, safePurchasePrice]
            );
            
            // Decrease Stock Quantity 
            await client.query(
                `UPDATE stock SET quantity = quantity - $1 WHERE sku = $2`,
                [safeQuantity, item.sku]
            );
        }

        // 3. Update Invoice with total_cost
        await client.query(
            `UPDATE invoices SET total_cost = $1 WHERE id = $2`,
            [calculatedTotalCost, invoiceId]
        );

        await client.query('COMMIT'); // Transaction End
        res.json({ success: true, invoice_id: invoiceId, message: 'बिक्री सफलतापूर्वक दर्ज की गई और स्टॉक अपडेट किया गया।' });

    } catch (error) {
        await client.query('ROLLBACK'); // Transaction Rollback on error
        console.error("Error processing sale/invoice:", error.message);
        res.status(500).json({ success: false, message: 'बिक्री दर्ज करने में विफल: ' + error.message });
    } finally {
        client.release();
    }
});


// --- Server Initialization ---

pool.connect()
    .then(() => {
        console.log('PostgreSQL connection established.');
        return createTables(); 
    })
    .then(() => {
        app.listen(PORT, '0.0.0.0', () => {
            console.log(`Server is running on port ${PORT} at 0.0.0.0`);
        });
    })
    .catch(err => {
        console.error('Database connection failed:', err.message);
        process.exit(1);
    });
