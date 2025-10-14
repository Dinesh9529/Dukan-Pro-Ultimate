// server.cjs

const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const path = require('path'); // Node.js में path मॉड्यूल का उपयोग करें

const app = express();
const PORT = process.env.PORT || 10000;

// --- Database Configuration (डाटाबेस कॉन्फ़िगरेशन) ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false // Render के लिए आवश्यक
    }
});

// --- Table Creation Logic (टेबल निर्माण लॉजिक) ---
async function createTables() {
    try {
        // STOCK table - (IF NOT EXISTS ensures it only runs once)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS stock (
                id SERIAL PRIMARY KEY,
                sku VARCHAR(50) UNIQUE NOT NULL,
                name VARCHAR(255) NOT NULL,
                category VARCHAR(100),
                cost_price NUMERIC(10, 2) NOT NULL,
                sale_price NUMERIC(10, 2) NOT NULL,
                quantity INTEGER NOT NULL DEFAULT 0,
                gst NUMERIC(5, 2) DEFAULT 0,
                unit VARCHAR(50),
                low_stock_threshold INTEGER DEFAULT 10,
                last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        
        // CATEGORIES table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS categories (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) UNIQUE NOT NULL
            );
        `);
        
        // CUSTOMERS table (New)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS customers (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) UNIQUE NOT NULL,
                phone VARCHAR(20) DEFAULT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // INVOICES table (New)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS invoices (
                id SERIAL PRIMARY KEY,
                customer_id INTEGER REFERENCES customers(id) ON DELETE SET NULL, 
                total_amount NUMERIC(10, 2) NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // INVOICE_ITEMS table (New)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS invoice_items (
                id SERIAL PRIMARY KEY,
                invoice_id INTEGER NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
                item_name VARCHAR(255) NOT NULL,
                quantity INTEGER NOT NULL,
                sale_price NUMERIC(10, 2) NOT NULL
            );
        `);

        // PURCHASES table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS purchases (
                id SERIAL PRIMARY KEY,
                vendor_name VARCHAR(255) NOT NULL,
                item_name VARCHAR(255) NOT NULL,
                quantity INTEGER NOT NULL,
                purchase_price NUMERIC(10, 2) NOT NULL,
                purchase_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // EXPENSES table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS expenses (
                id SERIAL PRIMARY KEY,
                description VARCHAR(255) NOT NULL,
                amount NUMERIC(10, 2) NOT NULL,
                category VARCHAR(100),
                expense_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        
        // SETTINGS table (For Admin/License)
         await pool.query(`
            CREATE TABLE IF NOT EXISTS settings (
                key VARCHAR(50) UNIQUE NOT NULL,
                value TEXT,
                PRIMARY KEY (key)
            );
        `);

        console.log("✅ All tables checked/created successfully (Data retained).");
        return true;
    } catch (error) {
        console.error("Error ensuring tables exist:", error.message);
        throw error; // त्रुटि को आगे बढ़ाएं
    }
}


// --- Middlewares (मिडिलवेयर्स) ---

// सुरक्षित CORS लॉजिक
app.use(cors({
    origin: (origin, callback) => {
        // null, undefined, या खाली स्ट्रिंग (स्थानीय फ़ाइलें या कुछ ऐप्स) को अनुमति दें
        const isLocalFileOrigin = origin === null || origin === undefined || origin === ''; 
        // वैध वेब Origins (http:// या https://) को अनुमति दें
        const isWebOrigin = origin && (origin.startsWith('http://') || origin.startsWith('https://'));

        if (isLocalFileOrigin || isWebOrigin) {
            callback(null, true); // ALLOW
        } else {
            // यदि यह कोई और अजीब origin है तो ब्लॉक करें
            console.error(`Error: Not allowed by CORS. Origin: ${origin}`);
            callback(new Error('Not allowed by CORS'), false); // DENY
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
}));

// JSON बॉडी पार्सर
app.use(express.json());


// --- API Endpoints (API एंडपॉइंट्स) ---

// 1. Get Dashboard Data
app.get('/api/get-dashboard-data', async (req, res) => {
    try {
        const totalStockValue = await pool.query('SELECT COALESCE(SUM(quantity * cost_price), 0) AS value FROM stock');
        const lowStockCount = await pool.query('SELECT COUNT(*) FROM stock WHERE quantity <= low_stock_threshold');
        
        // हाल की बिक्री का डेटा (उदाहरण के लिए, पिछले 7 दिनों का)
        const recentSales = await pool.query(`
            SELECT 
                DATE(created_at) as date, 
                SUM(total_amount) as total_sales 
            FROM invoices 
            WHERE created_at >= NOW() - INTERVAL '7 days'
            GROUP BY date 
            ORDER BY date;
        `);

        res.json({
            success: true,
            data: {
                totalStockValue: parseFloat(totalStockValue.rows[0].value),
                lowStockCount: parseInt(lowStockCount.rows[0].count),
                recentSales: recentSales.rows
            }
        });
    } catch (err) {
        console.error("Error fetching dashboard data:", err.message);
        res.status(500).json({ success: false, message: 'डैशबोर्ड डेटा प्राप्त करने में विफल।' });
    }
});


// 2. Get All Stock Items
app.get('/api/stock', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM stock ORDER BY name ASC');
        res.json({ success: true, stock: result.rows });
    } catch (err) {
        console.error("Error fetching stock:", err.message);
        res.status(500).json({ success: false, message: 'स्टॉक सूची प्राप्त करने में विफल।' });
    }
});

// 3. Add New Stock Item
app.post('/api/stock', async (req, res) => {
    const { sku, name, category, cost_price, sale_price, quantity, gst, unit, low_stock_threshold } = req.body;
    try {
        const result = await pool.query(
            `INSERT INTO stock (sku, name, category, cost_price, sale_price, quantity, gst, unit, low_stock_threshold) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
            [sku, name, category, cost_price, sale_price, quantity, gst, unit, low_stock_threshold]
        );
        res.status(201).json({ success: true, item: result.rows[0], message: 'आइटम सफलतापूर्वक जोड़ा गया।' });
    } catch (err) {
        console.error("Error adding stock:", err.message);
        res.status(500).json({ success: false, message: 'स्टॉक जोड़ने में विफल। SKU शायद पहले से मौजूद है।' });
    }
});

// 4. Update Stock Item
app.put('/api/stock/:sku', async (req, res) => {
    const { sku } = req.params;
    const { name, category, cost_price, sale_price, quantity, gst, unit, low_stock_threshold } = req.body;
    try {
        const result = await pool.query(
            `UPDATE stock SET name = $1, category = $2, cost_price = $3, sale_price = $4, quantity = $5, gst = $6, unit = $7, low_stock_threshold = $8, last_updated = CURRENT_TIMESTAMP 
             WHERE sku = $9 RETURNING *`,
            [name, category, cost_price, sale_price, quantity, gst, unit, low_stock_threshold, sku]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'आइटम नहीं मिला।' });
        }
        res.json({ success: true, item: result.rows[0], message: 'आइटम सफलतापूर्वक अपडेट किया गया।' });
    } catch (err) {
        console.error("Error updating stock:", err.message);
        res.status(500).json({ success: false, message: 'स्टॉक अपडेट करने में विफल।' });
    }
});

// 5. Delete Stock Item
app.delete('/api/stock/:sku', async (req, res) => {
    const { sku } = req.params;
    try {
        const result = await pool.query('DELETE FROM stock WHERE sku = $1 RETURNING *', [sku]);
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'आइटम नहीं मिला।' });
        }
        res.json({ success: true, message: 'आइटम सफलतापूर्वक डिलीट किया गया।' });
    } catch (err) {
        console.error("Error deleting stock:", err.message);
        res.status(500).json({ success: false, message: 'स्टॉक डिलीट करने में विफल।' });
    }
});


// 6. Get All Categories
app.get('/api/categories', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM categories ORDER BY name ASC');
        res.json({ success: true, categories: result.rows });
    } catch (err) {
        console.error("Error fetching categories:", err.message);
        res.status(500).json({ success: false, message: 'श्रेणियाँ प्राप्त करने में विफल।' });
    }
});


// 7. Get All Customers
app.get('/api/customer', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM customers ORDER BY name ASC');
        res.json({ success: true, customers: result.rows });
    } catch (err) {
        console.error("Error fetching customers:", err.message);
        res.status(500).json({ success: false, message: 'ग्राहक सूची प्राप्त करने में विफल।' });
    }
});


// 8. Get All Purchases
app.get('/api/purchases', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM purchases ORDER BY purchase_date DESC');
        res.json({ success: true, purchases: result.rows });
    } catch (err) {
        console.error("Error fetching purchases:", err.message);
        res.status(500).json({ success: false, message: 'खरीद सूची प्राप्त करने में विफल।' });
    }
});

// 9. Add New Purchase
app.post('/api/purchases', async (req, res) => {
    const { vendor_name, item_name, quantity, purchase_price } = req.body;
    const client = await pool.connect();
    try {
        await client.query('BEGIN'); // Transaction शुरू करें

        // 1. Purchases टेबल में एंट्री करें
        await client.query(
            'INSERT INTO purchases (vendor_name, item_name, quantity, purchase_price) VALUES ($1, $2, $3, $4)',
            [vendor_name, item_name, quantity, purchase_price]
        );
        
        // 2. स्टॉक अपडेट करें (यदि item_name stock टेबल में है)
        await client.query(
            `UPDATE stock SET quantity = quantity + $1, cost_price = $2 
             WHERE name = $3`,
            [quantity, purchase_price, item_name]
        );

        await client.query('COMMIT'); // Transaction सफल
        res.status(201).json({ success: true, message: 'खरीद सफलतापूर्वक दर्ज की गई और स्टॉक अपडेट किया गया।' });
    } catch (err) {
        await client.query('ROLLBACK'); // अगर कोई त्रुटि हो तो सभी बदलाव वापस लें
        console.error("Error adding purchase:", err.message);
        res.status(500).json({ success: false, message: 'खरीद दर्ज करने में विफल: ' + err.message });
    } finally {
        client.release();
    }
});

// 10. Get All Expenses
app.get('/api/expenses', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM expenses ORDER BY expense_date DESC');
        res.json({ success: true, expenses: result.rows });
    } catch (err) {
        console.error("Error fetching expenses:", err.message);
        res.status(500).json({ success: false, message: 'खर्च सूची प्राप्त करने में विफल।' });
    }
});

// 11. Add New Expense
app.post('/api/expenses', async (req, res) => {
    const { description, amount, category } = req.body;
    try {
        const result = await pool.query(
            'INSERT INTO expenses (description, amount, category) VALUES ($1, $2, $3) RETURNING *',
            [description, amount, category]
        );
        res.status(201).json({ success: true, expense: result.rows[0], message: 'खर्च सफलतापूर्वक दर्ज किया गया।' });
    } catch (err) {
        console.error("Error adding expense:", err.message);
        res.status(500).json({ success: false, message: 'खर्च दर्ज करने में विफल।' });
    }
});

// 12. Admin Login (Dummy for now)
app.post('/api/admin-login', async (req, res) => {
    const { password } = req.body;
    try {
        // इसे वास्तविक डेटाबेस चेक से बदलें
        if (password === 'admin123') { 
            res.json({ success: true, token: 'dummy-token' });
        } else {
            res.status(401).json({ success: false, message: 'अमान्य पासवर्ड।' });
        }
    } catch (err) {
        res.status(500).json({ success: false, message: 'लॉगिन विफल।' });
    }
});


// 13. Get All Invoices (for Sales page) - NEW
app.get('/api/invoices', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                i.id,
                COALESCE(c.name, 'अनाम ग्राहक') as customer_name,
                i.total_amount,
                i.created_at
            FROM invoices i
            LEFT JOIN customers c ON i.customer_id = c.id
            ORDER BY i.created_at DESC
            LIMIT 50;
        `);
        res.json({ success: true, invoices: result.rows });
    } catch (err) {
        console.error("Error fetching invoices:", err.message);
        res.status(500).json({ success: false, message: 'चालान सूची प्राप्त करने में विफल।' });
    }
});

// 14. Create New Invoice (POS Sale) - NEW
app.post('/api/invoices', async (req, res) => {
    const { customerName, items, totalAmount } = req.body;
    
    // इनपुट की जाँच करें
    if (!Array.isArray(items) || items.length === 0 || !totalAmount) {
        return res.status(400).json({ success: false, message: 'अमान्य अनुरोध: कार्ट में आइटम और कुल राशि आवश्यक है।' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN'); // Transaction शुरू करें

        let customerId = null;
        if (customerName) {
            // ग्राहक को खोजें या नया बनाएं
            let customerRes = await client.query('SELECT id FROM customers WHERE name = $1', [customerName]);
            if (customerRes.rows.length > 0) {
                customerId = customerRes.rows[0].id;
            } else {
                let newCustomerRes = await client.query(
                    'INSERT INTO customers (name) VALUES ($1) RETURNING id',
                    [customerName]
                );
                customerId = newCustomerRes.rows[0].id;
            }
        }

        // 1. Invoices टेबल में एंट्री करें
        const invoiceRes = await client.query(
            'INSERT INTO invoices (customer_id, total_amount) VALUES ($1, $2) RETURNING id',
            [customerId, totalAmount]
        );
        const invoiceId = invoiceRes.rows[0].id;

        // 2. हर आइटम के लिए, invoice_items में एंट्री करें और स्टॉक कम करें
        for (const item of items) {
            // item.name, item.quantity, item.sale_price क्लाइंट से आ रहे हैं
            await client.query(
                'INSERT INTO invoice_items (invoice_id, item_name, quantity, sale_price) VALUES ($1, $2, $3, $4)',
                [invoiceId, item.name, item.quantity, item.sale_price]
            );
            
            // 3. स्टॉक अपडेट करें (sku के आधार पर)
            await client.query(
                'UPDATE stock SET quantity = quantity - $1 WHERE sku = $2',
                [item.quantity, item.sku]
            );
        }

        await client.query('COMMIT'); // Transaction सफल, बदलाव सेव करें
        res.status(201).json({ success: true, message: 'बिक्री सफलतापूर्वक पूरी हुई!', invoiceId: invoiceId });

    } catch (err) {
        await client.query('ROLLBACK'); // अगर कोई त्रुटि हो तो सभी बदलाव वापस लें
        console.error("Error creating invoice:", err.message);
        res.status(500).json({ success: false, message: 'बिक्री पूरी करने में विफल: ' + err.message });
    } finally {
        client.release(); // कनेक्शन को वापस पूल में भेजें
    }
});


// --- Server Initialization (सर्वर शुरू करना) ---

pool.connect()
    .then(() => {
        console.log('PostgreSQL connection established.');
        return createTables();
    })
    .then(() => {
        // 0.0.0.0 IP एड्रेस पर बाइंड करना अनिवार्य है
        app.listen(PORT, '0.0.0.0', () => { 
            console.log(`Server is running on port ${PORT} at 0.0.0.0`);
        });
    })
    .catch(err => {
        console.error('Database connection failed:', err.message);
        process.exit(1); // गंभीर त्रुटि पर बाहर निकलें
    });
