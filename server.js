      import express from 'express';
import { verbose } from 'sqlite3'; // 'sqlite3' को 'import' करें
import cors from 'cors';

const app = express();
const PORT = process.env.PORT || 3000;

// 🚨 ADMIN PASSWORD: इसे Render पर Environment Variable (ENV) में सेट करें।
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'password123'; 

// --- Middleware Setup ---
app.use(cors()); 
app.use(express.json()); // JSON बॉडी पार्स करने के लिए
// Note: अब 'body-parser' की आवश्यकता नहीं है।

// --- Database Setup (SQLite) ---
const db = new verbose().Database('./dukanpro.db', (err) => {
    if (err) {
        console.error('❌ Error opening database ' + err.message);
    } else {
        console.log('✅ Connected to the SQLite database.');
        
        // 1. Core Licenses Table (Dukan Pro License Check)
        db.run(`CREATE TABLE IF NOT EXISTS licenses (
            key TEXT PRIMARY KEY, 
            valid_until DATE, 
            status TEXT
        )`, (err) => {
            if (err) console.error("Error creating licenses table:", err);
            else {
                console.log("Licenses table created/ready.");
                // टेस्टिंग के लिए डमी वैलिड की (कल तक वैध)
                const tomorrow = new Date();
                tomorrow.setDate(tomorrow.getDate() + 1); 
                db.run("INSERT OR IGNORE INTO licenses (key, valid_until, status) VALUES (?, ?, ?)", 
                    ['398844dc1396accf5e8379d8014eebaf:632a0f5b9015ecf744f8e265580e14d44acde25d51376b8b608d503b9c43b801dab098d802949854b8479c5e9d9c1f02', tomorrow.toISOString().split('T')[0], 'Active']);
            }
        });

        // 2. NEW Invoice Generator Pro Table (For SQL Saving)
        db.run(`CREATE TABLE IF NOT EXISTS invoices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            invoice_number TEXT UNIQUE,
            customer_name TEXT,
            customer_contact TEXT,
            shop_name TEXT,
            grand_total REAL,
            invoice_data TEXT,  
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`, (err) => {
            if (err) console.error("Error creating invoices table:", err);
            else console.log("Invoices table created/ready.");
        });

        // 3. (Optional) Add your other Dukan Pro tables here (stock, sales, customers, etc.)
    }
});

// --- API Routes ---

// 1. License Validation API (NEW ROUTE)
app.get('/api/validate-key', (req, res) => {
    const key = req.query.key;
    if (!key) {
        return res.status(400).json({ valid: false, message: 'License key is required.' });
    }

    db.get("SELECT valid_until, status FROM licenses WHERE key = ?", [key], (err, row) => {
        if (err) {
            console.error("Database error during license check:", err.message);
            return res.status(500).json({ valid: false, message: 'Internal server error.' });
        }

        if (row && row.status === 'Active' && new Date(row.valid_until) >= new Date()) {
            res.json({ valid: true, message: 'License is valid.' });
        } else {
            let message = 'Invalid or expired license key.';
            if (row && row.status !== 'Active') {
                 message = 'License is suspended or terminated.';
            }
            res.status(401).json({ valid: false, message: message });
        }
    });
});

// 2. Save Invoice API (NEW ROUTE for SQL Saving)
app.post('/api/save-invoice', (req, res) => {
    const invoiceData = req.body;
    const { invoiceNumber, customerName, customerContact, shopName, grandTotal } = invoiceData;

    if (!invoiceNumber || typeof grandTotal !== 'number' || grandTotal < 0) {
        return res.status(400).json({ success: false, message: 'Missing essential invoice data (Number or Total).' });
    }

    const sql = `INSERT INTO invoices 
                 (invoice_number, customer_name, customer_contact, shop_name, grand_total, invoice_data) 
                 VALUES (?, ?, ?, ?, ?, ?)`;
    
    db.run(sql, [
        invoiceNumber,
        customerName || 'N/A',
        customerContact || 'N/A',
        shopName || 'N/A',
        grandTotal,
        JSON.stringify(invoiceData) 
    ], function(err) {
        if (err) {
            if (err.message.includes('UNIQUE constraint failed')) {
                 return res.status(409).json({ success: false, message: 'Invoice with this number already exists.' });
            }
            console.error("Error saving invoice:", err.message);
            return res.status(500).json({ success: false, message: 'Database error while saving invoice.' });
        }
        res.json({ success: true, message: 'Invoice saved successfully.', invoiceId: this.lastID });
    });
});

// 3. Admin Login API (EXISTING ROUTE)
app.post('/api/admin-login', (req, res) => {
    const { password } = req.body;

    if (password === ADMIN_PASSWORD) {
        res.json({ success: true, message: 'Login successful' });
    } else {
        res.status(401).json({ success: false, message: 'Incorrect admin password.' });
    }
});


// 4. Basic Root URL response
app.get('/', (req, res) => {
    res.send('Dukan Pro Ultimate Backend is running! API Routes: /api/validate-key, /api/save-invoice, /api/admin-login');
});

// --- Server Start ---
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

// Handle graceful shutdown
process.on('SIGINT', () => {
    db.close(() => {
        console.log('Database connection closed.');
        process.exit(0);
    });
});
  
