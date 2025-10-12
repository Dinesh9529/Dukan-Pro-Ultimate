const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 3000;

// 🚨 सुरक्षा नोट: इसे हमेशा Render या किसी होस्टिंग प्लेटफ़ॉर्म पर Environment Variable (ENV) में सेट करें।
// अगर ENV में नहीं मिला, तो यह डिफ़ॉल्ट रूप से 'password123' का उपयोग करेगा।
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'password123'; 

// --- Middleware Setup ---
app.use(cors()); 
app.use(bodyParser.json());

// --- Database Setup (SQLite) ---
const db = new sqlite3.Database('./dukanpro.db', (err) => {
    if (err) {
        console.error('❌ Error opening database ' + err.message);
    } else {
        console.log('✅ Connected to the SQLite database.');
        
        // 1. Core Licenses Table
        db.run(`CREATE TABLE IF NOT EXISTS licenses (
            key TEXT PRIMARY KEY, 
            valid_until DATE, 
            status TEXT
        )`, (err) => {
            if (err) console.error("Error creating licenses table:", err);
            else {
                console.log("Licenses table created/ready.");
                // 💡 टेस्ट के लिए एक डमी वैलिड की डालें: '398844dc1396accf5e8379d8014eebaf:632a0f5b9015ecf744f8e265580e14d44acde25d51376b8b608d503b9c43b801dab098d802949854b8479c5e9d9c1f02'
                const tomorrow = new Date();
                tomorrow.setDate(tomorrow.getDate() + 1); // 1 day validity for test
                db.run("INSERT OR IGNORE INTO licenses (key, valid_until, status) VALUES (?, ?, ?)", 
                    ['398844dc1396accf5e8379d8014eebaf:632a0f5b9015ecf744f8e265580e14d44acde25d51376b8b608d503b9c43b801dab098d802949854b8479c5e9d9c1f02', tomorrow.toISOString().split('T')[0], 'Active']);
            }
        });

        // 2. NEW Invoice Generator Pro Table
        db.run(`CREATE TABLE IF NOT EXISTS invoices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            invoice_number TEXT UNIQUE,
            customer_name TEXT,
            customer_contact TEXT,
            shop_name TEXT,
            grand_total REAL,
            invoice_data TEXT,  /* Storing entire JSON as TEXT */
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`, (err) => {
            if (err) console.error("Error creating invoices table:", err);
            else console.log("Invoices table created/ready.");
        });

        // 3. Add other Dukan Pro tables here (stock, sales, customers, etc.) if needed.
    }
});

// --- API Routes ---

// 1. License Validation API (NEW)
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
            // Check status for specific message
            let message = 'Invalid or expired license key.';
            if (row && row.status !== 'Active') {
                 message = 'License is suspended or terminated.';
            }
            res.status(401).json({ valid: false, message: message });
        }
    });
});

// 2. Save Invoice API (NEW)
app.post('/api/save-invoice', (req, res) => {
    // Note: The index.html now sends the Authorization Bearer token, but we are not enforcing it here
    // for simplicity. In a real app, you would validate the license/user token here.
    
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
        JSON.stringify(invoiceData) // Save the entire object as JSON string
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

// 3. Admin Login API (Existing Dukan Pro Logic)
app.post('/api/admin-login', (req, res) => {
    const { password } = req.body;

    if (password === ADMIN_PASSWORD) {
        res.json({ success: true, message: 'Login successful' });
    } else {
        // Correct status for unauthorized access
        res.status(401).json({ success: false, message: 'Incorrect admin password.' });
    }
});


// 4. Basic Root URL response (for checking server status on Render)
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
