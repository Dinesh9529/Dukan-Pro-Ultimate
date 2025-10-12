            import express from 'express';
import cors from 'cors';
import pkg from 'pg'; // PostgreSQL Client
const { Client } = pkg;

const app = express();
const PORT = process.env.PORT || 3000;

// 🚨 ADMIN PASSWORD: इसे Render पर Environment Variable (ENV) में सेट करना सुनिश्चित करें।
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'password123'; 

// --- Middleware Setup ---
app.use(cors()); 
app.use(express.json()); // JSON बॉडी पार्स करने के लिए

// --- Database Setup (PostgreSQL) ---
if (!process.env.DATABASE_URL) {
    console.error("❌ DATABASE_URL environment variable is not set. Cannot connect to Postgres.");
    process.exit(1);
}

const client = new Client({
    connectionString: process.env.DATABASE_URL,
    // Render/External connections के लिए SSL आवश्यक है
    ssl: {
        rejectUnauthorized: false 
    }
});

// Database Connection and Table Initialization
async function initializeDatabase() {
    try {
        await client.connect();
        console.log('✅ Connected to PostgreSQL database.');

        // 1. Licenses Table (Dukan Pro License Check)
        await client.query(`
            CREATE TABLE IF NOT EXISTS licenses (
                key TEXT PRIMARY KEY, 
                valid_until DATE, 
                status TEXT
            );
        `);
        
        // 2. NEW Invoices Table (For SQL Saving)
        await client.query(`
            CREATE TABLE IF NOT EXISTS invoices (
                id SERIAL PRIMARY KEY,
                invoice_number TEXT UNIQUE,
                customer_name TEXT,
                customer_contact TEXT,
                shop_name TEXT,
                grand_total REAL,
                invoice_data JSONB,  
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 3. (Optional) Add your other Dukan Pro tables here (stock, sales, customers, etc.) if they don't exist yet.

        console.log('Database tables verified/ready.');

        // Insert dummy key for testing (only if it doesn't exist)
        const tomorrow = new Date();
        tomorrow.setDate(tomorrow.getDate() + 1);
        await client.query(`
            INSERT INTO licenses (key, valid_until, status) 
            VALUES ($1, $2, $3)
            ON CONFLICT (key) DO NOTHING;
        `, ['398844dc1396accf5e8379d8014eebaf:632a0f5b9015ecf744f8e265580e14d44acde25d51376b8b608d503b9c43b801dab098d802949854b8479c5e9d9c1f02', tomorrow.toISOString().split('T')[0], 'Active']);

    } catch (error) {
        console.error('❌ Database initialization error (Check DATABASE_URL):', error.message);
        process.exit(1); // Exit if DB connection fails
    }
}
initializeDatabase();

// --- API Routes ---

// 1. License Validation API (NEW ROUTE)
app.get('/api/validate-key', async (req, res) => {
    const key = req.query.key;
    if (!key) {
        return res.status(400).json({ valid: false, message: 'License key is required.' });
    }

    try {
        const result = await client.query("SELECT valid_until, status FROM licenses WHERE key = $1", [key]);
        const row = result.rows[0];

        if (row && row.status === 'Active' && new Date(row.valid_until) >= new Date()) {
            res.json({ valid: true, message: 'License is valid.' });
        } else {
            let message = 'Invalid or expired license key.';
            if (row && row.status !== 'Active') {
                 message = 'License is suspended or terminated.';
            }
            res.status(401).json({ valid: false, message: message });
        }
    } catch (error) {
        console.error("Error validating license:", error);
        res.status(500).json({ valid: false, message: 'Internal server error during validation.' });
    }
});

// 2. Save Invoice API (NEW ROUTE)
app.post('/api/save-invoice', async (req, res) => {
    const invoiceData = req.body;
    const { invoiceNumber, customerName, customerContact, shopName, grandTotal } = invoiceData;

    if (!invoiceNumber || typeof grandTotal !== 'number' || grandTotal < 0) {
        return res.status(400).json({ success: false, message: 'Missing essential invoice data (Number or Total).' });
    }

    const sql = `INSERT INTO invoices 
                 (invoice_number, customer_name, customer_contact, shop_name, grand_total, invoice_data) 
                 VALUES ($1, $2, $3, $4, $5, $6) 
                 RETURNING id`;
    
    try {
        const result = await client.query(sql, [
            invoiceNumber,
            customerName || 'N/A',
            customerContact || 'N/A',
            shopName || 'N/A',
            grandTotal,
            JSON.stringify(invoiceData) // Save the entire object as JSON string
        ]);

        res.json({ success: true, message: 'Invoice saved successfully.', invoiceId: result.rows[0].id });
    } catch (err) {
        // PostgreSQL duplicate key error code is 23505
        if (err.code === '23505') {
             return res.status(409).json({ success: false, message: 'Invoice with this number already exists.' });
        }
        console.error("Error saving invoice:", err);
        return res.status(500).json({ success: false, message: 'Database error while saving invoice.' });
    }
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
process.on('SIGINT', async () => {
    await client.end();
    console.log('PostgreSQL connection closed.');
    process.exit(0);
});
          
