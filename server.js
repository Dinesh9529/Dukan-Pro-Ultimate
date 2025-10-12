import express from 'express';
import cors from 'cors';
import pg from 'pg'; 
import crypto from 'crypto'; // Key Generation के लिए 

const { Pool } = pg; 

const app = express();
const PORT = process.env.PORT || 3000;

// 🚨 ENVIRONMENT VARIABLES: Render पर इन्हें सेट करना ज़रूरी है।
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Dkc@#9529561113@abc'; 
const DATABASE_URL = process.env.DATABASE_URL;

// यदि DATABASE_URL सेट नहीं है, तो तुरंत क्रैश करें।
if (!DATABASE_URL) {
    console.error('❌ ERROR: DATABASE_URL environment variable is not set!');
    process.exit(1);
}

// --- Utility Function ---
// Function to generate a long, unique license key (32:64 format)
function generateLicenseKey() {
    // Generate a 32-character hex part
    const part1 = crypto.randomBytes(16).toString('hex');
    // Generate a 64-character hex part
    const part2 = crypto.randomBytes(32).toString('hex');
    return `${part1}:${part2}`;
}

// --- Database Setup (PostgreSQL) ---
const pool = new Pool({
    connectionString: DATABASE_URL,
    // FIX: Render पर बाहरी कनेक्शनों के लिए SSL आवश्यक है।
    ssl: { rejectUnauthorized: false } 
});

pool.on('error', (err, client) => {
    console.error('❌ Unexpected error on idle client', err);
    process.exit(-1);
});

async function setupDatabase() {
    try {
        const client = await pool.connect();

        // 1. Core Licenses Table (CLEANED SQL)
        await client.query(`
            CREATE TABLE IF NOT EXISTS licenses (
                key TEXT PRIMARY KEY, 
                valid_until DATE, 
                status TEXT
            );
        `);
        console.log("✅ Licenses table created/ready (PostgreSQL).");

        // Testing: Insert dummy valid key (CLEANED SQL)
        const tomorrow = new Date();
        tomorrow.setDate(tomorrow.getDate() + 1); 
        await client.query(`
            INSERT INTO licenses (key, valid_until, status) VALUES ($1, $2, $3)
            ON CONFLICT (key) DO NOTHING;
        `, ['398844dc1396accf5e8379d8014eebaf:632a0f5b9015ecf744f8e265580e14d44acde25d51376b8b608d503b9c43b801dab098d802949854b8479c5e9d9c1f02', tomorrow.toISOString().split('T')[0], 'Active']);

        // 2. Invoice Generator Pro Table (CLEANED SQL)
        await client.query(`
            CREATE TABLE IF NOT EXISTS invoices (
                id SERIAL PRIMARY KEY,
                invoice_number TEXT UNIQUE,
                customer_name TEXT,
                customer_contact TEXT,
                shop_name TEXT,
                grand_total REAL,
                invoice_data TEXT,  
                created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log("✅ Invoices table created/ready (PostgreSQL).");
        
        client.release();
        
    } catch (err) {
        // यह यहाँ पकड़ेगा अगर DATABASE_URL गलत है या SSL काम नहीं कर रहा है।
        console.error('❌ Database setup error:', err);
        process.exit(1);
    }
}

// --- Middleware Setup ---
app.use(cors()); 
app.use(express.json());

// --- API Routes ---

// 1. License Validation API
app.get('/api/validate-key', async (req, res) => {
    const key = req.query.key;
    if (!key) {
        return res.status(400).json({ valid: false, message: 'License key is required.' });
    }

    try {
        const result = await pool.query("SELECT valid_until, status FROM licenses WHERE key = $1", [key]);
        const row = result.rows[0];

        if (row && row.status === 'Active' && new Date(row.valid_until) >= new Date()) {
            res.json({ valid: true, message: 'License is valid.', valid_until: row.valid_until });
        } else {
            let message = 'Invalid or expired license key.';
            if (row) {
                if (row.status !== 'Active') message = 'License is suspended or terminated.';
                else if (new Date(row.valid_until) < new Date()) message = `License expired on ${row.valid_until}.`;
            }
            res.status(401).json({ valid: false, message: message });
        }
    } catch (err) {
        console.error("Database error during license check:", err.message);
        return res.status(500).json({ valid: false, message: 'Internal server error.' });
    }
});

// 2. Save Invoice API
app.post('/api/save-invoice', async (req, res) => {
    const invoiceData = req.body;
    const { invoiceNumber, customerName, customerContact, shopName, grandTotal } = invoiceData;

    if (!invoiceNumber || typeof grandTotal !== 'number' || grandTotal < 0) {
        return res.status(400).json({ success: false, message: 'Missing essential invoice data (Number or Total).' });
    }

    // CLEANED SQL
    const sql = `
        INSERT INTO invoices (invoice_number, customer_name, customer_contact, shop_name, grand_total, invoice_data) 
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id;
    `; 
    
    try {
        const result = await pool.query(sql, [
            invoiceNumber,
            customerName || 'N/A',
            customerContact || 'N/A',
            shopName || 'N/A',
            grandTotal,
            JSON.stringify(invoiceData) 
        ]);
        
        res.json({ success: true, message: 'Invoice saved successfully.', invoiceId: result.rows[0].id });
    } catch (err) {
        // PostgreSQL duplicate key error code 23505
        if (err.code === '23505') { 
             return res.status(409).json({ success: false, message: 'Invoice with this number already exists.' });
        }
        console.error("Error saving invoice:", err.message);
        return res.status(500).json({ success: false, message: 'Database error while saving invoice.' });
    }
});

// 3. Admin Login API
app.post('/api/admin-login', (req, res) => {
    const { password } = req.body;

    if (password === ADMIN_PASSWORD) {
        res.json({ success: true, message: 'Login successful' });
    } else {
        res.status(401).json({ success: false, message: 'Incorrect admin password.' });
    }
});

// 4. Generate Key API
app.post('/api/generate-key', async (req, res) => {
    const { password, days } = req.body;

    // 1. Admin Password Check
    if (password !== ADMIN_PASSWORD) {
        return res.status(401).json({ success: false, message: 'Authorization failed. Incorrect admin password.' });
    }
    
    // 2. Days validation
    if (!days || typeof days !== 'number' || days <= 0) {
        return res.status(400).json({ success: false, message: 'Invalid or missing "days" duration.' });
    }

    try {
        const newKey = generateLicenseKey();
        
        // Calculate expiration date
        const validUntil = new Date();
        validUntil.setDate(validUntil.getDate() + days);
        const expiryDate = validUntil.toISOString().split('T')[0]; // YYYY-MM-DD format

        // 3. Save key to database
        const result = await pool.query(
            "INSERT INTO licenses (key, valid_until, status) VALUES ($1, $2, 'Active') RETURNING key, valid_until",
            [newKey, expiryDate]
        );
        
        res.json({ 
            success: true, 
            message: `${days}-day license key generated successfully.`,
            key: result.rows[0].key,
            valid_until: result.rows[0].valid_until,
            duration_days: days
        });

    } catch (err) {
        console.error("Error generating or saving key:", err.message);
        return res.status(500).json({ success: false, message: 'Database error during key generation.' });
    }
});


// 5. Basic Root URL response
app.get('/', (req, res) => {
    res.send('Dukan Pro Ultimate Backend is running! API Routes: /api/validate-key, /api/save-invoice, /api/admin-login, /api/generate-key');
});

// --- Server Start ---
// पहले डेटाबेस सेटअप चलाएँ, फिर सर्वर शुरू करें
setupDatabase().then(() => {
    app.listen(PORT, () => {
        console.log(`Server is running on port ${PORT}`);
        console.log('PostgreSQL connection established.');
    });
}).catch(err => {
    console.error('Fatal error during application startup:', err.message);
    process.exit(1);
});

// Handle graceful shutdown
process.on('SIGINT', async () => {
    console.log('Server shutting down...');
    await pool.end(); // सभी क्लाइंट कनेक्शन बंद करें
    console.log('PostgreSQL pool disconnected.');
    process.exit(0);
});

