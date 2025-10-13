import express from 'express';
import cors from 'cors';
import pg from 'pg'; 
import crypto from 'crypto'; 

const { Pool } = pg; 

const app = express();
const PORT = process.env.PORT || 3000;

// 🚨 ENVIRONMENT VARIABLES: Render पर इन्हें सेट करना ज़रूरी है।
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Dkc@#9529561113@abc'; 
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
    console.error('❌ ERROR: DATABASE_URL environment variable is not set!');
    process.exit(1);
}

// --- Utility Function ---
function generateLicenseKey() {
    const part1 = crypto.randomBytes(16).toString('hex');
    const part2 = crypto.randomBytes(32).toString('hex');
    return `${part1}:${part2}`;
}

// --- Database Setup (PostgreSQL) ---
const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false } 
});

pool.on('error', (err, client) => {
    console.error('❌ Unexpected error on idle client', err);
    process.exit(-1);
});

// ... (setupDatabase फ़ंक्शन: इसमें कोई बदलाव नहीं है, यह स्टॉक और लाइसेंस टेबल बनाता है) ...
async function setupDatabase() {
    try {
        const client = await pool.connect();

        // 1. Core Licenses Table
        await client.query(`
            CREATE TABLE IF NOT EXISTS licenses (
                key TEXT PRIMARY KEY, 
                valid_until DATE, 
                status TEXT
            );
        `);
        console.log("✅ Licenses table created/ready (PostgreSQL).");

        // Testing: Insert dummy valid key
        const tomorrow = new Date();
        tomorrow.setDate(tomorrow.getDate() + 1); 
        await client.query(`
            INSERT INTO licenses (key, valid_until, status) VALUES ($1, $2, $3)
            ON CONFLICT (key) DO NOTHING;
        `, ['398844dc1396accf5e8379d8014eebaf:632a0f5b9015ecf744f8e265580e14d44acde25d51376b8b608d503b9c43b801dab098d802949854b8479c5e9d9c1f02', tomorrow.toISOString().split('T')[0], 'Active']);

        // 2. Invoice Generator Pro Table
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
        
        // 3. Stock Management Table
        await client.query(`
            CREATE TABLE IF NOT EXISTS stock (
                sku TEXT PRIMARY KEY, 
                item_name TEXT NOT NULL,
                quantity INTEGER NOT NULL DEFAULT 0,
                unit TEXT,
                purchase_price REAL NOT NULL DEFAULT 0.0,
                sale_price REAL NOT NULL DEFAULT 0.0,
                gst REAL DEFAULT 0.0,
                last_updated TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log("✅ Stock table created/ready (PostgreSQL).");

        client.release();
        
    } catch (err) {
        console.error('❌ Database setup error:', err);
        process.exit(1);
    }
}


// --- Middleware Setup ---
app.use(cors()); 
app.use(express.json({ limit: '50mb' }));

// --- API Routes ---

// 1. 🟢 UPDATED: License Validation API (Route name fixed to match front-end)
app.get('/api/verify-license', async (req, res) => {
    const key = req.query.key;
    
    // एडमिन एक्सेस टोकन को बिना डेटाबेस चेक के सीधे पास करें
    if (key === 'ADMIN_ACCESS_TOKEN') {
        return res.json({ valid: true, message: 'Admin access active.', valid_until: '2099-12-31', durationInDays: 9999 });
    }

    if (!key) {
        return res.status(400).json({ valid: false, message: 'License key is required.' });
    }

    try {
        const result = await pool.query("SELECT valid_until, status FROM licenses WHERE key = $1", [key]);
        const row = result.rows[0];
        const now = new Date();

        if (row && row.status === 'Active' && new Date(row.valid_until) >= now) {
            
            // दिनों की अवधि की गणना करें (फ्रंट-एंड को इसकी आवश्यकता है)
            const validUntilDate = new Date(row.valid_until);
            const durationMs = validUntilDate.getTime() - now.getTime();
            const durationInDays = Math.ceil(durationMs / (1000 * 60 * 60 * 24));
            
            res.json({ valid: true, message: 'License is valid.', valid_until: row.valid_until, durationInDays: durationInDays });
        } else {
            // ... (बाकी त्रुटि लॉजिक) ...
            let message = 'Invalid or expired license key.';
            // ...
            res.status(401).json({ valid: false, message: message });
        }
    } catch (err) {
        console.error("Database error during license check:", err.message);
        return res.status(500).json({ valid: false, message: 'Internal server error.' });
    }
});

// 2. Save Invoice API (कोई बदलाव नहीं)
app.post('/api/save-invoice', async (req, res) => {
    const invoiceData = req.body;
    const { invoiceNumber, customerName, customerContact, shopName, grandTotal } = invoiceData;

    // ... (आपका मौजूदा कोड) ...
     if (!invoiceNumber || typeof grandTotal !== 'number' || grandTotal < 0) {
        return res.status(400).json({ success: false, message: 'Missing essential invoice data (Number or Total).' });
    }

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
        if (err.code === '23505') { 
             return res.status(409).json({ success: false, message: 'Invoice with this number already exists.' });
        }
        console.error("Error saving invoice:", err.message);
        return res.status(500).json({ success: false, message: 'Database error while saving invoice.' });
    }
});

// 3. Add Stock Item API (कोई बदलाव नहीं)
app.post('/api/stock', async (req, res) => {
    // ... (आपका मौजूदा कोड) ...
    const { SKU, 'Item Name': itemName, Quantity, Unit, 'Purchase Price': purchasePrice, 'Sale Price': salePrice, GST } = req.body;

    // Basic validation
    if (!SKU || !itemName || typeof Quantity !== 'number' || Quantity < 0 || typeof purchasePrice !== 'number' || typeof salePrice !== 'number') {
        return res.status(400).json({ success: false, message: 'Missing or invalid required stock data.' });
    }

    const sql = `
        INSERT INTO stock (sku, item_name, quantity, unit, purchase_price, sale_price, gst, last_updated)
        VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
        ON CONFLICT (sku) 
        DO UPDATE SET
            quantity = stock.quantity + EXCLUDED.quantity, 
            unit = EXCLUDED.unit,
            item_name = EXCLUDED.item_name,
            purchase_price = EXCLUDED.purchase_price, 
            sale_price = EXCLUDED.sale_price,
            gst = EXCLUDED.gst,
            last_updated = NOW()
        RETURNING *;
    `;

    try {
        const result = await pool.query(sql, [SKU, itemName, Quantity, Unit || 'Pcs', purchasePrice, salePrice, GST || 0]);
        
        const item = {
            SKU: result.rows[0].sku,
            'Item Name': result.rows[0].item_name,
            Quantity: result.rows[0].quantity,
            Unit: result.rows[0].unit,
            'Purchase Price': result.rows[0].purchase_price,
            'Sale Price': result.rows[0].sale_price,
            GST: result.rows[0].gst
        };
        res.json({ success: true, message: 'Stock updated/added successfully.', item });
    } catch (err) {
        console.error("Error adding/updating stock:", err.message);
        return res.status(500).json({ success: false, message: 'Database error while updating stock.' });
    }
});

// 4. Get All Stock Items API (कोई बदलाव नहीं)
app.get('/api/stocks', async (req, res) => {
    // ... (आपका मौजूदा कोड) ...
    try {
        const sql = `
            SELECT sku, item_name, quantity, unit, purchase_price, sale_price, gst, last_updated 
            FROM stock 
            ORDER BY last_updated DESC;
        `;
        const result = await pool.query(sql);

        const stocks = result.rows.map(row => ({
            SKU: row.sku,
            'Item Name': row.item_name,
            Quantity: row.quantity,
            Unit: row.unit,
            'Purchase Price': row.purchase_price,
            'Sale Price': row.sale_price,
            GST: row.gst,
            'Last Updated': row.last_updated.toISOString()
        }));
        
        res.json({ success: true, stocks });

    } catch (err) {
        console.error("Error fetching stocks:", err.message);
        return res.status(500).json({ success: false, message: 'Database error while fetching stock list.' });
    }
});

// 5. Admin Login API (कोई बदलाव नहीं)
app.post('/api/admin-login', (req, res) => {
    // ... (आपका मौजूदा कोड) ...
    const { password } = req.body;

    if (password === ADMIN_PASSWORD) {
        res.json({ success: true, message: 'Login successful' });
    } else {
        res.status(401).json({ success: false, message: 'Incorrect admin password.' });
    }
});

// 6. Generate Key API (कोई बदलाव नहीं)
app.post('/api/generate-key', async (req, res) => {
    // ... (आपका मौजूदा कोड) ...
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


// 7. 🟢 NEW: Dashboard Data API (जो 404 एरर दे रहा था)
app.get('/api/get-dashboard-data', async (req, res) => {
    try {
        // A. Inventory Value Calculation
        // इन्वेंट्री मूल्य = स्टॉक में Quantity * Purchase Price
        const inventoryResult = await pool.query(`
            SELECT 
                COALESCE(SUM(quantity * purchase_price), 0) AS inventory_value
            FROM stock;
        `);
        const inventoryValue = inventoryResult.rows[0].inventory_value;

        // B. Total Sales Calculation (मान लीजिए कि इनवॉइस में grand_total = बिक्री है)
        const salesResult = await pool.query(`
            SELECT 
                COALESCE(SUM(grand_total), 0) AS total_sales
            FROM invoices;
        `);
        const totalSales = salesResult.rows[0].total_sales;
        
        // C. Net Profit Calculation (इसे आपके विशिष्ट P&L लॉजिक के आधार पर विस्तृत करना होगा)
        // फिलहाल यह केवल एक डमी मान है या साधारण गणना। 
        // Note: सही लाभ गणना के लिए COGS (Cost of Goods Sold) लॉजिक चाहिए, जो बिक्री के दौरान स्टॉक से काटा जाता है।
        // अभी के लिए, हम एक साधारण अनुमान लगाते हैं।
        
        // DUMMY PROFIT (Example: 20% of Sales)
        // const totalProfit = totalSales * 0.20; 

        // ROUGH PROFIT: (Sales Total) - (Total Purchase Value of ALL Stock) - This is inaccurate but better than nothing
        // const totalPurchasedValueResult = await pool.query(`
        //     SELECT COALESCE(SUM(quantity * purchase_price), 0) AS total_purchased_value
        //     FROM stock;
        // `);
        // const totalPurchasedValue = totalPurchasedValueResult.rows[0].total_purchased_value;
        // const totalProfit = totalSales - totalPurchasedValue;
        
        // 🔴 Temporary simple value:
        const totalProfit = totalSales * 0.25; 

        // 4. Send the calculated data to the front-end
        res.json({
            success: true,
            data: {
                totalSales: parseFloat(totalSales.toFixed(2)),
                totalProfit: parseFloat(totalProfit.toFixed(2)),
                inventoryValue: parseFloat(inventoryValue.toFixed(2)),
                // अन्य डैशबोर्ड मेट्रिक्स यहाँ जोड़े जा सकते हैं
            }
        });

    } catch (err) {
        console.error("Error fetching dashboard data:", err.message);
        // सुनिश्चित करें कि यह 404 नहीं बल्कि 500 एरर हो
        return res.status(500).json({ success: false, message: 'Failed to fetch dashboard data due to a database error.' });
    }
});


// 8. Basic Root URL response
app.get('/', (req, res) => {
    res.send('Dukan Pro Ultimate Backend is running! API Routes: /api/verify-license, /api/save-invoice, /api/stock, /api/admin-login, /api/generate-key, /api/get-dashboard-data');
});

// --- Server Start ---
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
