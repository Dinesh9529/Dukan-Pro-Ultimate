/*
 * Node.js Server for Dukan Pro Business Suite (PostgreSQL Backend)
 * FINAL FIX: Includes automated schema update for the 'Sales' table.
 */
import express from 'express';
import pg from 'pg'; // PostgreSQL Client
import { createDecipheriv, createHash, createHmac } from 'crypto';
import cors from 'cors';

// --- Server Setup ---
const app = express();

// ------------------------------------------
// 🔥 CORS FIX: GitHub Pages URL को allow करें
// ------------------------------------------
const FRONTEND_URL = 'https://dinesh9529.github.io'; 
app.use(cors({
    origin: FRONTEND_URL, 
    methods: ['GET', 'POST', 'PUT', 'DELETE'], 
    allowedHeaders: ['Content-Type'],
}));
app.use(express.json());
// ------------------------------------------


// --- Environment Variables & Constants ---
const APP_SECRET_KEY = process.env.APP_SECRET_KEY || '6019c9ecf0fd55147c482910a17f1b21'; 
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'defaultadminpass'; 
const PORT = process.env.PORT || 3000;

// Table Names
const CUSTOMERS_TABLE_NAME = 'Customers';
const STOCK_TABLE_NAME = 'Stock';
const PURCHASES_TABLE_NAME = 'Purchases';
const SALES_TABLE_NAME = 'Sales';
const EXPENSES_TABLE_NAME = 'Expenses';


// --- PostgreSQL Connection Pool ---
const { Pool } = pg;
const pool = new Pool({
    connectionString: process.env.DATABASE_URL, 
    ssl: {
        rejectUnauthorized: false
    }
});


// --- License Key & Crypto Logic ---
// Key Derivation: SHA256 hash of the secret key (SAME AS IN HTML GENERATOR)
const derivedKey = createHash('sha256').update(APP_SECRET_KEY).digest();
const ALGORITHM = 'aes-256-cbc';
const IV_LENGTH = 16; 


// 🔥 UPDATED Decrypt function:
function decrypt(encryptedBase64Key) {
    if (!encryptedBase64Key) return null;
    try {
        const combined = Buffer.from(encryptedBase64Key, 'base64');
        const iv = combined.slice(0, IV_LENGTH);
        const encrypted = combined.slice(IV_LENGTH);

        if (iv.length !== IV_LENGTH) {
            console.error("Decryption failed: IV length mismatch.");
            return null;
        }

        const decipher = createDecipheriv(ALGORITHM, derivedKey, iv);
        let decrypted = decipher.update(encrypted);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        
        return JSON.parse(decrypted.toString('utf8'));
    } catch (e) {
        console.error("Decryption failed:", e.message);
        return null;
    }
}


// --- Database Initialization Function (Auto-Create & Repair Tables) ---
async function initializeDatabase() {
    console.log("Initializing database tables...");
    const client = await pool.connect();
    try {
        // 1. Create all tables (IF NOT EXISTS)
        await client.query(`CREATE TABLE IF NOT EXISTS "${STOCK_TABLE_NAME}" (
            ID SERIAL PRIMARY KEY,
            "SKU" VARCHAR(50) UNIQUE NOT NULL, 
            "Item Name" VARCHAR(255) NOT NULL,
            "Purchase Price" NUMERIC(10, 2) NOT NULL,
            "Sale Price" NUMERIC(10, 2) NOT NULL,
            "Quantity" INTEGER NOT NULL DEFAULT 0,
            "Last Updated" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );`);
        
        await client.query(`CREATE TABLE IF NOT EXISTS "${CUSTOMERS_TABLE_NAME}" (
            ID VARCHAR(50) PRIMARY KEY,
            "Name" VARCHAR(255) NOT NULL,
            "Phone" VARCHAR(20),
            "Address" TEXT,
            "Date Added" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );`);

        await client.query(`CREATE TABLE IF NOT EXISTS "${PURCHASES_TABLE_NAME}" (
            ID SERIAL PRIMARY KEY,
            "Date" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            "SKU" VARCHAR(50) NOT NULL,
            "Item Name" VARCHAR(255),
            "Quantity" INTEGER NOT NULL,
            "Purchase Price" NUMERIC(10, 2),
            "Total Value" NUMERIC(10, 2),
            "Supplier" VARCHAR(255)
        );`);

        await client.query(`CREATE TABLE IF NOT EXISTS "${SALES_TABLE_NAME}" (
            ID SERIAL PRIMARY KEY,
            "Date" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            "Invoice Number" VARCHAR(100) UNIQUE NOT NULL,
            "Customer Name" VARCHAR(255),
            "Total Amount" NUMERIC(10, 2),
            "Total Tax" NUMERIC(10, 2),
            "Items" JSONB 
        );`);

        await client.query(`CREATE TABLE IF NOT EXISTS "${EXPENSES_TABLE_NAME}" (
            ID SERIAL PRIMARY KEY,
            "Date" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            "Category" VARCHAR(100) NOT NULL,
            "Amount" NUMERIC(10, 2) NOT NULL,
            "Description" TEXT
        );`);
        
        // --- 🔥 FIX: SCHEMA REPAIR FOR MISSING ITEMS COLUMN (The root cause of the 500 error) ---
        // Since CREATE TABLE IF NOT EXISTS does not add new columns, we try to ALTER the table.
        try {
            await client.query(`ALTER TABLE "${SALES_TABLE_NAME}" ADD COLUMN "Items" JSONB`);
            console.log(`[FIX] Successfully added missing "Items" column to "${SALES_TABLE_NAME}".`);
        } catch (err) {
            // Error code '42701' means the column already exists. We ignore this error.
            if (err.code === '42701') { 
                console.log(`[FIX] "Items" column already exists in "${SALES_TABLE_NAME}". Skipping ALTER.`);
            } else {
                 // Log any other unexpected error.
                console.error("Warning: Could not run ALTER TABLE for Sales.Items:", err.message);
            }
        }
        // --- END OF FIX ---
        
        console.log("All tables initialized and schema repaired successfully.");
    } catch (err) {
        console.error("FATAL: Database Initialization Error:", err);
        throw err; 
    } finally {
        client.release();
    }
}


// ===================================
//          CORE API ENDPOINTS
// ===================================

// 1. License Key Validation
app.post('/api/validate-key', (req, res) => {
    const { key } = req.body;
    if (!key) return res.status(400).json({ valid: false, message: 'Key is required.' });

    const decryptedData = decrypt(key);
    
    // Decryption or key format failure
    if (!decryptedData || !decryptedData.expiry) {
        return res.status(401).json({ valid: false, message: 'Invalid or corrupted license key.' });
    }

    const expiryDate = new Date(decryptedData.expiry);
    const currentDate = new Date();
    
    if (currentDate > expiryDate) {
        return res.status(401).json({ valid: false, message: 'License key has expired.' });
    }

    // Token for client-side persistence (using HMAC)
    const tokenPayload = `${decryptedData.expiry}:${currentDate.toISOString().split('T')[0]}`;
    const token = createHmac('sha256', APP_SECRET_KEY).update(tokenPayload).digest('hex');

    // 🔥 RESPONSE UPDATE: Include name, phone, address
    res.json({ 
        valid: true, 
        message: 'License key validated successfully.',
        name: decryptedData.name || 'Dukan Pro User',
        phone: decryptedData.phone || 'N/A',
        address: decryptedData.address || 'N/A',
        expiry: decryptedData.expiry,
        plan: decryptedData.plan || 'N/A',
        token: token 
    });
});


// 2. Fetch Data (PostgreSQL)
app.get('/api/data/:sheetName', async (req, res) => {
    const { sheetName } = req.params;
    const validTables = [STOCK_TABLE_NAME, CUSTOMERS_TABLE_NAME, PURCHASES_TABLE_NAME, SALES_TABLE_NAME, EXPENSES_TABLE_NAME];
    if (!validTables.includes(sheetName)) {
        return res.status(400).json({ message: "Invalid data source specified." });
    }

    try {
        const queryText = `SELECT * FROM "${sheetName}"`;
        const result = await pool.query(queryText);
        res.json(result.rows);
    } catch (error) {
        console.error(`PostgreSQL Error fetching ${sheetName}:`, error);
        res.status(500).json({ message: `Failed to fetch data from ${sheetName}: ${error.message}` });
    }
});


// 3. Add/Update Stock Item (PostgreSQL)
app.post('/api/stock', async (req, res) => {
    const { sku, itemName, purchasePrice, salePrice, quantity } = req.body;
    if (!sku || !itemName || !purchasePrice || !salePrice || !quantity) {
        return res.status(400).json({ message: "All stock fields are required." });
    }

    const queryText = `
        INSERT INTO "${STOCK_TABLE_NAME}" ("SKU", "Item Name", "Purchase Price", "Sale Price", "Quantity", "Last Updated")
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT ("SKU") 
        DO UPDATE SET 
            "Item Name" = EXCLUDED."Item Name", 
            "Purchase Price" = EXCLUDED."Purchase Price", 
            "Sale Price" = EXCLUDED."Sale Price",
            "Quantity" = "Stock"."Quantity" + EXCLUDED."Quantity",
            "Last Updated" = EXCLUDED."Last Updated"
    `; 
    const values = [sku, itemName, purchasePrice, salePrice, quantity, new Date().toISOString()];
    try {
        await pool.query(queryText, values);
        res.status(201).json({ message: "Stock item added/updated successfully in PostgreSQL." });
    } catch (error) {
        console.error("PostgreSQL Error:", error);
        res.status(500).json({ message: `Failed to add/update stock: ${error.message}` });
    }
});


// 4. Add Customer (PostgreSQL)
app.post('/api/customers', async (req, res) => {
    const { id, name, phone, address } = req.body;
    if (!id || !name) {
        return res.status(400).json({ message: "ID and Name are required for customer." });
    }

    const queryText = `
        INSERT INTO "${CUSTOMERS_TABLE_NAME}" (ID, "Name", "Phone", "Address", "Date Added")
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (ID) 
        DO UPDATE SET 
            "Name" = EXCLUDED."Name", 
            "Phone" = EXCLUDED."Phone", 
            "Address" = EXCLUDED."Address"
    `;
    const values = [id, name, phone, address, new Date().toISOString()];
    try {
        await pool.query(queryText, values);
        res.status(201).json({ message: "Customer added/updated successfully." });
    } catch (error) {
        console.error("PostgreSQL Error:", error);
        res.status(500).json({ message: `Failed to add/update customer: ${error.message}` });
    }
});


// 5. Add Purchase (PostgreSQL)
app.post('/api/purchases', async (req, res) => {
    const { sku, itemName, quantity, purchasePrice, totalValue, supplier } = req.body;
    if (!sku || !quantity || !purchasePrice) {
        return res.status(400).json({ message: "SKU, Quantity, and Purchase Price are required." });
    }

    const queryText = `
        INSERT INTO "${PURCHASES_TABLE_NAME}" ("Date", "SKU", "Item Name", "Quantity", "Purchase Price", "Total Value", "Supplier")
        VALUES ($1, $2, $3, $4, $5, $6, $7)
    `;
    const values = [new Date().toISOString(), sku, itemName, quantity, purchasePrice, totalValue, supplier];
    try {
        await pool.query(queryText, values);
        res.status(201).json({ message: "Purchase added successfully." });
    } catch (error) {
        console.error("PostgreSQL Error:", error);
        res.status(500).json({ message: `Failed to add purchase: ${error.message}` });
    }
});


// 6. Add Sale (PostgreSQL)
app.post('/api/sales', async (req, res) => {
    const { invoiceNumber, customerName, totalAmount, totalTax, items } = req.body;
    if (!invoiceNumber || !totalAmount || !items) {
        return res.status(400).json({ message: "Invoice Number, Total Amount, and Items are required." });
    }

    const queryText = `
        INSERT INTO "${SALES_TABLE_NAME}" ("Date", "Invoice Number", "Customer Name", "Total Amount", "Total Tax", "Items")
        VALUES ($1, $2, $3, $4, $5, $6)
    `;
    // Note: Items is passed as a JSON string to PostgreSQL's JSONB column
    const values = [new Date().toISOString(), invoiceNumber, customerName, totalAmount, totalTax, JSON.stringify(items)]; 
    try {
        await pool.query(queryText, values);
        res.status(201).json({ message: "Sale recorded successfully." });
    } catch (error) {
        console.error("PostgreSQL Error:", error);
        res.status(500).json({ message: `Failed to record sale: ${error.message}` });
    }
});


// 7. Add Expense (PostgreSQL)
app.post('/api/expenses', async (req, res) => {
    const { category, amount, description } = req.body;
    if (!category || !amount) {
        return res.status(400).json({ message: "Category and Amount are required." });
    }
    
    const queryText = `
        INSERT INTO "${EXPENSES_TABLE_NAME}" ("Date", "Category", "Amount", "Description")
        VALUES ($1, $2, $3, $4)
    `;
    const values = [new Date().toISOString(), category, amount, description];
    try {
        await pool.query(queryText, values);
        res.status(201).json({ message: "Expense added successfully." });
    } catch (error) {
        console.error("PostgreSQL Error:", error);
        res.status(500).json({ message: `Failed to add expense: ${error.message}` });
    }
});

// 8. Dashboard Stats - All Financial Data 
app.get('/api/dashboard-stats', async (req, res) => {
    try {
        // 1. Total Revenue, Tax, Sales Revenue
        const salesSummary = await pool.query(`
            SELECT 
                COALESCE(SUM("Total Amount" + "Total Tax"), 0) AS "totalRevenue",
                COALESCE(SUM("Total Amount"), 0) AS "totalSalesRevenue",
                COALESCE(SUM("Total Tax"), 0) AS "totalTaxCollected"
            FROM "${SALES_TABLE_NAME}"
        `);

        // 2. Stock Value and Total Products
        const stockSummary = await pool.query(`
            SELECT 
                COALESCE(SUM("Purchase Price" * "Quantity"), 0) AS "stockValue",
                COUNT(ID) AS "totalProducts"
            FROM "${STOCK_TABLE_NAME}"
        `);

        // 3. Total COGS (A bit complex, based on JSONB items)
        const COGSResult = await pool.query(`
            SELECT jsonb_array_elements("Items") AS item_data
            FROM "${SALES_TABLE_NAME}"
        `);
        
        let totalCOGS = 0;
        COGSResult.rows.forEach(row => {
            const item = row.item_data;
            // Ensure data types are handled as numbers
            totalCOGS += (parseFloat(item.purchasePrice) || 0) * (parseFloat(item.qty) || 0); 
        });
        
        const totalSalesRevenue = parseFloat(salesSummary.rows[0].totalSalesRevenue);

        const stats = {
            totalRevenue: parseFloat(salesSummary.rows[0].totalRevenue),
            totalSalesRevenue: totalSalesRevenue,
            totalTaxCollected: parseFloat(salesSummary.rows[0].totalTaxCollected),
            stockValue: parseFloat(stockSummary.rows[0].stockValue),
            totalProducts: parseInt(stockSummary.rows[0].totalProducts),
            totalCOGS: totalCOGS,
            grossProfit: totalSalesRevenue - totalCOGS // Revenue - COGS
        };
        
        res.json(stats);
    } catch (error) {
        // Error here should now only be if data is corrupted, not column missing
        console.error("Dashboard Stats Error:", error);
        res.status(500).json({ message: `Failed to fetch dashboard statistics: ${error.message}` });
    }
});

// 9. Search API (General Search)
app.get('/api/search', async (req, res) => {
    const { query } = req.query;
    if (!query) return res.status(400).json({ message: "Search query is required." });

    try {
        const searchQuery = `%${query.toLowerCase()}%`;
        const queryText = `
            SELECT "SKU", "Item Name" FROM "${STOCK_TABLE_NAME}"
            WHERE LOWER("SKU") LIKE $1 OR LOWER("Item Name") LIKE $1
            LIMIT 10
        `;
        const result = await pool.query(queryText, [searchQuery]);
        res.json({ results: result.rows, source: STOCK_TABLE_NAME });
    } catch (error) {
        console.error("PostgreSQL Search Error:", error);
        res.status(500).json({ message: `Failed to perform search: ${error.message}` });
    }
});


// ===================================
//         ADMIN API ENDPOINTS
// ===================================

// 10. Admin Login (Authentication)
app.post('/api/admin/auth', (req, res) => {
    const { password } = req.body;
    if (password === ADMIN_PASSWORD) {
        // Success: Generate a simple token 
        const adminToken = createHmac('sha256', APP_SECRET_KEY).update(new Date().toISOString().split('T')[0] + 'ADMIN').digest('hex');
        res.json({ success: true, token: adminToken });
    } else {
        res.status(401).json({ success: false, message: 'Invalid Admin Password' });
    }
});

// 11. Fetch All Admin Data (Customers, Sales Overview, Stock)
app.get('/api/admin/all-data', async (req, res) => {
    // Note: यहाँ सुरक्षा के लिए Admin Token Validation जोड़ा जाना चाहिए।
    try {
        // Fetch all customer details (Name, Phone, Address, Date Added)
        const customers = await pool.query(`SELECT "ID", "Name", "Phone", "Address", "Date Added" FROM "${CUSTOMERS_TABLE_NAME}" ORDER BY "Date Added" DESC`);
        
        // Fetch sales overview (Invoice, Customer, Amount)
        const sales = await pool.query(`SELECT "Invoice Number", "Customer Name", "Total Amount", "Date" FROM "${SALES_TABLE_NAME}" ORDER BY "Date" DESC LIMIT 100`);
        
        // Fetch stock overview (SKU, Item Name, Quantity)
        const stock = await pool.query(`SELECT "SKU", "Item Name", "Quantity" FROM "${STOCK_TABLE_NAME}" WHERE "Quantity" <= 10 ORDER BY "Quantity" ASC`);

        res.json({
            customers: customers.rows,
            sales: sales.rows,
            lowStock: stock.rows // Low stock items
        });
    } catch (error) {
        console.error("Admin Data Fetch Error:", error);
        res.status(500).json({ message: `Failed to fetch admin data: ${error.message}` });
    }
});


// ===================================
//          SERVER START
// ===================================

async function startServer() {
    try {
        // 1. Tables बनाएँ (और Schema Repair करें)
        await initializeDatabase(); 
        
        // 2. Server शुरू करें
        app.listen(PORT, () => {
            console.log(`Server is running on port ${PORT}`);
        });
    } catch (err) {
        // अगर DB Initialization फेल होता है, तो सर्वर को बंद कर दें
        console.error("FATAL ERROR: Server could not start due to DB issue. Exiting.");
        process.exit(1); 
    }
}

startServer();
