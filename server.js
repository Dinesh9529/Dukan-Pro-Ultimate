/*
 * Node.js Server for Dukan Pro Business Suite
 * Handles: License Validation, Stock, Sales, Purchases, CRM, Expenses
 * Database: PostgreSQL (using DATABASE_URL environment variable)
 * Feature: Auto-Initializes tables on server startup if they don't exist.
 */
import express from 'express';
// OLD: import { google } from 'googleapis'; // Google Sheets हटाएँ
import pg from 'pg'; // NEW: PostgreSQL Client
import { createCipheriv, createDecipheriv, randomBytes, createHash, createHmac } from 'crypto';
import cors from 'cors';

// --- Server Setup ---
const app = express();
app.use(cors());
app.use(express.json()); // Body parser middleware


// --- Environment Variables & Constants ---
// Google Sheets IDs अब ज़रूरी नहीं हैं।
// const CUSTOMER_SPREADSHEET_ID = '...'; 
// const DATA_SPREADSHEET_ID = '...'; 

const APP_SECRET_KEY = process.env.APP_SECRET_KEY || '6019c9ecf0fd55147c482910a17f1b21'; // App Secret Key
const PORT = process.env.PORT || 3000;

// Table Names (Sheets Names का उपयोग करते हुए)
const CUSTOMERS_TABLE_NAME = 'Customers';
const STOCK_TABLE_NAME = 'Stock';
const PURCHASES_TABLE_NAME = 'Purchases';
const SALES_TABLE_NAME = 'Sales';
const EXPENSES_TABLE_NAME = 'Expenses';


// --- PostgreSQL Connection Pool ---
const { Pool } = pg;
// Render स्वचालित रूप से DATABASE_URL Environment Variable सेट करता है
const pool = new Pool({
    connectionString: process.env.DATABASE_URL, 
    ssl: {
        rejectUnauthorized: false // Render के साथ SSL ज़रूरी है
    }
});


// --- License Key & Crypto Logic (SAME AS BEFORE) ---
const derivedKey = createHash('sha256').update(APP_SECRET_KEY).digest();
const ALGORITHM = 'aes-256-cbc';
const IV_LENGTH = 16; 

// Decrypt function (SAME AS BEFORE)
function decrypt(encryptedText) {
    if (!encryptedText) return null;
    try {
        const parts = encryptedText.split(':');
        if (parts.length !== 2) return null;

        const iv = Buffer.from(parts[0], 'hex');
        const encrypted = Buffer.from(parts[1], 'hex');
        if (iv.length !== IV_LENGTH) return null;

        const decipher = createDecipheriv(ALGORITHM, derivedKey, iv);
        let decrypted = decipher.update(encrypted);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return JSON.parse(decrypted.toString());
    } catch (e) {
        console.error("Decryption failed:", e.message);
        return null;
    }
}

// Encrypt function (SAME AS BEFORE, although not used in validation)
function encrypt(text) {
    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv(ALGORITHM, derivedKey, iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

// --- NEW: Database Initialization Function (Auto-Create Tables) ---
async function initializeDatabase() {
    console.log("Initializing database tables...");
    const client = await pool.connect();
    try {
        // SQL कमांड्स को एक-एक करके चलाएँ
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
            Name VARCHAR(255) NOT NULL,
            Phone VARCHAR(20),
            Address TEXT,
            "Date Added" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );`);

        await client.query(`CREATE TABLE IF NOT EXISTS "${PURCHASES_TABLE_NAME}" (
            ID SERIAL PRIMARY KEY,
            "Date" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            "SKU" VARCHAR(50) NOT NULL,
            "Item Name" VARCHAR(255),
            Quantity INTEGER NOT NULL,
            "Purchase Price" NUMERIC(10, 2),
            "Total Value" NUMERIC(10, 2),
            Supplier VARCHAR(255)
        );`);

        await client.query(`CREATE TABLE IF NOT EXISTS "${SALES_TABLE_NAME}" (
            ID SERIAL PRIMARY KEY,
            "Date" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            "Invoice Number" VARCHAR(100) UNIQUE NOT NULL,
            "Customer Name" VARCHAR(255),
            "Total Amount" NUMERIC(10, 2),
            "Total Tax" NUMERIC(10, 2),
            Items JSONB 
        );`);

        await client.query(`CREATE TABLE IF NOT EXISTS "${EXPENSES_TABLE_NAME}" (
            ID SERIAL PRIMARY KEY,
            "Date" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            Category VARCHAR(100) NOT NULL,
            Amount NUMERIC(10, 2) NOT NULL,
            Description TEXT
        );`);
        
        console.log("All tables initialized successfully (if they didn't exist).");
    } catch (err) {
        console.error("FATAL: Database Initialization Error:", err);
        throw err; 
    } finally {
        client.release();
    }
}


// --- API Endpoints ---

// 1. License Key Validation (Logic Maintained)
app.post('/api/validate-key', (req, res) => {
    const { key } = req.body;

    if (!key) {
        return res.status(400).json({ valid: false, message: 'Key is required.' });
    }

    const decryptedData = decrypt(key);

    if (!decryptedData || !decryptedData.expiry) {
        return res.status(401).json({ valid: false, message: 'Invalid or corrupted license key.' });
    }

    const expiryDate = new Date(decryptedData.expiry);
    const currentDate = new Date();
    
    // Check if key has expired
    if (currentDate > expiryDate) {
        return res.status(401).json({ valid: false, message: 'License key has expired.' });
    }

    // Generate a simple token (as per previous logic)
    const tokenPayload = `${decryptedData.expiry}:${currentDate.toISOString().split('T')[0]}`;
    const token = createHmac('sha256', APP_SECRET_KEY).update(tokenPayload).digest('hex');

    res.json({ 
        valid: true, 
        message: 'License key validated successfully.',
        user: decryptedData.user || 'Dukan Pro User',
        expiry: decryptedData.expiry,
        token: token // Sending back a simple auth token
    });
});


// 2. Fetch Data (Replaces sheets.spreadsheets.values.get)
app.get('/api/data/:sheetName', async (req, res) => {
    const { sheetName } = req.params;
    
    // Validate table name to prevent SQL Injection
    const validTables = [STOCK_TABLE_NAME, CUSTOMERS_TABLE_NAME, PURCHASES_TABLE_NAME, SALES_TABLE_NAME, EXPENSES_TABLE_NAME];
    if (!validTables.includes(sheetName)) {
        return res.status(400).json({ message: "Invalid data source specified." });
    }

    try {
        // PostgreSQL query
        const queryText = `SELECT * FROM "${sheetName}"`;
        const result = await pool.query(queryText);
        
        // Rows/Data वापस भेजें
        res.json(result.rows);
    } catch (error) {
        console.error(`PostgreSQL Error fetching ${sheetName}:`, error);
        res.status(500).json({ message: `Failed to fetch data from ${sheetName}: ${error.message}` });
    }
});


// 3. Add/Update Stock Item (Replaces sheets.spreadsheets.values.append)
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


// 4. Add Customer (Replaces sheets.spreadsheets.values.append)
app.post('/api/customers', async (req, res) => {
    const { id, name, phone, address } = req.body;
    if (!id || !name) {
        return res.status(400).json({ message: "ID and Name are required for customer." });
    }

    const queryText = `
        INSERT INTO "${CUSTOMERS_TABLE_NAME}" (ID, Name, Phone, Address, "Date Added")
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (ID) 
        DO UPDATE SET 
            Name = EXCLUDED.Name, 
            Phone = EXCLUDED.Phone, 
            Address = EXCLUDED.Address
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


// 5. Add Purchase (Replaces sheets.spreadsheets.values.append)
app.post('/api/purchases', async (req, res) => {
    const { sku, itemName, quantity, purchasePrice, totalValue, supplier } = req.body;
    if (!sku || !quantity || !purchasePrice) {
        return res.status(400).json({ message: "SKU, Quantity, and Purchase Price are required." });
    }

    const queryText = `
        INSERT INTO "${PURCHASES_TABLE_NAME}" ("Date", "SKU", "Item Name", Quantity, "Purchase Price", "Total Value", Supplier)
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


// 6. Add Sale (Replaces sheets.spreadsheets.values.append)
app.post('/api/sales', async (req, res) => {
    const { invoiceNumber, customerName, totalAmount, totalTax, items } = req.body;
    if (!invoiceNumber || !totalAmount || !items) {
        return res.status(400).json({ message: "Invoice Number, Total Amount, and Items are required." });
    }

    const queryText = `
        INSERT INTO "${SALES_TABLE_NAME}" ("Date", "Invoice Number", "Customer Name", "Total Amount", "Total Tax", Items)
        VALUES ($1, $2, $3, $4, $5, $6)
    `;
    // items array को PostgreSQL के JSONB कॉलम में डालने के लिए JSON.stringify का उपयोग करें
    const values = [new Date().toISOString(), invoiceNumber, customerName, totalAmount, totalTax, JSON.stringify(items)];

    try {
        await pool.query(queryText, values);
        res.status(201).json({ message: "Sale recorded successfully." });
    } catch (error) {
        console.error("PostgreSQL Error:", error);
        res.status(500).json({ message: `Failed to record sale: ${error.message}` });
    }
});


// 7. Add Expense (Replaces sheets.spreadsheets.values.append)
app.post('/api/expenses', async (req, res) => {
    const { category, amount, description } = req.body;
    if (!category || !amount) {
        return res.status(400).json({ message: "Category and Amount are required." });
    }
    
    const queryText = `
        INSERT INTO "${EXPENSES_TABLE_NAME}" ("Date", Category, Amount, Description)
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


// 8. Search API (General Search)
app.get('/api/search', async (req, res) => {
    const { query } = req.query;
    if (!query) {
        return res.status(400).json({ message: "Search query is required." });
    }

    try {
        // हम यहाँ एक उदाहरण के लिए Stock Table में खोज रहे हैं। 
        // आप इसे अन्य टेबल्स में भी विस्तारित कर सकते हैं।
        const searchQuery = `%${query.toLowerCase()}%`;
        const queryText = `
            SELECT * FROM "${STOCK_TABLE_NAME}"
            WHERE LOWER("SKU") LIKE $1 OR LOWER("Item Name") LIKE $1
            LIMIT 10
        `;
        
        const result = await pool.query(queryText, [searchQuery]);
        
        res.json({
            results: result.rows,
            source: STOCK_TABLE_NAME
        });
    } catch (error) {
        console.error("PostgreSQL Search Error:", error);
        res.status(500).json({ message: `Failed to perform search: ${error.message}` });
    }
});


// --- Server Start ---
// Initialization को पहले चलाएँ
async function startServer() {
    try {
        // 1. Tables बनाएँ (या चेक करें कि वे मौजूद हैं)
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

// सबसे नीचे, startServer को कॉल करें
startServer();
