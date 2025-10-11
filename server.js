/*
 * Node.js Server for Dukan Pro Business Suite (PostgreSQL Backend)
 * Handles: License Validation, Stock, Sales, Purchases, CRM, Expenses
 * Database: PostgreSQL
 */
import express from 'express';
import pg from 'pg'; // PostgreSQL Client
import { createDecipheriv, createHash, createHmac } from 'crypto';
import cors from 'cors';

// --- Server Setup ---
const app = express();


// -----------------------------------------------------------------
// 🔥 CORS FIX: GitHub Pages URL को allow करने के लिए नया और बेहतर तरीका
// -----------------------------------------------------------------
const allowedOrigins = ['https://dinesh9529.github.io'];

const corsOptions = {
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) === -1) {
            const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], // OPTIONS को शामिल करना महत्वपूर्ण है
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
};

// **सबसे महत्वपूर्ण बदलाव**
// सर्वर को बताएं कि वह सभी रूट्स के लिए OPTIONS (preflight) अनुरोधों को हैंडल करे
app.options('*', cors(corsOptions)); 

// अब सभी सामान्य अनुरोधों के लिए CORS का उपयोग करें
app.use(cors(corsOptions));
app.use(express.json());
// -----------------------------------------------------------------


// --- Environment Variables & Constants ---
const APP_SECRET_KEY = process.env.APP_SECRET_KEY || '6019c9ecf0fd55147c482910a17f1b21'; 
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'defaultadminpass'; 
// Render.com पोर्ट को स्वचालित रूप से सेट करता है, इसलिए 10000 का उपयोग करें
const PORT = process.env.PORT || 10000;

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
const derivedKey = createHash('sha256').update(APP_SECRET_KEY).digest();
const ALGORITHM = 'aes-256-cbc';
const IV_LENGTH = 16; 

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

// --- Database Initialization Function ---
async function initializeDatabase() {
    console.log("Initializing database tables...");
    const client = await pool.connect();
    try {
        await client.query(`CREATE TABLE IF NOT EXISTS "${STOCK_TABLE_NAME}" (
            ID SERIAL PRIMARY KEY, "SKU" VARCHAR(50) UNIQUE NOT NULL, "Item Name" VARCHAR(255) NOT NULL,
            "Purchase Price" NUMERIC(10, 2) NOT NULL, "Sale Price" NUMERIC(10, 2) NOT NULL,
            "Quantity" INTEGER NOT NULL DEFAULT 0, "Last Updated" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );`);
        
        await client.query(`CREATE TABLE IF NOT EXISTS "${CUSTOMERS_TABLE_NAME}" (
            ID VARCHAR(50) PRIMARY KEY, "Name" VARCHAR(255) NOT NULL, "Phone" VARCHAR(20), "Address" TEXT,
            "Date Added" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );`);

        await client.query(`CREATE TABLE IF NOT EXISTS "${PURCHASES_TABLE_NAME}" (
            ID SERIAL PRIMARY KEY, "Date" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, "SKU" VARCHAR(50) NOT NULL,
            "Item Name" VARCHAR(255), "Quantity" INTEGER NOT NULL, "Purchase Price" NUMERIC(10, 2),
            "Total Value" NUMERIC(10, 2), "Supplier" VARCHAR(255)
        );`);

        await client.query(`CREATE TABLE IF NOT EXISTS "${SALES_TABLE_NAME}" (
            ID SERIAL PRIMARY KEY, "Date" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            "Invoice Number" VARCHAR(100) UNIQUE NOT NULL, "Customer Name" VARCHAR(255),
            "Total Amount" NUMERIC(10, 2), "Total Tax" NUMERIC(10, 2), "Items" JSONB 
        );`);

        await client.query(`CREATE TABLE IF NOT EXISTS "${EXPENSES_TABLE_NAME}" (
            ID SERIAL PRIMARY KEY, "Date" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            "Category" VARCHAR(100) NOT NULL, "Amount" NUMERIC(10, 2) NOT NULL, "Description" TEXT
        );`);
        
        console.log("All tables initialized successfully (if they didn't exist).");
    } catch (err) {
        console.error("FATAL: Database Initialization Error:", err);
        throw err; 
    } finally {
        client.release();
    }
}


// ===================================
//         CORE API ENDPOINTS
// ===================================

// 1. License Key Validation
app.post('/api/validate-key', (req, res) => {
    const { key } = req.body;
    if (!key) return res.status(400).json({ valid: false, message: 'Key is required.' });

    const decryptedData = decrypt(key);
    
    if (!decryptedData || !decryptedData.expiry) {
        return res.status(401).json({ valid: false, message: 'Invalid or corrupted license key.' });
    }

    const expiryDate = new Date(decryptedData.expiry);
    const currentDate = new Date();
    
    if (currentDate > expiryDate) {
        return res.status(401).json({ valid: false, message: 'License key has expired.' });
    }

    res.json({ 
        valid: true, 
        message: 'License key validated successfully.',
        name: decryptedData.name || 'Dukan Pro User',
        phone: decryptedData.phone || 'N/A',
        address: decryptedData.address || 'N/A',
        expiry: decryptedData.expiry,
        plan: decryptedData.plan || 'N/A',
    });
});

// 2. Fetch Data (Generic Endpoint)
app.get('/api/data/:sheetName', async (req, res) => {
    const { sheetName } = req.params;
    const validTables = [STOCK_TABLE_NAME, CUSTOMERS_TABLE_NAME, PURCHASES_TABLE_NAME, SALES_TABLE_NAME, EXPENSES_TABLE_NAME];
    if (!validTables.includes(sheetName)) {
        return res.status(400).json({ message: "Invalid data source specified." });
    }
    try {
        const result = await pool.query(`SELECT * FROM "${sheetName}"`);
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ message: `Failed to fetch data from ${sheetName}: ${error.message}` });
    }
});


// ... (बाकी सभी API endpoints जैसे /api/stock, /api/sales आदि वैसे ही रहेंगे) ...
// The rest of your API endpoints (/api/stock, /api/customers, etc.) remain unchanged.
// Just ensure they are placed here.


// ===================================
//         SERVER START
// ===================================

async function startServer() {
    try {
        await initializeDatabase(); 
        app.listen(PORT, () => {
            console.log(`Server is running on port ${PORT}`);
        });
    } catch (err) {
        console.error("FATAL ERROR: Server could not start due to DB issue. Exiting.");
        process.exit(1); 
    }
}

startServer();
