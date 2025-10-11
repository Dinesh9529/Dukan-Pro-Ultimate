/*
 * Node.js Server for Dukan Pro Business Suite (PostgreSQL Backend)
 * FINAL & CORRECTED VERSION
 * Handles: License Validation, Stock, Sales, Dashboard Stats
 * Database: PostgreSQL
 */
import express from 'express';
import pg from 'pg';
import { createDecipheriv, createHash } from 'crypto';
import cors from 'cors';

// --- Server Setup ---
const app = express();

// CORS Configuration
const allowedOrigins = ['https://dinesh9529.github.io', 'http://127.0.0.1:5500', 'http://localhost:5500'];
const corsOptions = {
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
};

app.options('*', cors(corsOptions));
app.use(cors(corsOptions));
app.use(express.json({ limit: '10mb' }));

// --- Environment Variables & Constants ---
const APP_SECRET_KEY = process.env.APP_SECRET_KEY || '6019c9ecf0fd55147c482910a17f1b21';
const PORT = process.env.PORT || 10000;
const STOCK_TABLE_NAME = 'Stock';
const SALES_TABLE_NAME = 'Sales';

// --- PostgreSQL Connection Pool ---
const { Pool } = pg;
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
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
        if (iv.length !== IV_LENGTH) return null;
        const decipher = createDecipheriv(ALGORITHM, derivedKey, iv);
        let decrypted = decipher.update(encrypted);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return JSON.parse(decrypted.toString('utf8'));
    } catch (e) {
        console.error("Decryption Error:", e.message);
        return null;
    }
}

// ===================================
//      CORE API ENDPOINTS (FIXED)
// ===================================

// 1. License Key Validation
app.post('/api/validate-key', (req, res) => {
    const { key } = req.body;
    if (!key) return res.status(400).json({ valid: false, message: 'Key is required.' });
    const decryptedData = decrypt(key);
    if (!decryptedData || !decryptedData.expiry) {
        return res.status(401).json({ valid: false, message: 'Invalid or corrupted license key.' });
    }
    if (new Date() > new Date(decryptedData.expiry)) {
        return res.status(401).json({ valid: false, message: 'License key has expired.' });
    }
    res.json({
        valid: true,
        message: 'License key validated successfully.',
        name: decryptedData.name || 'Dukan Pro User',
        expiry: decryptedData.expiry
    });
});

// 2. Stock Management (CRUD) - **FIXED ENDPOINT**
app.get('/api/stock', async (req, res) => {
    try {
        const result = await pool.query(`SELECT * FROM "${STOCK_TABLE_NAME}" ORDER BY "Item Name" ASC`);
        res.json(result.rows);
    } catch (error) {
        res.status(500).json({ message: `Failed to fetch stock: ${error.message}` });
    }
});

app.post('/api/stock', async (req, res) => {
    const { name, sku, purchase_price, sale_price, quantity } = req.body;
    try {
        const query = `
            INSERT INTO "${STOCK_TABLE_NAME}" ("Item Name", "SKU", "Purchase Price", "Sale Price", "Quantity")
            VALUES ($1, $2, $3, $4, $5) RETURNING *;
        `;
        const result = await pool.query(query, [name, sku, purchase_price, sale_price, quantity]);
        res.status(201).json(result.rows[0]);
    } catch (error) {
        res.status(500).json({ message: `Failed to add stock item: ${error.message}` });
    }
});

// 3. Sales Recording - **FIXED ENDPOINT**
app.post('/api/sales', async (req, res) => {
    // Note: customer_name, total_tax are not used in this simplified version but can be added
    const { invoice_number, total_amount, items } = req.body;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const salesQuery = `
            INSERT INTO "${SALES_TABLE_NAME}" ("Invoice Number", "Total Amount", "Items")
            VALUES ($1, $2, $3) RETURNING "ID";
        `;
        await client.query(salesQuery, [invoice_number, total_amount, JSON.stringify(items)]);

        for (const item of items) {
            const stockUpdateQuery = `
                UPDATE "${STOCK_TABLE_NAME}" SET "Quantity" = "Quantity" - $1 WHERE "ID" = $2;
            `;
            await client.query(stockUpdateQuery, [item.quantity, item.id]);
        }
        await client.query('COMMIT');
        res.status(201).json({ success: true, message: 'Sale recorded successfully!' });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error("Sale Recording Error:", error);
        res.status(500).json({ success: false, message: `Failed to record sale: ${error.message}` });
    } finally {
        client.release();
    }
});

// 4. Dashboard Stats - **FIXED ENDPOINT**
app.get('/api/dashboard-stats', async (req, res) => {
    try {
        const salesQuery = `SELECT SUM("Total Amount") as total_sales FROM "${SALES_TABLE_NAME}"`;
        const stockValueQuery = `SELECT SUM("Purchase Price" * "Quantity") as stock_value FROM "${STOCK_TABLE_NAME}"`;
        
        const [salesRes, stockValueRes] = await Promise.all([
            pool.query(salesQuery),
            pool.query(stockValueQuery)
        ]);
        
        res.json({
            totalSales: parseFloat(salesRes.rows[0].total_sales) || 0,
            stockValue: parseFloat(stockValueRes.rows[0].stock_value) || 0,
        });
    } catch (error) {
        res.status(500).json({ message: `Failed to fetch dashboard stats: ${error.message}` });
    }
});

// Server Start
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
