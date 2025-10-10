/*
 * Node.js Server for Dukan Pro Business Suite
 * Handles: License Validation, Stock, Sales, Purchases, CRM, Expenses
 * NOW USING: PostgreSQL
 */
import express from 'express';
// import { google } from 'googleapis'; // Google Sheets API हटा दिया गया है
import { createCipheriv, createDecipheriv, randomBytes, createHash } from 'crypto';
import cors from 'cors';
import { Pool } from 'pg'; // NEW: PostgreSQL क्लाइंट इम्पोर्ट किया गया

// --- Environment Variables & Constants ---
// NOTE: Google Sheet IDs हटा दिए गए हैं, DATABASE_URL को ENV में सेट किया गया है।
// const CUSTOMER_SPREADSHEET_ID = '109TtsLFXzJGQbn1r2zr59kl86-peOEF_VFYK1HVu6MU'; // हटाया गया
// const DATA_SPREADSHEET_ID = '1RXW43LrZbpmyQMCbvdWmk0c9RWrAJVGaXiIA3vW-PrA'; // हटाया गया
const APP_SECRET_KEY = '6019c9ecf0fd55147c482910a17f1b21'; // License Key Security (रखा गया)

// Sheet names अब Table names हैं
const CUSTOMERS_TABLE_NAME = 'Customers';
const STOCK_TABLE_NAME = 'Stock';
const PURCHASES_TABLE_NAME = 'Purchases';
const SALES_TABLE_NAME = 'Sales';
const EXPENSES_TABLE_NAME = 'Expenses';
const PORT = process.env.PORT || 3000;

// Derive a 32-byte key for AES-256 (License Key Logic - रखा गया)
const derivedKey = createHash('sha256').update(APP_SECRET_KEY).digest();
const ALGORITHM = 'aes-256-cbc';

// --- NEW: PostgreSQL Setup ---
const pool = new Pool({
    // Render में सेट किया गया DATABASE_URL ENV variable का उपयोग करें
    connectionString: process.env.DATABASE_URL, 
    // Render SSL के लिए ज़रूरी
    ssl: { rejectUnauthorized: false } 
});

// टेस्ट कनेक्शन
pool.connect((err, client, release) => {
  if (err) {
    console.error('CRITICAL: Error connecting to PostgreSQL:', err.stack);
    process.exit(1); 
  } else {
    client.query('SELECT NOW()', (err, result) => {
      release();
      if (err) {
        console.error('Error executing test query:', err.stack);
      } else {
        console.log("PostgreSQL Connected successfully! Time:", result.rows[0].now);
      }
    });
  }
});


const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public')); 

// --- Helper Functions ---

// License Decryption Function (UNCHANGED)
function decryptKey(base64Key) {
    try {
        const key = derivedKey;
        const combined = Buffer.from(base64Key, 'base64');
        const iv = combined.slice(0, 16);
        const ciphertext = combined.slice(16);

        const decipher = createDecipheriv(ALGORITHM, key, iv);
        let decrypted = decipher.update(ciphertext);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        
        return decrypted.toString();
    } catch (e) {
        console.error("Decryption failed:", e.message);
        return null;
    }
}

// NEW Helper to read all data from a table (replaces readSheetData)
async function readTableData(tableName) {
    // Note: Column names with spaces like "Item Name" must be double-quoted in SQL
    // We assume the tables were created with the schema provided earlier.
    const result = await pool.query(`SELECT * FROM "${tableName}"`); 
    return result.rows; 
}

// --- API Endpoints ---

// 1. License Validation (UNCHANGED LOGIC)
app.post('/api/validate-key', (req, res) => {
    const { key } = req.body;
    if (!key) return res.status(400).json({ valid: false, message: 'Key is required.' });

    const decryptedDataJson = decryptKey(key);
    if (!decryptedDataJson) return res.status(401).json({ valid: false, message: 'Invalid license key format.' });
    
    try {
        const data = JSON.parse(decryptedDataJson);
        const expiryDate = new Date(data.expiry);
        const currentDate = new Date();
        
        if (expiryDate > currentDate) {
            return res.json({ 
                valid: true, 
                user: data.name, 
                expiry: data.expiry,
                message: `License activated for ${data.plan}. Expires on ${expiryDate.toLocaleDateString()}.`
            });
        } else {
            return res.status(401).json({ valid: false, message: 'License key has expired. Please renew.' });
        }

    } catch (e) {
        console.error("Error processing license data:", e);
        return res.status(401).json({ valid: false, message: 'Invalid license key data.' });
    }
});


// 2. Main Data API (fetches everything from PostgreSQL - CHANGED)
app.get('/api/initial-data', async (req, res) => {
    try {
        // All data fetching now uses readTableData for PostgreSQL
        const [stock, sales, purchases, customers, expenses] = await Promise.all([
            readTableData(STOCK_TABLE_NAME),
            readTableData(SALES_TABLE_NAME),
            readTableData(PURCHASES_TABLE_NAME),
            readTableData(CUSTOMERS_TABLE_NAME),
            readTableData(EXPENSES_TABLE_NAME),
        ]);
        
        res.status(200).json({ stock, sales, purchases, customers, expenses });

    } catch (error) {
        console.error("Critical Error loading initial data from PostgreSQL:", error.message, error.stack);
        res.status(500).json({ 
            message: `डेटा लोड करने में विफल: PostgreSQL कनेक्शन या टेबल स्कीमा जाँचें। Error: ${error.message}` 
        });
    }
});

// 3. Add Stock (CHANGED: Uses ON CONFLICT for upsert logic)
app.post('/api/add-stock', async (req, res) => {
    const { sku, itemname, purchaseprice, saleprice, quantity } = req.body;
    try {
        const sql = `
            INSERT INTO "${STOCK_TABLE_NAME}" (
                "SKU", "Item Name", "Purchase Price", "Sale Price", "Quantity", "Last Updated"
            ) VALUES ($1, $2, $3, $4, $5, NOW())
            ON CONFLICT (SKU) DO UPDATE
            SET "Item Name" = EXCLUDED."Item Name", 
                "Purchase Price" = EXCLUDED."Purchase Price", 
                "Sale Price" = EXCLUDED."Sale Price", 
                "Quantity" = "${STOCK_TABLE_NAME}".Quantity + EXCLUDED.Quantity, 
                "Last Updated" = NOW()
        `; 

        await pool.query(sql, [sku, itemname, purchaseprice, saleprice, quantity]);
        res.status(201).json({ message: "Stock added/updated successfully." });
    } catch (error) {
        res.status(500).json({ message: `Failed to add stock: ${error.message}` });
    }
});

// 4. Add Purchase (CHANGED)
app.post('/api/add-purchase', async (req, res) => {
    const { sku, itemname, quantity, purchaseprice, supplier } = req.body;
    try {
        const totalValue = quantity * purchaseprice;
        const sql = `
            INSERT INTO "${PURCHASES_TABLE_NAME}" (
                "Date", SKU, "Item Name", Quantity, "Purchase Price", "Total Value", Supplier
            ) VALUES (NOW(), $1, $2, $3, $4, $5, $6)
        `;
        await pool.query(sql, [sku, itemname, quantity, purchaseprice, totalValue, supplier]);
        res.status(201).json({ message: "Purchase added successfully." });
    } catch (error) {
        res.status(500).json({ message: `Failed to add purchase: ${error.message}` });
    }
});

// 5. Log Sales (CHANGED)
app.post('/api/log-sale', async (req, res) => {
    const { invoiceNumber, customerName, totalAmount, totalTax, items } = req.body;
    try {
        const sql = `
            INSERT INTO "${SALES_TABLE_NAME}" (
                "Date", "Invoice Number", "Customer Name", "Total Amount", "Total Tax", Items
            ) VALUES (NOW(), $1, $2, $3, $4, $5)
        `;
        // Items array को JSONB कॉलम में सेव करने के लिए JSON.stringify का उपयोग करें
        await pool.query(sql, [invoiceNumber, customerName, totalAmount, totalTax, JSON.stringify(items)]);
        res.status(201).json({ message: "Sale logged successfully." });
    } catch (error) {
        res.status(500).json({ message: `Failed to log sale: ${error.message}` });
    }
});

// 6. Add Customer (CHANGED)
app.post('/api/add-customer', async (req, res) => {
    const { name, phone, address } = req.body;
    try {
        // Customer ID generation logic is preserved
        const customerId = 'CUST-' + Math.floor(Math.random() * 1000000); 
        const sql = `
            INSERT INTO "${CUSTOMERS_TABLE_NAME}" (
                ID, Name, Phone, Address, "Date Added"
            ) VALUES ($1, $2, $3, $4, NOW())
        `;
        await pool.query(sql, [customerId, name, phone, address]);
        res.status(201).json({ message: "Customer added successfully." });
    } catch (error) {
        res.status(500).json({ message: `Failed to add customer: ${error.message}` });
    }
});

// 7. Add Expense (CHANGED)
app.post('/api/expenses', async (req, res) => {
    const { category, amount, description } = req.body;
    if (!category || !amount) {
        return res.status(400).json({ message: "Category and Amount are required." });
    }
    try {
        const sql = `
            INSERT INTO "${EXPENSES_TABLE_NAME}" (
                "Date", Category, Amount, Description
            ) VALUES (NOW(), $1, $2, $3)
        `;
        await pool.query(sql, [category, amount, description]);
        res.status(201).json({ message: "Expense added successfully." });
    } catch (error) {
        res.status(500).json({ message: `Failed to add expense: ${error.message}` });
    }
});


app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
