/*
 * Node.js Server for Dukan Pro Business Suite (PostgreSQL Backend)
 * FINAL & COMPLETE VERSION - Includes all features (Sales, Stock, Purchases, Expenses, CRM)
 * Database: PostgreSQL
 * FIX: Added robust database connection handling (client.connect/release) to prevent 500 errors.
 */
import express from 'express';
import pg from 'pg'; // PostgreSQL Client
import { createDecipheriv, createHash } from 'crypto';
import cors from 'cors';

// --- Server Setup ---
const app = express();
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json());

// --- Environment Variables & Constants ---
// APP_SECRET_KEY आपके key generator में इस्तेमाल होनी चाहिए
const APP_SECRET_KEY = process.env.APP_SECRET_KEY || '6019c9ecf0fd55147c482910a17f1b21'; 
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'defaultadminpass';
// Render 10000 पोर्ट का उपयोग करता है
const PORT = process.env.PORT || 10000; 

// Table Names
const CUSTOMERS_TABLE_NAME = 'Customers';
const STOCK_TABLE_NAME = 'Stock';
const PURCHASES_TABLE_NAME = 'Purchases';
const SALES_TABLE_NAME = 'Sales';
const EXPENSES_TABLE_NAME = 'Expenses';
const LICENSES_TABLE_NAME = 'Licenses';

// --- Database Configuration (PostgreSQL) ---
// Render में DATABASE_URL environment variable सेट करें
const pool = new pg.Pool({
    connectionString: process.env.DATABASE_URL || 'postgresql://user:password@localhost:5432/dukanprodb',
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// --- Utility Functions ---

function decryptLicense(encryptedText) {
    try {
        const parts = encryptedText.split(':');
        if (parts.length !== 2) return null;

        const iv = Buffer.from(parts[0], 'hex');
        const encrypted = Buffer.from(parts[1], 'hex');
        
        const key = createHash('sha256').update(APP_SECRET_KEY).digest().slice(0, 32);

        const decipher = createDecipheriv('aes-256-cbc', key, iv);
        let decrypted = decipher.update(encrypted);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    } catch (e) {
        console.error("Decryption failed:", e.message);
        return null;
    }
}

function hashPassword(password) {
    return createHash('sha256').update(password).digest('hex');
}

// --- Database Initialization ---
async function initializeDatabase() {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Tables creation queries (unchanged, using double quotes for case-sensitivity)
        await client.query(`
            CREATE TABLE IF NOT EXISTS "${LICENSES_TABLE_NAME}" (
                "License Key" VARCHAR(255) PRIMARY KEY, "Issued Date" DATE NOT NULL,
                "Expiry Date" DATE NOT NULL, "Status" VARCHAR(50) NOT NULL, "Issued To" VARCHAR(255)
            );
        `);
        await client.query(`
            CREATE TABLE IF NOT EXISTS "${STOCK_TABLE_NAME}" (
                "SKU" VARCHAR(50) PRIMARY KEY, "Item Name" VARCHAR(255) NOT NULL, "Quantity" INTEGER NOT NULL,
                "Purchase Price" DECIMAL(10, 2) NOT NULL, "Selling Price" DECIMAL(10, 2) NOT NULL,
                "GST Rate" DECIMAL(5, 2) NOT NULL, "Date Added" DATE DEFAULT CURRENT_DATE
            );
        `);
        await client.query(`
            CREATE TABLE IF NOT EXISTS "${CUSTOMERS_TABLE_NAME}" (
                "ID" SERIAL PRIMARY KEY, "Customer Name" VARCHAR(255) NOT NULL, "Phone" VARCHAR(20),
                "Address" TEXT, "Date Added" DATE DEFAULT CURRENT_DATE
            );
        `);
        await client.query(`
            CREATE TABLE IF NOT EXISTS "${SALES_TABLE_NAME}" (
                "Invoice Number" VARCHAR(100) PRIMARY KEY, "Customer Name" VARCHAR(255) NOT NULL,
                "Items Sold" JSONB NOT NULL, "Total Amount" DECIMAL(10, 2) NOT NULL,
                "GST Amount" DECIMAL(10, 2) NOT NULL, "Date" DATE DEFAULT CURRENT_DATE
            );
        `);
        await client.query(`
            CREATE TABLE IF NOT EXISTS "${PURCHASES_TABLE_NAME}" (
                "ID" SERIAL PRIMARY KEY, "Bill Number" VARCHAR(100) UNIQUE, "Supplier Name" VARCHAR(255),
                "Items Purchased" JSONB NOT NULL, "Total Cost" DECIMAL(10, 2) NOT NULL,
                "Date" DATE DEFAULT CURRENT_DATE
            );
        `);
        await client.query(`
            CREATE TABLE IF NOT EXISTS "${EXPENSES_TABLE_NAME}" (
                "ID" SERIAL PRIMARY KEY, "Category" VARCHAR(100) NOT NULL, "Description" TEXT,
                "Amount" DECIMAL(10, 2) NOT NULL, "Date" DATE DEFAULT CURRENT_DATE
            );
        `);

        await client.query('COMMIT');
        console.log("Database tables initialized successfully.");

        // Insert a default license for testing if none exists (FIX: Using client.query)
        const licenseCheck = await client.query(`SELECT COUNT(*) FROM "${LICENSES_TABLE_NAME}"`);
        if (licenseCheck.rows[0].count == 0) {
            console.log("Inserting default license for testing purposes.");
            const defaultLicenseKey = 'TEST-LIC-12345';
            const issuedDate = new Date().toISOString().split('T')[0];
            const expiryDate = new Date(new Date().setFullYear(new Date().getFullYear() + 1)).toISOString().split('T')[0];
            await client.query(
                `INSERT INTO "${LICENSES_TABLE_NAME}" ("License Key", "Issued Date", "Expiry Date", "Status", "Issued To") VALUES ($1, $2, $3, $4, $5) ON CONFLICT ("License Key") DO NOTHING;`,
                [defaultLicenseKey, issuedDate, expiryDate, 'Active', 'Test User']
            );
            console.log("Default license inserted.");
        }
    } catch (err) {
        await client.query('ROLLBACK');
        console.error("Database initialization failed:", err);
        throw err;
    } finally {
        client.release();
    }
}

// ===================================
//             API ENDPOINTS
// ===================================

// --- 1. System & Authentication ---

// License Check Endpoint (FIX: Added try...catch...finally)
app.post('/api/check-license', async (req, res) => {
    const { licenseKey } = req.body;
    if (!licenseKey) {
        return res.status(400).json({ isValid: false, message: 'License key is required.' });
    }
    
    const decryptedData = decryptLicense(licenseKey);

    if (!decryptedData) {
        return res.status(401).json({ isValid: false, message: 'Invalid license key format or secret mismatch.' });
    }

    const parts = decryptedData.split('|');
    if (parts.length !== 2) {
        return res.status(401).json({ isValid: false, message: 'Invalid decrypted data format.' });
    }
    
    const keyToLookup = parts[0]; 
    const client = await pool.connect(); // FIX: Connect client
    try {
        const result = await client.query(
            `SELECT "Expiry Date", "Status" FROM "${LICENSES_TABLE_NAME}" WHERE "License Key" = $1`,
            [keyToLookup]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ isValid: false, message: 'License not found in database.' });
        }

        const dbExpiryDate = new Date(result.rows[0]["Expiry Date"]);
        const status = result.rows[0]["Status"];
        const currentDate = new Date();

        if (status !== 'Active' || dbExpiryDate < currentDate) {
            return res.status(401).json({ isValid: false, message: 'License is inactive or expired.' });
        }
        
        return res.json({ isValid: true, message: 'License is valid!', expiryDate: dbExpiryDate.toISOString().split('T')[0] });

    } catch (error) {
        console.error("CRITICAL ERROR IN /api/check-license:", error.message, error.stack); // FIX: Detailed logging
        return res.status(500).json({ isValid: false, message: `Server error during license check: ${error.message}` });
    } finally {
        client.release(); // FIX: Release client
    }
});

// License Registration Endpoint (FIX: Added try...catch...finally)
app.post('/api/register-license', async (req, res) => {
    const { encryptedKey, issuedTo } = req.body;
    
    if (!encryptedKey || !issuedTo) {
        return res.status(400).json({ success: false, message: 'Encrypted Key and Issued To details are required.' });
    }

    const decryptedData = decryptLicense(encryptedKey);

    if (!decryptedData) {
        return res.status(401).json({ success: false, message: 'Invalid encrypted key or secret mismatch.' });
    }

    const parts = decryptedData.split('|');
    if (parts.length !== 2) {
        return res.status(401).json({ success: false, message: 'Invalid decrypted data format.' });
    }
    
    const licenseKey = parts[0]; 
    const expiryDateISO = parts[1];
    const client = await pool.connect(); // FIX: Connect client
    
    try {
        const dbExpiryDate = new Date(expiryDateISO).toISOString().split('T')[0];
        const dbIssuedDate = new Date().toISOString().split('T')[0];

        const query = `
            INSERT INTO "${LICENSES_TABLE_NAME}" ("License Key", "Issued Date", "Expiry Date", "Status", "Issued To")
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT ("License Key") DO UPDATE 
            SET "Expiry Date" = EXCLUDED."Expiry Date", "Issued To" = EXCLUDED."Issued To", "Status" = 'Active';
        `;
        
        await client.query(query, [licenseKey, dbIssuedDate, dbExpiryDate, 'Active', issuedTo]);

        res.status(201).json({ 
            success: true, 
            message: 'License registered/updated successfully!', 
            licenseKey, 
            expiryDate: dbExpiryDate 
        });

    } catch (error) {
        console.error("CRITICAL ERROR IN /api/register-license:", error.message, error.stack); // FIX: Detailed logging
        res.status(500).json({ success: false, message: `Failed to register license: ${error.message}` });
    } finally {
        client.release(); // FIX: Release client
    }
});

// Admin Login Endpoint (No DB interaction needed, so no pool fix)
app.post('/api/admin-login', (req, res) => {
    const { password } = req.body;
    const hashedPassword = hashPassword(password);
    const adminHashedPass = hashPassword(ADMIN_PASSWORD);

    if (hashedPassword === adminHashedPass) {
        const token = createHash('sha256').update(ADMIN_PASSWORD + Date.now()).digest('hex');
        res.json({ success: true, token });
    } else {
        res.status(401).json({ success: false, message: 'Invalid admin password' });
    }
});


// --- 2. Sales Management ---

// Record Sale (Already uses client.connect/release) - Added detailed logging
app.post('/api/record-sale', async (req, res) => {
    const { invoiceNumber, customerName, items, totalAmount, gstAmount } = req.body;
    if (!invoiceNumber || !customerName || !items || !totalAmount || !gstAmount || !items.length) {
        return res.status(400).json({ success: false, message: 'Missing required sale details.' });
    }

    const itemsJson = JSON.stringify(items);
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const saleQuery = `INSERT INTO "${SALES_TABLE_NAME}" ("Invoice Number", "Customer Name", "Items Sold", "Total Amount", "GST Amount") VALUES ($1, $2, $3, $4, $5);`;
        await client.query(saleQuery, [invoiceNumber, customerName, itemsJson, totalAmount, gstAmount]);

        for (const item of items) {
            const stockUpdateQuery = `UPDATE "${STOCK_TABLE_NAME}" SET "Quantity" = "Quantity" - $1 WHERE "SKU" = $2 AND "Quantity" >= $1;`;
            const result = await client.query(stockUpdateQuery, [item.quantity, item.sku]);
            if (result.rowCount === 0) {
                throw new Error(`Insufficient stock or invalid SKU for item: ${item.sku}`);
            }
        }
        
        const existingCustomer = await client.query(`SELECT "ID" FROM "${CUSTOMERS_TABLE_NAME}" WHERE "Customer Name" = $1;`, [customerName]);
        if (existingCustomer.rows.length === 0) {
            await client.query(`INSERT INTO "${CUSTOMERS_TABLE_NAME}" ("Customer Name") VALUES ($1);`, [customerName]);
        }

        await client.query('COMMIT');
        res.status(201).json({ success: true, message: 'Sale recorded successfully!', invoiceNumber });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error("CRITICAL ERROR IN /api/record-sale:", error.message, error.stack); // FIX: Detailed logging
        res.status(500).json({ success: false, message: `Failed to record sale: ${error.message}` });
    } finally {
        client.release();
    }
});

// Get Sales (FIX: Added try...catch...finally)
app.get('/api/sales', async (req, res) => {
    const client = await pool.connect();
    try {
        const result = await client.query(`SELECT * FROM "${SALES_TABLE_NAME}" ORDER BY "Date" DESC, "Invoice Number" DESC`);
        res.json(result.rows);
    } catch (error) {
        console.error("CRITICAL ERROR IN /api/sales:", error.message, error.stack); // FIX: Detailed logging
        res.status(500).json({ success: false, message: `Failed to fetch sales data: ${error.message}` });
    } finally {
        client.release();
    }
});


// --- 3. Purchases Management ---

// Record Purchase (Already uses client.connect/release) - Added detailed logging
app.post('/api/record-purchase', async (req, res) => {
    const { billNumber, supplierName, items, totalCost } = req.body;
    if (!billNumber || !items || !totalCost || !items.length) {
        return res.status(400).json({ success: false, message: 'Missing required purchase details.' });
    }

    const itemsJson = JSON.stringify(items);
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const purchaseQuery = `INSERT INTO "${PURCHASES_TABLE_NAME}" ("Bill Number", "Supplier Name", "Items Purchased", "Total Cost") VALUES ($1, $2, $3, $4) RETURNING *;`;
        const purchaseResult = await client.query(purchaseQuery, [billNumber, supplierName, itemsJson, totalCost]);

        for (const item of items) {
            const stockUpdateQuery = `
                UPDATE "${STOCK_TABLE_NAME}" SET "Quantity" = "Quantity" + $1, "Purchase Price" = $2
                WHERE "SKU" = $3;
            `;
            await client.query(stockUpdateQuery, [item.quantity, item.purchasePrice, item.sku]);
        }

        await client.query('COMMIT');
        res.status(201).json({ success: true, message: 'Purchase recorded!', purchase: purchaseResult.rows[0] });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error("CRITICAL ERROR IN /api/record-purchase:", error.message, error.stack); // FIX: Detailed logging
        res.status(500).json({ success: false, message: `Failed to record purchase: ${error.message}` });
    } finally {
        client.release();
    }
});

// Get Purchases (FIX: Added try...catch...finally)
app.get('/api/purchases', async (req, res) => {
    const client = await pool.connect();
    try {
        const result = await client.query(`SELECT * FROM "${PURCHASES_TABLE_NAME}" ORDER BY "Date" DESC`);
        res.json(result.rows);
    } catch (error) {
        console.error("CRITICAL ERROR IN /api/purchases:", error.message, error.stack); // FIX: Detailed logging
        res.status(500).json({ success: false, message: `Failed to fetch purchases data: ${error.message}` });
    } finally {
        client.release();
    }
});

// Delete Purchase (Already uses client.connect/release) - Added detailed logging
app.delete('/api/purchases/:id', async (req, res) => {
    const { id } = req.params;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const purchase = await client.query(`SELECT "Items Purchased" FROM "${PURCHASES_TABLE_NAME}" WHERE "ID" = $1`, [id]);
        if (purchase.rows.length === 0) throw new Error("Purchase record not found.");
        
        const items = purchase.rows[0]['Items Purchased'];
        for (const item of items) {
            await client.query(`UPDATE "${STOCK_TABLE_NAME}" SET "Quantity" = "Quantity" - $1 WHERE "SKU" = $2`, [item.quantity, item.sku]);
        }
        await client.query(`DELETE FROM "${PURCHASES_TABLE_NAME}" WHERE "ID" = $1`, [id]);
        
        await client.query('COMMIT');
        res.json({ success: true, message: 'Purchase record deleted and stock reversed.' });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error("CRITICAL ERROR IN /api/purchases/:id:", error.message, error.stack); // FIX: Detailed logging
        res.status(500).json({ success: false, message: error.message });
    } finally {
        client.release();
    }
});


// --- 4. Expenses Management ---

// Record Expense (FIX: Added try...catch...finally)
app.post('/api/record-expense', async (req, res) => {
    const { category, description, amount, date } = req.body;
    if (!category || amount === undefined || !date) {
        return res.status(400).json({ success: false, message: 'Category, Amount, and Date are required.' });
    }
    const client = await pool.connect();
    try {
        const query = `INSERT INTO "${EXPENSES_TABLE_NAME}" ("Category", "Description", "Amount", "Date") VALUES ($1, $2, $3, $4) RETURNING *;`;
        const result = await client.query(query, [category, description, amount, date]);
        res.status(201).json({ success: true, expense: result.rows[0] });
    } catch (error) {
        console.error("CRITICAL ERROR IN /api/record-expense:", error.message, error.stack); // FIX: Detailed logging
        res.status(500).json({ success: false, message: `Failed to record expense: ${error.message}` });
    } finally {
        client.release();
    }
});

// Get Expenses (FIX: Added try...catch...finally)
app.get('/api/expenses', async (req, res) => {
    const client = await pool.connect();
    try {
        const result = await client.query(`SELECT * FROM "${EXPENSES_TABLE_NAME}" ORDER BY "Date" DESC`);
        res.json(result.rows);
    } catch (error) {
        console.error("CRITICAL ERROR IN /api/expenses:", error.message, error.stack); // FIX: Detailed logging
        res.status(500).json({ success: false, message: `Failed to fetch expenses data: ${error.message}` });
    } finally {
        client.release();
    }
});

// Delete Expense (FIX: Added try...catch...finally)
app.delete('/api/expenses/:id', async (req, res) => {
    const client = await pool.connect();
    try {
        await client.query(`DELETE FROM "${EXPENSES_TABLE_NAME}" WHERE "ID" = $1`, [req.params.id]);
        res.json({ success: true, message: 'Expense deleted successfully.' });
    } catch (error) {
        console.error("CRITICAL ERROR IN /api/expenses/:id:", error.message, error.stack); // FIX: Detailed logging
        res.status(500).json({ success: false, message: error.message });
    } finally {
        client.release();
    }
});


// --- 5. Stock & Inventory ---

// Get Stock (FIX: Added try...catch...finally)
app.get('/api/stock', async (req, res) => {
    const client = await pool.connect();
    try {
        const result = await client.query(`SELECT *, "Selling Price" as "Sale Price", "GST Rate" as "GST" FROM "${STOCK_TABLE_NAME}" ORDER BY "Item Name" ASC`);
        res.json(result.rows);
    } catch (error) {
        console.error("CRITICAL ERROR IN /api/stock:", error.message, error.stack); // FIX: Detailed logging
        res.status(500).json({ success: false, message: `Failed to fetch stock data: ${error.message}` });
    } finally {
        client.release();
    }
});

// Add/Update Stock (FIX: Added try...catch...finally)
app.post('/api/stock', async (req, res) => {
    const { SKU, "Item Name": itemName, Quantity, "Purchase Price": purchasePrice, "Sale Price": sellingPrice, GST: gstRate } = req.body;
    if (!SKU || !itemName || Quantity === undefined || purchasePrice === undefined || sellingPrice === undefined || gstRate === undefined) {
        return res.status(400).json({ success: false, message: 'Missing required stock item details.' });
    }
    const client = await pool.connect();
    try {
        const query = `
            INSERT INTO "${STOCK_TABLE_NAME}" ("SKU", "Item Name", "Quantity", "Purchase Price", "Selling Price", "GST Rate")
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT ("SKU") DO UPDATE SET
                "Item Name" = EXCLUDED."Item Name", "Quantity" = "${STOCK_TABLE_NAME}"."Quantity" + EXCLUDED."Quantity",
                "Purchase Price" = EXCLUDED."Purchase Price", "Selling Price" = EXCLUDED."Selling Price",
                "GST Rate" = EXCLUDED."GST Rate", "Date Added" = CURRENT_DATE
            RETURNING *, "Selling Price" as "Sale Price", "GST Rate" as "GST";
        `;
        const result = await client.query(query, [SKU, itemName, Quantity, purchasePrice, sellingPrice, gstRate]);
        res.status(201).json({ success: true, message: 'Stock item added/updated successfully!', item: result.rows[0] });
    } catch (error) {
        console.error("CRITICAL ERROR IN /api/stock POST:", error.message, error.stack); // FIX: Detailed logging
        res.status(500).json({ success: false, message: `Failed to add/update stock item: ${error.message}` });
    } finally {
        client.release();
    }
});

// Delete Stock (FIX: Added try...catch...finally)
app.delete('/api/stock/:sku', async (req, res) => {
    const client = await pool.connect();
    try {
        const result = await client.query(`DELETE FROM "${STOCK_TABLE_NAME}" WHERE "SKU" = $1`, [req.params.sku]);
        if (result.rowCount === 0) return res.status(404).json({ success: false, message: 'SKU not found.' });
        res.json({ success: true, message: 'Stock item deleted successfully.' });
    } catch (error) {
        console.error("CRITICAL ERROR IN /api/stock DELETE:", error.message, error.stack); // FIX: Detailed logging
        res.status(500).json({ success: false, message: `Deletion failed. This item might be linked to sales records. Error: ${error.message}` });
    } finally {
        client.release();
    }
});


// --- 6. CRM (Customers) ---

// Get Customers (FIX: Added try...catch...finally)
app.get('/api/customers', async (req, res) => {
    const client = await pool.connect();
    try {
        const result = await client.query(`SELECT "ID", "Customer Name" as "Name", "Phone", '' as "Email", "Address", "Date Added" FROM "${CUSTOMERS_TABLE_NAME}" ORDER BY "ID" DESC`);
        res.json(result.rows);
    } catch (error) {
        console.error("CRITICAL ERROR IN /api/customers:", error.message, error.stack); // FIX: Detailed logging
        res.status(500).json({ success: false, message: `Failed to fetch customer data: ${error.message}` });
    } finally {
        client.release();
    }
});

// Add Customer (FIX: Added try...catch...finally)
app.post('/api/customers', async (req, res) => {
    const { Name, Phone, Address } = req.body;
    if (!Name) return res.status(400).json({ success: false, message: 'Customer name is required.' });
    const client = await pool.connect();
    try {
        const query = `INSERT INTO "${CUSTOMERS_TABLE_NAME}" ("Customer Name", "Phone", "Address") VALUES ($1, $2, $3) RETURNING "ID", "Customer Name" as "Name", "Phone", "Address", "Date Added";`;
        const result = await client.query(query, [Name, Phone, Address]);
        res.status(201).json({ success: true, message: 'Customer added!', customer: result.rows[0] });
    } catch (error) {
        console.error("CRITICAL ERROR IN /api/customers POST:", error.message, error.stack); // FIX: Detailed logging
        res.status(500).json({ success: false, message: `Failed to add customer: ${error.message}` });
    } finally {
        client.release();
    }
});

// Delete Customer (FIX: Added try...catch...finally)
app.delete('/api/customers/:id', async (req, res) => {
    const client = await pool.connect();
    try {
        await client.query(`DELETE FROM "${CUSTOMERS_TABLE_NAME}" WHERE "ID" = $1`, [req.params.id]);
        res.json({ success: true, message: 'Customer deleted successfully.' });
    } catch (error) {
        console.error("CRITICAL ERROR IN /api/customers DELETE:", error.message, error.stack); // FIX: Detailed logging
        res.status(500).json({ success: false, message: error.message });
    } finally {
        client.release();
    }
});


// --- 7. Dashboard & Reporting ---

// Comprehensive Dashboard Stats (FIX: Added client.connect/release and using client.query)
app.get('/api/dashboard-stats', async (req, res) => {
    const client = await pool.connect();
    try {
        const salesQuery = `SELECT SUM("Total Amount") as total_sales, SUM("GST Amount") as total_tax FROM "${SALES_TABLE_NAME}"`;
        const purchasesCostQuery = `SELECT SUM("Total Cost") as total_cogs FROM "${PURCHASES_TABLE_NAME}"`;
        const expensesQuery = `SELECT SUM("Amount") as total_expenses FROM "${EXPENSES_TABLE_NAME}"`;
