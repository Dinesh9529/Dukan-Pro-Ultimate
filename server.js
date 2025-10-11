/*
 * Node.js Server for Dukan Pro Business Suite (PostgreSQL Backend)
 * FINAL & COMPLETE VERSION - Saare features (Sales, Stock, Purchases, Expenses, CRM) shamil hain.
 * Database: PostgreSQL
 */
import express from 'express';
import pg from 'pg'; // PostgreSQL Client
import { createDecipheriv, createHash, createHmac } from 'crypto';
import cors from 'cors';

// --- Server Setup ---
const app = express();

// ------------------------------------------
// 🔥 CORS FIX: 'Failed to fetch' error ko theek karne ke liye CORS ko relax kiya gaya hai.
// Ab yeh server sabhi origins se requests accept karega (Development environment ke liye).
// ------------------------------------------
app.use(cors({
    origin: '*', // Sabhi origins (websites) ki anumati
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
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
const LICENSES_TABLE_NAME = 'Licenses'; 

// --- Database Configuration (PostgreSQL) ---
const pool = new pg.Pool({
    connectionString: process.env.DATABASE_URL || 'postgresql://user:password@localhost:5432/dukanprodb',
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// --- Utility Functions ---

/**
 * License Key ko decrypt karta hai (AES-256-CBC).
 * @param {string} encryptedText - Encrypted license key string.
 * @returns {string | null} Decrypted plain text.
 */
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

/**
 * Password ka SHA256 hash generate karta hai.
 * @param {string} password - The password to hash.
 * @returns {string} SHA256 hash.
 */
function hashPassword(password) {
    return createHash('sha256').update(password).digest('hex');
}


// --- Database Initialization ---

/**
 * Database mein zaroori tables banata hai.
 */
async function initializeDatabase() {
    try {
        const client = await pool.connect();
        await client.query('BEGIN');

        // 1. Licenses Table
        await client.query(`
            CREATE TABLE IF NOT EXISTS "${LICENSES_TABLE_NAME}" (
                "License Key" VARCHAR(255) PRIMARY KEY,
                "Issued Date" DATE NOT NULL,
                "Expiry Date" DATE NOT NULL,
                "Status" VARCHAR(50) NOT NULL,
                "Issued To" VARCHAR(255)
            );
        `);

        // 2. Stock Table (Inventory)
        await client.query(`
            CREATE TABLE IF NOT EXISTS "${STOCK_TABLE_NAME}" (
                "SKU" VARCHAR(50) PRIMARY KEY,
                "Item Name" VARCHAR(255) NOT NULL,
                "Quantity" INTEGER NOT NULL,
                "Purchase Price" DECIMAL(10, 2) NOT NULL,
                "Selling Price" DECIMAL(10, 2) NOT NULL,
                "GST Rate" DECIMAL(5, 2) NOT NULL,
                "Date Added" DATE DEFAULT CURRENT_DATE
            );
        `);

        // 3. Customers Table (CRM)
        await client.query(`
            CREATE TABLE IF NOT EXISTS "${CUSTOMERS_TABLE_NAME}" (
                "ID" SERIAL PRIMARY KEY,
                "Customer Name" VARCHAR(255) NOT NULL,
                "Phone" VARCHAR(20),
                "Address" TEXT,
                "Date Added" DATE DEFAULT CURRENT_DATE
            );
        `);

        // 4. Sales Table (Invoices)
        await client.query(`
            CREATE TABLE IF NOT EXISTS "${SALES_TABLE_NAME}" (
                "Invoice Number" VARCHAR(100) PRIMARY KEY,
                "Customer Name" VARCHAR(255) NOT NULL,
                "Items Sold" JSONB NOT NULL,
                "Total Amount" DECIMAL(10, 2) NOT NULL,
                "GST Amount" DECIMAL(10, 2) NOT NULL,
                "Date" DATE DEFAULT CURRENT_DATE
            );
        `);

        // 5. Purchases Table (Supplier Bills/Inventory Inflow)
        await client.query(`
            CREATE TABLE IF NOT EXISTS "${PURCHASES_TABLE_NAME}" (
                "Bill Number" VARCHAR(100) PRIMARY KEY,
                "Supplier Name" VARCHAR(255),
                "Items Purchased" JSONB NOT NULL,
                "Total Cost" DECIMAL(10, 2) NOT NULL,
                "Date" DATE DEFAULT CURRENT_DATE
            );
        `);

        // 6. Expenses Table
        await client.query(`
            CREATE TABLE IF NOT EXISTS "${EXPENSES_TABLE_NAME}" (
                "ID" SERIAL PRIMARY KEY,
                "Category" VARCHAR(100) NOT NULL,
                "Description" TEXT,
                "Amount" DECIMAL(10, 2) NOT NULL,
                "Date" DATE DEFAULT CURRENT_DATE
            );
        `);

        await client.query('COMMIT');
        client.release();
        console.log("Database tables initialized successfully.");

        // Testing: Ek default license daalna (agar koi maujood nahi hai)
        const licenseCheck = await pool.query(`SELECT COUNT(*) FROM "${LICENSES_TABLE_NAME}"`);
        if (licenseCheck.rows[0].count == 0) {
            console.log("Inserting default license for testing purposes.");
            const defaultLicenseKey = 'TEST-LIC-12345';
            const issuedDate = new Date().toISOString().split('T')[0];
            const expiryDate = new Date(new Date().setFullYear(new Date().getFullYear() + 1)).toISOString().split('T')[0];
            
            await pool.query(`
                INSERT INTO "${LICENSES_TABLE_NAME}" ("License Key", "Issued Date", "Expiry Date", "Status", "Issued To")
                VALUES ($1, $2, $3, $4, $5);
            `, [defaultLicenseKey, issuedDate, expiryDate, 'Active', 'Test User']);
            console.log("Default license inserted.");
        }


    } catch (err) {
        console.error("Database initialization failed:", err.message);
        throw err;
    }
}

// ===================================
//              API ENDPOINTS
// ===================================

// --- 1. System & Authentication Endpoints ---

// 1.1 License Check Endpoint
app.post('/api/check-license', async (req, res) => {
    const { licenseKey } = req.body;
    
    const decryptedData = decryptLicense(licenseKey);
    
    if (!decryptedData) {
        return res.status(401).json({ isValid: false, message: 'Invalid license format or decryption failed.' });
    }

    const [decryptedKey, decryptedExpiryDateStr] = decryptedData.split('|');
    const decryptedExpiryDate = new Date(decryptedExpiryDateStr);
    const currentDate = new Date();

    if (decryptedKey !== licenseKey) {
        return res.status(401).json({ isValid: false, message: 'License Key mismatch.' });
    }

    try {
        const result = await pool.query(
            `SELECT "Expiry Date", "Status" FROM "${LICENSES_TABLE_NAME}" WHERE "License Key" = $1`,
            [decryptedKey]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ isValid: false, message: 'License not found.' });
        }

        const dbExpiryDate = new Date(result.rows[0]["Expiry Date"]);
        const status = result.rows[0]["Status"];

        if (status !== 'Active' || dbExpiryDate < currentDate) {
            return res.status(401).json({ isValid: false, message: 'License is inactive or expired.' });
        }
        
        return res.json({ isValid: true, expiryDate: dbExpiryDate.toISOString().split('T')[0] });

    } catch (error) {
        console.error("Database error during license check:", error);
        return res.status(500).json({ isValid: false, message: `Server error: ${error.message}` });
    }
});

// 1.2 Admin Login Endpoint
app.post('/api/admin-login', (req, res) => {
    const { password } = req.body;
    const hashedPassword = hashPassword(password);
    const adminHashedPass = hashPassword(ADMIN_PASSWORD);

    if (hashedPassword === adminHashedPass) {
        // Simple token (JWT is recommended for production)
        const token = createHash('sha256').update(ADMIN_PASSWORD + Date.now()).digest('hex');
        res.json({ success: true, token });
    } else {
        res.status(401).json({ success: false, message: 'Invalid admin password' });
    }
});


// --- 2. Sales Management Endpoints ---

// 2.1 Sales Record karna
app.post('/api/record-sale', async (req, res) => {
    const { invoiceNumber, customerName, items, totalAmount, gstAmount } = req.body;

    if (!invoiceNumber || !customerName || !items || !totalAmount || !gstAmount || !items.length) {
        return res.status(400).json({ success: false, message: 'Missing required sale details.' });
    }

    const itemsJson = JSON.stringify(items);
    
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Sales Table mein record daalein
        const saleQuery = `
            INSERT INTO "${SALES_TABLE_NAME}" ("Invoice Number", "Customer Name", "Items Sold", "Total Amount", "GST Amount")
            VALUES ($1, $2, $3, $4, $5);
        `;
        await client.query(saleQuery, [invoiceNumber, customerName, itemsJson, totalAmount, gstAmount]);

        // Stock Quantity ko kam karein (update)
        for (const item of items) {
            const stockUpdateQuery = `
                UPDATE "${STOCK_TABLE_NAME}" SET "Quantity" = "Quantity" - $1 WHERE "SKU" = $2 AND "Quantity" >= $1;
            `;
            const result = await client.query(stockUpdateQuery, [item.quantity, item.sku]);
             if (result.rowCount === 0) {
                 // Agar stock update nahi hua toh rollback kar dein
                 throw new Error(`Insufficient stock or invalid SKU for item: ${item.sku}`);
             }
        }

        // Customer ko add/update karein
        const customerCheckQuery = `SELECT * FROM "${CUSTOMERS_TABLE_NAME}" WHERE "Customer Name" = $1;`;
        const existingCustomer = await client.query(customerCheckQuery, [customerName]);
        if (existingCustomer.rows.length === 0) {
            const customerAddQuery = `
                INSERT INTO "${CUSTOMERS_TABLE_NAME}" ("Customer Name") VALUES ($1);
            `;
            await client.query(customerAddQuery, [customerName]);
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

// 2.2 Sales list dekhna
app.get('/api/sales', async (req, res) => {
    try {
        const result = await pool.query(`SELECT * FROM "${SALES_TABLE_NAME}" ORDER BY "Date" DESC`);
        res.json(result.rows);
    } catch (error) {
        console.error("Sales Fetch Error:", error);
        res.status(500).json({ message: `Failed to fetch sales data: ${error.message}` });
    }
});


// --- 3. Purchases Management Endpoints (Naye Endpoints) ---

// 3.1 Purchase record karna aur stock badhana
app.post('/api/record-purchase', async (req, res) => {
    const { billNumber, supplierName, items, totalCost } = req.body;

    if (!billNumber || !items || !totalCost || !items.length) {
        return res.status(400).json({ success: false, message: 'Missing required purchase details.' });
    }

    const itemsJson = JSON.stringify(items);
    
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Purchases Table mein record daalein
        const purchaseQuery = `
            INSERT INTO "${PURCHASES_TABLE_NAME}" ("Bill Number", "Supplier Name", "Items Purchased", "Total Cost")
            VALUES ($1, $2, $3, $4);
        `;
        await client.query(purchaseQuery, [billNumber, supplierName, itemsJson, totalCost]);

        // Stock Quantity ko badhayein (increase)
        for (const item of items) {
            // Hum maan rahe hain ki khareeda gaya item pehle se Stock table mein maujood hai.
            const stockUpdateQuery = `
                UPDATE "${STOCK_TABLE_NAME}" SET 
                "Quantity" = "Quantity" + $1,
                "Purchase Price" = $3, -- Nayi purchase price update kar sakte hain
                "Date Added" = CURRENT_DATE
                WHERE "SKU" = $2;
            `;
            // item object mein quantity, sku aur (naye) purchasePrice honi chahiye
            await client.query(stockUpdateQuery, [item.quantity, item.sku, item.purchasePrice]); 
        }

        await client.query('COMMIT');
        res.status(201).json({ success: true, message: 'Purchase recorded and stock updated successfully!' });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error("Purchase Recording Error:", error);
        res.status(500).json({ success: false, message: `Failed to record purchase: ${error.message}` });
    } finally {
        client.release();
    }
});

// 3.2 Purchases list dekhna
app.get('/api/purchases', async (req, res) => {
    try {
        const result = await pool.query(`SELECT * FROM "${PURCHASES_TABLE_NAME}" ORDER BY "Date" DESC`);
        res.json(result.rows);
    } catch (error) {
        console.error("Purchases Fetch Error:", error);
        res.status(500).json({ message: `Failed to fetch purchases data: ${error.message}` });
    }
});


// --- 4. Expenses Management Endpoints (Naye Endpoints) ---

// 4.1 Expense record karna
app.post('/api/record-expense', async (req, res) => {
    const { category, description, amount } = req.body;

    if (!category || amount === undefined) {
        return res.status(400).json({ success: false, message: 'Missing required expense details (Category and Amount).' });
    }
    
    try {
        const query = `
            INSERT INTO "${EXPENSES_TABLE_NAME}" ("Category", "Description", "Amount")
            VALUES ($1, $2, $3)
            RETURNING *;
        `;
        const result = await pool.query(query, [category, description, amount]);
        res.status(201).json({ success: true, message: 'Expense recorded successfully!', expense: result.rows[0] });
    } catch (error) {
        console.error("Expense Recording Error:", error);
        res.status(500).json({ success: false, message: `Failed to record expense: ${error.message}` });
    }
});

// 4.2 Expenses list dekhna
app.get('/api/expenses', async (req, res) => {
    try {
        const result = await pool.query(`SELECT * FROM "${EXPENSES_TABLE_NAME}" ORDER BY "Date" DESC`);
        res.json(result.rows);
    } catch (error) {
        console.error("Expenses Fetch Error:", error);
        res.status(500).json({ message: `Failed to fetch expenses data: ${error.message}` });
    }
});


// --- 5. Stock & Inventory Endpoints ---

// 5.1 Stock ki list
app.get('/api/stock', async (req, res) => {
    try {
        const result = await pool.query(`SELECT * FROM "${STOCK_TABLE_NAME}" ORDER BY "Date Added" DESC`);
        res.json(result.rows);
    } catch (error) {
        console.error("Stock Fetch Error:", error);
        res.status(500).json({ message: `Failed to fetch stock data: ${error.message}` });
    }
});

// 5.2 Naya Stock Item add/update karein
app.post('/api/stock', async (req, res) => {
    const { sku, itemName, quantity, purchasePrice, sellingPrice, gstRate } = req.body;
    if (!sku || !itemName || quantity === undefined || purchasePrice === undefined || sellingPrice === undefined || gstRate === undefined) {
        return res.status(400).json({ success: false, message: 'Missing required stock item details.' });
    }

    try {
        const query = `
            INSERT INTO "${STOCK_TABLE_NAME}" ("SKU", "Item Name", "Quantity", "Purchase Price", "Selling Price", "GST Rate")
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT ("SKU") DO UPDATE SET
                "Item Name" = EXCLUDED."Item Name",
                "Quantity" = "${STOCK_TABLE_NAME}"."Quantity" + EXCLUDED."Quantity",
                "Purchase Price" = EXCLUDED."Purchase Price",
                "Selling Price" = EXCLUDED."Selling Price",
                "GST Rate" = EXCLUDED."GST Rate",
                "Date Added" = CURRENT_DATE
            RETURNING *;
        `;
        const result = await pool.query(query, [sku, itemName, quantity, purchasePrice, sellingPrice, gstRate]);
        res.status(201).json({ success: true, message: 'Stock item added/updated successfully!', item: result.rows[0] });
    } catch (error) {
        console.error("Stock Add Error:", error);
        res.status(500).json({ success: false, message: `Failed to add/update stock item: ${error.message}` });
    }
});

// --- 6. CRM (Customers) Endpoints ---

// 6.1 Customers ki list
app.get('/api/customers', async (req, res) => {
    try {
        const result = await pool.query(`SELECT * FROM "${CUSTOMERS_TABLE_NAME}" ORDER BY "Date Added" DESC`);
        res.json(result.rows);
    } catch (error) {
        console.error("Customers Fetch Error:", error);
        res.status(500).json({ message: `Failed to fetch customer data: ${error.message}` });
    }
});


// --- 7. Dashboard & Reporting Endpoints (Updated) ---

// 7.1 Comprehensive Dashboard Stats
app.get('/api/dashboard-stats', async (req, res) => {
    try {
        // Sales aur Tax ka total
        const salesQuery = `SELECT SUM("Total Amount") as total_sales, SUM("GST Amount") as total_tax FROM "${SALES_TABLE_NAME}"`;
        // Total Cost of Purchases (COGS proxy)
        const purchasesCostQuery = `SELECT SUM("Total Cost") as total_cogs FROM "${PURCHASES_TABLE_NAME}"`;
        // Total Expenses
        const expensesQuery = `SELECT SUM("Amount") as total_expenses FROM "${EXPENSES_TABLE_NAME}"`;
        // Stock ki current value
        const stockValueQuery = `SELECT SUM("Purchase Price" * "Quantity") as stock_value FROM "${STOCK_TABLE_NAME}"`;
        
        const [salesRes, purchasesRes, expensesRes, stockValueRes] = await Promise.all([
            pool.query(salesQuery),
            pool.query(purchasesCostQuery),
            pool.query(expensesQuery),
            pool.query(stockValueQuery)
        ]);

        const totalSalesRevenue = parseFloat(salesRes.rows[0].total_sales) || 0;
        const totalTaxCollected = parseFloat(salesRes.rows[0].total_tax) || 0;
        const totalCOGS = parseFloat(purchasesRes.rows[0].total_cogs) || 0;
        const totalExpenses = parseFloat(expensesRes.rows[0].total_expenses) || 0;
        const stockValue = parseFloat(stockValueRes.rows[0].stock_value) || 0;

        // Financial Calculation
        const grossProfit = totalSalesRevenue - totalCOGS;
        const netProfit = grossProfit - totalExpenses; // Approximate Net Profit

        res.json({
            totalSalesRevenue: totalSalesRevenue,
            totalTaxCollected: totalTaxCollected,
            totalCOGS: totalCOGS,
            totalExpenses: totalExpenses, // Naya field
            grossProfit: grossProfit,
            netProfit: netProfit, // Naya field
            stockValue: stockValue
        });
    } catch (error) {
        console.error("Dashboard Stats Fetch Error:", error);
        res.status(500).json({ message: `Failed to fetch dashboard stats: ${error.message}` });
    }
});

// 7.2 Admin Overview (Low Stock, Recent Sales/Customers)
app.get('/api/admin-overview', async (req, res) => {
    try {
        const customers = await pool.query(`SELECT "Customer Name", "Phone", "Date Added" FROM "${CUSTOMERS_TABLE_NAME}" ORDER BY "Date Added" DESC LIMIT 10`);
        const sales = await pool.query(`SELECT "Invoice Number", "Customer Name", "Total Amount", "Date" FROM "${SALES_TABLE_NAME}" ORDER BY "Date" DESC LIMIT 10`);
        const lowStock = await pool.query(`SELECT "SKU", "Item Name", "Quantity" FROM "${STOCK_TABLE_NAME}" WHERE "Quantity" <= 10 ORDER BY "Quantity" ASC`);

        res.json({
            customers: customers.rows,
            sales: sales.rows,
            lowStock: lowStock.rows
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
        await initializeDatabase(); 
        
        app.listen(PORT, () => {
            console.log(`Server is running on port ${PORT}`);
        });
    } catch (err) {
        console.error("Server failed to start due to DB error:", err);
    }
}

startServer();
