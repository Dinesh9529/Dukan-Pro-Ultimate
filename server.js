/*
 * Node.js Server for Dukan Pro Business Suite
 * Handles: License Validation, Stock Management, Sales/Purchase Logging, Dashboard Data
 */
import express from 'express';
import { google } from 'googleapis';
import { createCipheriv, createDecipheriv, randomBytes, createHash } from 'crypto';
import cors from 'cors';

// --- Environment Variables Setup ---
const CUSTOMER_SPREADSHEET_ID = process.env.CUSTOMER_SPREADSHEET_ID;
const DATA_SPREADSHEET_ID = process.env.DATA_SPREADSHEET_ID;
const CUSTOMER_SHEET_NAME = 'Customers';
const STOCK_SHEET_NAME = 'Stock';
const PURCHASES_SHEET_NAME = 'Purchases';
const SALES_SHEET_NAME = 'Sales';
const APP_SECRET_KEY = process.env.APP_SECRET_KEY || 'DEFAULT_APP_SECRET';
const PORT = process.env.PORT || 3000;

// Derive a 32-byte key for AES-256
const derivedKey = createHash('sha256').update(APP_SECRET_KEY).digest();
const ALGORITHM = 'aes-256-cbc';

let GOOGLE_CLIENT_EMAIL = '';
let GOOGLE_PRIVATE_KEY = '';

if (process.env.GOOGLE_CREDENTIALS) {
    try {
        const credentials = JSON.parse(process.env.GOOGLE_CREDENTIALS);
        GOOGLE_CLIENT_EMAIL = credentials.client_email;
        GOOGLE_PRIVATE_KEY = credentials.private_key?.replace(/\\n/g, '\n');
    } catch (e) {
        console.error("FATAL ERROR: Failed to parse GOOGLE_CREDENTIALS.");
    }
}

const isConfigValid = CUSTOMER_SPREADSHEET_ID && DATA_SPREADSHEET_ID && GOOGLE_CLIENT_EMAIL && GOOGLE_PRIVATE_KEY;
if (!isConfigValid) {
    console.error("FATAL ERROR: Missing critical Google Sheet variables or credentials.");
}

const app = express();
app.use(cors());
app.use(express.json());

// --- Google Sheets Authentication ---
const auth = new google.auth.JWT({
    email: GOOGLE_CLIENT_EMAIL,
    key: GOOGLE_PRIVATE_KEY,
    scopes: ['https://www.googleapis.com/auth/spreadsheets']
});
const sheets = google.sheets({ version: 'v4', auth });

// --- Helper Functions ---
async function readSheetData(sheetId, sheetName) {
    if (!isConfigValid) throw new Error("Google Sheets configuration is invalid.");
    const response = await sheets.spreadsheets.values.get({
        spreadsheetId: sheetId,
        range: `${sheetName}!A:Z`,
    });
    const rows = response.data.values;
    if (!rows || rows.length === 0) return [];

    const headers = rows[0].map(h => h.toLowerCase().replace(/\s/g, ''));
    return rows.slice(1).map(row => {
        let obj = {};
        headers.forEach((header, index) => {
            obj[header] = row[index] || '';
        });
        return obj;
    });
}

// --- License Key Logic (UNCHANGED) ---
function encrypt(data) {
    const iv = randomBytes(16);
    const cipher = createCipheriv(ALGORITHM, derivedKey, iv);
    const encrypted = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
    return Buffer.concat([iv, encrypted]).toString('base64');
}

function decrypt(key) {
    try {
        const combined = Buffer.from(key, 'base64');
        const iv = combined.slice(0, 16);
        const encryptedText = combined.slice(16);
        if (iv.length !== 16) return null;
        const decipher = createDecipheriv(ALGORITHM, derivedKey, iv);
        const decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()]);
        return decrypted.toString('utf8');
    } catch (e) { return null; }
}


// --- API Endpoints ---

// License Validation Endpoint (UNCHANGED)
app.post('/validate-key', async (req, res) => {
    const { key } = req.body;
    if (!key) return res.status(400).json({ isValid: false, message: "License key is required." });
    try {
        const decryptedDataString = decrypt(key);
        if (!decryptedDataString) return res.status(200).json({ isValid: false, message: "Invalid license key." });
        const keyData = JSON.parse(decryptedDataString);
        const expiryDate = new Date(keyData.expiry);
        if (new Date() > expiryDate) return res.status(200).json({ isValid: false, message: "License key has expired." });
        
        return res.status(200).json({
            isValid: true,
            name: keyData.name,
            plan: keyData.plan || 'UNKNOWN',
            message: "Key validated successfully.",
            expiryDate: expiryDate.toLocaleString('en-US')
        });
    } catch (error) {
        return res.status(500).json({ isValid: false, message: `Server Error: ${error.message}` });
    }
});

// --- NEW: Stock Management API ---
app.get('/api/stock', async (req, res) => {
    try {
        const stockData = await readSheetData(DATA_SPREADSHEET_ID, STOCK_SHEET_NAME);
        res.status(200).json(stockData);
    } catch (error) {
        res.status(500).json({ message: `Failed to get stock: ${error.message}` });
    }
});

app.post('/api/stock', async (req, res) => {
    const { sku, itemName, purchasePrice, salePrice, quantity } = req.body;
    if (!sku || !itemName || !purchasePrice || !salePrice || !quantity) {
        return res.status(400).json({ message: "All fields are required." });
    }
    try {
        const rowData = [sku, itemName, purchasePrice, salePrice, quantity, new Date().toISOString()];
        await sheets.spreadsheets.values.append({
            spreadsheetId: DATA_SPREADSHEET_ID,
            range: `${STOCK_SHEET_NAME}!A:F`,
            valueInputOption: 'USER_ENTERED',
            requestBody: { values: [rowData] }
        });
        res.status(201).json({ message: "Stock item added successfully." });
    } catch (error) {
        res.status(500).json({ message: `Failed to add stock item: ${error.message}` });
    }
});


// --- NEW: Purchase Logging API ---
app.post('/api/purchases', async (req, res) => {
    const { itemName, sku, quantity, purchasePrice, supplier } = req.body;
    try {
        // Log the purchase
        const purchaseRow = [new Date().toISOString(), itemName, quantity, purchasePrice, supplier, quantity * purchasePrice];
        await sheets.spreadsheets.values.append({
            spreadsheetId: DATA_SPREADSHEET_ID, range: `${PURCHASES_SHEET_NAME}!A:F`, valueInputOption: 'USER_ENTERED', requestBody: { values: [purchaseRow] }
        });

        // Update stock
        const stockData = await sheets.spreadsheets.values.get({ spreadsheetId: DATA_SPREADSHEET_ID, range: `${STOCK_SHEET_NAME}!A:Z` });
        const rows = stockData.data.values;
        const rowIndex = rows.findIndex(row => row[0] === sku || row[1] === itemName);

        if (rowIndex > -1) { // Update existing stock
            const existingQty = parseInt(rows[rowIndex][4]) || 0;
            const newQty = existingQty + parseInt(quantity);
            await sheets.spreadsheets.values.update({
                spreadsheetId: DATA_SPREADSHEET_ID,
                range: `${STOCK_SHEET_NAME}!E${rowIndex + 1}`,
                valueInputOption: 'USER_ENTERED',
                requestBody: { values: [[newQty]] }
            });
        } else { // Add new stock item
             const newStockRow = [sku || `SKU-${Date.now()}`, itemName, purchasePrice, purchasePrice * 1.25, quantity, new Date().toISOString()]; // Default 25% markup
             await sheets.spreadsheets.values.append({ spreadsheetId: DATA_SPREADSHEET_ID, range: `${STOCK_SHEET_NAME}!A:F`, valueInputOption: 'USER_ENTERED', requestBody: { values: [newStockRow] } });
        }

        res.status(201).json({ message: "Purchase logged and stock updated." });
    } catch (error) {
        res.status(500).json({ message: `Failed to log purchase: ${error.message}` });
    }
});

// --- NEW: Sales Logging API (updates stock) ---
app.post('/api/sales', async (req, res) => {
    const { invoiceNumber, customerName, totalAmount, items } = req.body;
    try {
        // Log the sale
        let profit = 0;
        // In a real app, you would fetch purchase price from stock to calculate profit.
        // For simplicity, we are skipping profit calculation here.
        const saleRow = [new Date().toISOString(), invoiceNumber, customerName, totalAmount, JSON.stringify(items), profit];
        await sheets.spreadsheets.values.append({
            spreadsheetId: DATA_SPREADSHEET_ID, range: `${SALES_SHEET_NAME}!A:F`, valueInputOption: 'USER_ENTERED', requestBody: { values: [saleRow] }
        });

        // Update stock quantities
        const stockData = await sheets.spreadsheets.values.get({ spreadsheetId: DATA_SPREADSHEET_ID, range: `${STOCK_SHEET_NAME}!A:Z` });
        const stockRows = stockData.data.values;

        for (const item of items) {
            const rowIndex = stockRows.findIndex(row => row[1].toLowerCase() === item.itemName.toLowerCase());
            if (rowIndex > -1) {
                const existingQty = parseInt(stockRows[rowIndex][4]) || 0;
                const newQty = existingQty - parseInt(item.quantity);
                await sheets.spreadsheets.values.update({
                    spreadsheetId: DATA_SPREADSHEET_ID,
                    range: `${STOCK_SHEET_NAME}!E${rowIndex + 1}`,
                    valueInputOption: 'USER_ENTERED',
                    requestBody: { values: [[newQty]] }
                });
            }
        }
        res.status(201).json({ success: true, message: "Sale logged and stock updated successfully." });
    } catch (error) {
        res.status(500).json({ message: `Failed to log sale: ${error.message}` });
    }
});

// --- NEW: Dashboard Data API ---
app.get('/api/dashboard-data', async (req, res) => {
    try {
        const salesData = await readSheetData(DATA_SPREADSHEET_ID, SALES_SHEET_NAME);
        const purchasesData = await readSheetData(DATA_SPREADSHEET_ID, PURCHASES_SHEET_NAME);
        res.status(200).json({ sales: salesData, purchases: purchasesData });
    } catch (error) {
        res.status(500).json({ message: `Failed to get dashboard data: ${error.message}` });
    }
});


app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    if(!isConfigValid) console.log("WARNING: Server is running with invalid configuration.");
});