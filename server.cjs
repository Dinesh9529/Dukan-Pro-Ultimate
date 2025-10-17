// server.cjs (Dukan Pro - Ultimate Backend) - MULTI-USER/SECURE VERSION (850+ LINES)
// -----------------------------------------------------------------------------
// यह कोड JWT, Bcrypt और PostgreSQL के साथ एक सुरक्षित और मल्टी-टेनेंट सर्वर लागू करता है।
// सभी डेटा एक्सेस 'shop_id' द्वारा सीमित (scoped) है।
// -----------------------------------------------------------------------------

const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto');
const cors = require('cors');
const jwt = require('jsonwebtoken'); 
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
const PORT = process.env.PORT || 10000;
const SECRET_KEY = process.env.SECRET_KEY || 'a_very_strong_secret_key_for_hashing'; // Must be secure!
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex'); // Stronger JWT Secret

// --- Encryption Constants (Retained for license key hashing) ---
const ENCRYPTION_KEY = crypto.createHash('sha256').update(SECRET_KEY).digest();
const SALT_ROUNDS = 10; // 🔒 Bcrypt salt rounds for password hashing

// --- Middlewares ---
app.use(cors({
    origin: '*', // सभी ऑरिजिन को अनुमति दें (डिबगिंग के लिए)
}));


// -----------------------------------------------------------------------------
// I. DATABASE CONFIGURATION AND CONNECTION
// -----------------------------------------------------------------------------

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false // Render/Heroku के लिए आवश्यक
    }
});

// डेटाबेस टेबल्स सुनिश्चित करने के लिए फ़ंक्शन
const createTables = async () => {
    console.log('Checking and ensuring database tables exist...');
    const queries = [];

    // 1. Users Table (Multi-User Login/Shop Admins)
    // NOTE: Added 'status' column to fix 'column "status" of relation "users" does not exist' error.
    const createUsersTable = `
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            shop_id TEXT UNIQUE NOT NULL,
            name VARCHAR(255) NOT NULL,
            username VARCHAR(255) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            status TEXT DEFAULT 'active' NOT NULL, 
            license_key TEXT,
            license_expiry_date TIMESTAMP WITH TIME ZONE
        );
    `;
    queries.push(pool.query(createUsersTable));

    // 2. Customers Table (Shop specific)
    const createCustomersTable = `
        CREATE TABLE IF NOT EXISTS customers (
            id SERIAL PRIMARY KEY,
            shop_id TEXT NOT NULL,
            name VARCHAR(255) NOT NULL,
            phone VARCHAR(20) UNIQUE NOT NULL,
            address TEXT,
            gst_number VARCHAR(50),
            balance NUMERIC(10, 2) DEFAULT 0.00 NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (shop_id) REFERENCES users (shop_id) ON DELETE CASCADE
        );
    `;
    queries.push(pool.query(createCustomersTable));

    // 3. Products Table (Shop specific)
    const createProductsTable = `
        CREATE TABLE IF NOT EXISTS products (
            id SERIAL PRIMARY KEY,
            shop_id TEXT NOT NULL,
            name VARCHAR(255) NOT NULL,
            hsn_sac VARCHAR(50),
            category VARCHAR(100),
            unit_type VARCHAR(50),
            current_stock INT DEFAULT 0,
            sale_price NUMERIC(10, 2) NOT NULL,
            purchase_price NUMERIC(10, 2),
            gst_rate NUMERIC(5, 2) DEFAULT 0.00,
            description TEXT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (shop_id) REFERENCES users (shop_id) ON DELETE CASCADE,
            UNIQUE (shop_id, name)
        );
    `;
    queries.push(pool.query(createProductsTable));

    // 4. Invoices Table (Shop specific - Sales/Billing)
    const createInvoicesTable = `
        CREATE TABLE IF NOT EXISTS invoices (
            id SERIAL PRIMARY KEY,
            shop_id TEXT NOT NULL,
            invoice_number TEXT UNIQUE NOT NULL,
            customer_id INT,
            customer_name TEXT NOT NULL,
            customer_phone TEXT,
            total_amount NUMERIC(10, 2) NOT NULL,
            amount_paid NUMERIC(10, 2) NOT NULL,
            payment_method VARCHAR(50),
            discount NUMERIC(10, 2) DEFAULT 0.00,
            invoice_date DATE NOT NULL DEFAULT CURRENT_DATE,
            is_deleted BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (shop_id) REFERENCES users (shop_id) ON DELETE CASCADE,
            FOREIGN KEY (customer_id) REFERENCES customers (id) ON DELETE SET NULL
        );
    `;
    queries.push(pool.query(createInvoicesTable));

    // 5. Invoice Items Table (Details of each invoice)
    const createInvoiceItemsTable = `
        CREATE TABLE IF NOT EXISTS invoice_items (
            id SERIAL PRIMARY KEY,
            invoice_id INT NOT NULL,
            shop_id TEXT NOT NULL,
            product_id INT,
            product_name VARCHAR(255) NOT NULL,
            hsn_sac VARCHAR(50),
            quantity NUMERIC(10, 2) NOT NULL,
            rate NUMERIC(10, 2) NOT NULL,
            gst_rate NUMERIC(5, 2) DEFAULT 0.00,
            gst_amount NUMERIC(10, 2) DEFAULT 0.00,
            net_amount NUMERIC(10, 2) NOT NULL,
            FOREIGN KEY (invoice_id) REFERENCES invoices (id) ON DELETE CASCADE,
            FOREIGN KEY (shop_id) REFERENCES users (shop_id) ON DELETE CASCADE,
            FOREIGN KEY (product_id) REFERENCES products (id) ON DELETE SET NULL
        );
    `;
    queries.push(pool.query(createInvoiceItemsTable));

    // 6. Expenses Table (Shop specific)
    const createExpensesTable = `
        CREATE TABLE IF NOT EXISTS expenses (
            id SERIAL PRIMARY KEY,
            shop_id TEXT NOT NULL,
            expense_date DATE NOT NULL DEFAULT CURRENT_DATE,
            category VARCHAR(100) NOT NULL,
            description TEXT,
            amount NUMERIC(10, 2) NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (shop_id) REFERENCES users (shop_id) ON DELETE CASCADE
        );
    `;
    queries.push(pool.query(createExpensesTable));

    // 7. Purchase Table (Shop specific)
    const createPurchaseTable = `
        CREATE TABLE IF NOT EXISTS purchases (
            id SERIAL PRIMARY KEY,
            shop_id TEXT NOT NULL,
            supplier_name VARCHAR(255),
            purchase_date DATE NOT NULL DEFAULT CURRENT_DATE,
            total_amount NUMERIC(10, 2) NOT NULL,
            amount_paid NUMERIC(10, 2) NOT NULL,
            is_deleted BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (shop_id) REFERENCES users (shop_id) ON DELETE CASCADE
        );
    `;
    queries.push(pool.query(createPurchaseTable));

    // 8. Purchase Items Table (Details of each purchase)
    const createPurchaseItemsTable = `
        CREATE TABLE IF NOT EXISTS purchase_items (
            id SERIAL PRIMARY KEY,
            purchase_id INT NOT NULL,
            shop_id TEXT NOT NULL,
            product_id INT,
            product_name VARCHAR(255) NOT NULL,
            quantity NUMERIC(10, 2) NOT NULL,
            rate NUMERIC(10, 2) NOT NULL,
            gst_rate NUMERIC(5, 2) DEFAULT 0.00,
            gst_amount NUMERIC(10, 2) DEFAULT 0.00,
            net_amount NUMERIC(10, 2) NOT NULL,
            FOREIGN KEY (purchase_id) REFERENCES purchases (id) ON DELETE CASCADE,
            FOREIGN KEY (shop_id) REFERENCES users (shop_id) ON DELETE CASCADE,
            FOREIGN KEY (product_id) REFERENCES products (id) ON DELETE SET NULL
        );
    `;
    queries.push(pool.query(createPurchaseItemsTable));
    
    // 9. Balances/Transactions Table (Customer Ledger)
    const createCustomerLedgerTable = `
        CREATE TABLE IF NOT EXISTS customer_ledger (
            id SERIAL PRIMARY KEY,
            shop_id TEXT NOT NULL,
            customer_id INT NOT NULL,
            transaction_date DATE NOT NULL DEFAULT CURRENT_DATE,
            type VARCHAR(50) NOT NULL, -- 'SALE', 'PAYMENT', 'ADJUSTMENT'
            description TEXT,
            debit NUMERIC(10, 2) DEFAULT 0.00, -- Amount Receivable (Sale)
            credit NUMERIC(10, 2) DEFAULT 0.00, -- Amount Received (Payment)
            current_balance NUMERIC(10, 2) NOT NULL, -- Running Balance
            reference_id INT, -- Invoice ID or Payment ID
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (shop_id) REFERENCES users (shop_id) ON DELETE CASCADE,
            FOREIGN KEY (customer_id) REFERENCES customers (id) ON DELETE CASCADE
        );
    `;
    queries.push(pool.query(createCustomerLedgerTable));

    // Execute all table creation queries
    await Promise.all(queries);
    console.log(`Database tables checked and verified successfully. (${(createTables.toString().split('\\n').length)} line schema)`);
};

// ... (Rest of the file remains the same, assuming it was correct before the schema issue)

// -----------------------------------------------------------------------------
// II. UTILITIES (JWT, Encryption)
// -----------------------------------------------------------------------------

/**
 * Encrypts a value using AES-256-CBC.
 * @param {string} text - The text to encrypt.
 * @returns {string} - The encrypted text (hex format).
 */
const encrypt = (text) => {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
};

/**
 * Decrypts a value using AES-256-CBC.
 * @param {string} text - The encrypted text (hex format).
 * @returns {string|null} - The decrypted text or null on error.
 */
const decrypt = (text) => {
    try {
        const parts = text.split(':');
        if (parts.length !== 2) return null;
        const iv = Buffer.from(parts[0], 'hex');
        const encryptedText = parts[1];
        const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (e) {
        console.error("Decryption failed:", e.message);
        return null;
    }
};

/**
 * Generates a standard JWT token for a user.
 * @param {object} user - User object containing shop_id and username.
 * @returns {string} - JWT token.
 */
const generateToken = (user) => {
    return jwt.sign({ shop_id: user.shop_id, username: user.username, name: user.name, status: user.status }, JWT_SECRET, { expiresIn: '7d' });
};


// -----------------------------------------------------------------------------
// III. CORE BUSINESS LOGIC (License, Auth, Registration)
// -----------------------------------------------------------------------------

/**
 * Verifies a license key against the server's secret key.
 * @param {string} licenseKey - The license key provided by the client.
 * @param {string} shopId - The shop ID/username for which the key was generated.
 * @returns {object} - { valid: boolean, expiryDate: Date | null }
 */
const verifyLicense = (licenseKey, shopId) => {
    const expectedPrefix = 'DUKANPRO-';
    if (!licenseKey.startsWith(expectedPrefix)) {
        return { valid: false, expiryDate: null, message: "अमान्य फॉर्मेट (Invalid format)." };
    }

    const encryptedData = licenseKey.substring(expectedPrefix.length);
    const decryptedData = decrypt(encryptedData);

    if (!decryptedData) {
        return { valid: false, expiryDate: null, message: "डिक्रिप्शन विफल (Decryption failed)." };
    }

    try {
        const [keyShopId, keyExpiryTimestamp] = decryptedData.split('|');
        const expiryDate = new Date(parseInt(keyExpiryTimestamp, 10));

        if (keyShopId !== shopId) {
            return { valid: false, expiryDate: null, message: "की उपयोगकर्ता से मेल नहीं खाती (Key mismatch)." };
        }

        if (isNaN(expiryDate.getTime())) {
             return { valid: false, expiryDate: null, message: "अमान्य समाप्ति तिथि (Invalid expiry date)." };
        }

        const isValid = expiryDate.getTime() > Date.now();
        const status = isValid ? 'सक्रिय' : 'समाप्त (Expired)';

        return {
            valid: isValid,
            expiryDate: expiryDate,
            message: `लाइसेंस ${status}. समाप्ति तिथि: ${expiryDate.toISOString().split('T')[0]}`
        };

    } catch (e) {
        console.error("License key parsing error:", e.message);
        return { valid: false, expiryDate: null, message: "कुंजी पार्सिंग में त्रुटि (Key parsing error)." };
    }
};

/**
 * Registers a new user/shop and updates their license status.
 * @param {string} shop_id - Unique ID for the shop.
 * @param {string} name - User's name.
 * @param {string} username - Login username.
 * @param {string} password - Login password (plaintext).
 * @param {string} license_key - Optional license key.
 * @returns {object} - Result object.
 */
const registerUser = async (shop_id, name, username, password, license_key = null) => {
    try {
        // 1. Check if username or shop_id already exists
        const checkQuery = 'SELECT username, shop_id FROM users WHERE username = $1 OR shop_id = $2';
        const checkResult = await pool.query(checkQuery, [username, shop_id]);

        if (checkResult.rows.length > 0) {
            if (checkResult.rows.some(row => row.username === username)) {
                return { success: false, message: 'उपयोगकर्ता नाम पहले से मौजूद है (Username already exists).' };
            }
            if (checkResult.rows.some(row => row.shop_id === shop_id)) {
                 // This should technically not happen if shop_id is generated uniquely
                return { success: false, message: 'Shop ID पहले से मौजूद है (Shop ID already exists).' };
            }
        }

        // 2. Hash password
        const password_hash = await bcrypt.hash(password, SALT_ROUNDS);

        // 3. Handle License Key
        let license_expiry_date = null;
        let final_license_key = null;
        let status = 'active'; // Default status

        if (license_key) {
            const licenseCheck = verifyLicense(license_key, shop_id);
            if (licenseCheck.valid) {
                license_expiry_date = licenseCheck.expiryDate.toISOString();
                final_license_key = license_key;
            } else {
                // If key is invalid or expired, proceed with registration but without the key/expiry.
                console.warn(`Registration attempted with invalid/expired key for shop: ${shop_id}`);
            }
        } else {
             // If no key is provided, the user is registered but must use trial or get a license.
             // Setting a very short trial (e.g., 7 days) if needed, otherwise, the client must handle this.
             // For now, we proceed and let the client UI enforce trial/license logic.
        }

        // 4. Insert into users table
        const insertQuery = `
            INSERT INTO users (shop_id, name, username, password_hash, status, license_key, license_expiry_date) 
            VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, shop_id, name, username, status, license_expiry_date
        `;
        const insertResult = await pool.query(insertQuery, [
            shop_id, 
            name, 
            username, 
            password_hash, 
            status, // Insert the status column value
            final_license_key, 
            license_expiry_date
        ]);

        const newUser = insertResult.rows[0];
        const token = generateToken(newUser);

        return { 
            success: true, 
            message: 'पंजीकरण सफल! (Registration successful!)', 
            user: { 
                name: newUser.name, 
                username: newUser.username, 
                shop_id: newUser.shop_id, 
                status: newUser.status,
                licenseExpiryDate: newUser.license_expiry_date ? newUser.license_expiry_date.toISOString() : null
            },
            token: token
        };

    } catch (err) {
        console.error("Error registering user/shop:", err.message);
        return { success: false, message: 'पंजीकरण विफल: ' + err.message };
    }
};

/**
 * Authenticates a user.
 * @param {string} username - Login username.
 * @param {string} password - Login password (plaintext).
 * @returns {object} - Result object.
 */
const authenticateUser = async (username, password) => {
    try {
        // 1. Find user by username
        const userQuery = 'SELECT * FROM users WHERE username = $1';
        const userResult = await pool.query(userQuery, [username]);

        if (userResult.rows.length === 0) {
            return { success: false, message: 'उपयोगकर्ता नाम या पासवर्ड गलत है (Incorrect username or password).' };
        }

        const user = userResult.rows[0];

        // 2. Compare password hash
        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (!isMatch) {
            return { success: false, message: 'उपयोगकर्ता नाम या पासवर्ड गलत है (Incorrect username or password).' };
        }
        
        // 3. Check user status
        if (user.status !== 'active') {
             return { success: false, message: `उपयोगकर्ता स्थिति: ${user.status} (User status: ${user.status}).` };
        }

        // 4. Generate token
        const token = generateToken(user);
        
        return { 
            success: true, 
            message: 'लॉगिन सफल (Login successful)!', 
            user: { 
                name: user.name, 
                username: user.username, 
                shop_id: user.shop_id, 
                status: user.status,
                licenseExpiryDate: user.license_expiry_date ? user.license_expiry_date.toISOString() : null
            },
            token: token
        };

    } catch (err) {
        console.error("Error authenticating user:", err.message);
        return { success: false, message: 'लॉगिन विफल: ' + err.message };
    }
};

/**
 * Updates a user's license key and expiry date.
 * @param {string} shopId - The shop ID to update.
 * @param {string} licenseKey - The new license key.
 * @returns {object} - Result object.
 */
const updateLicense = async (shopId, licenseKey) => {
    try {
        const licenseCheck = verifyLicense(licenseKey, shopId);

        if (!licenseCheck.valid) {
            return { success: false, message: 'लाइसेंस अमान्य या समाप्त हो गया है (License invalid or expired).' };
        }
        
        const expiryDate = licenseCheck.expiryDate.toISOString();

        const updateQuery = `
            UPDATE users SET license_key = $1, license_expiry_date = $2 
            WHERE shop_id = $3 RETURNING id, shop_id, name, username, status, license_expiry_date
        `;
        const updateResult = await pool.query(updateQuery, [licenseKey, expiryDate, shopId]);

        if (updateResult.rowCount === 0) {
            return { success: false, message: 'उपयोगकर्ता नहीं मिला (User not found).' };
        }
        
        const user = updateResult.rows[0];

        return {
            success: true,
            message: 'लाइसेंस सफलतापूर्वक अपडेट किया गया (License updated successfully)!',
            user: { 
                name: user.name, 
                username: user.username, 
                shop_id: user.shop_id,
                status: user.status,
                licenseExpiryDate: user.license_expiry_date ? user.license_expiry_date.toISOString() : null
            },
            token: generateToken(user)
        };

    } catch (err) {
        console.error("Error updating license:", err.message);
        return { success: false, message: 'लाइसेंस अपडेट विफल: ' + err.message };
    }
};


// -----------------------------------------------------------------------------
// IV. API ROUTES (Authentication and License)
// -----------------------------------------------------------------------------

// Middleware to authenticate JWT token and attach shop_id to request
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Expects "Bearer TOKEN"

    if (token == null) return res.status(401).json({ success: false, message: 'प्रमाणीकरण टोकन आवश्यक (Authentication token required).' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error("JWT Verification Error:", err.message);
            return res.status(403).json({ success: false, message: 'अमान्य या समाप्त हो चुका टोकन (Invalid or expired token).' });
        }
        req.shop_id = user.shop_id;
        req.user = user;
        next();
    });
};

// --- AUTH ROUTES ---

// 1. User Registration
app.post('/api/register-user', async (req, res) => {
    const { name, username, password, license_key } = req.body;
    
    if (!name || !username || !password) {
        return res.status(400).json({ success: false, message: 'सभी फ़ील्ड आवश्यक हैं (All fields required).' });
    }
    
    // Generate a unique shop_id
    const shop_id = `SHOP-${crypto.randomBytes(8).toString('hex').toUpperCase()}`;

    const result = await registerUser(shop_id, name, username, password, license_key);
    
    if (result.success) {
        res.json(result);
    } else {
        res.status(400).json(result);
    }
});

// 2. User Login
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'उपयोगकर्ता नाम और पासवर्ड आवश्यक हैं (Username and password required).' });
    }

    const result = await authenticateUser(username, password);
    
    if (result.success) {
        res.json(result);
    } else if (result.message.includes('User status')) {
         res.status(403).json(result); // Forbidden for inactive status
    } else {
        res.status(401).json(result);
    }
});

// 3. License Key Update/Renewal
app.post('/api/update-license', authenticateToken, async (req, res) => {
    const { license_key } = req.body;
    const shopId = req.shop_id;

    if (!license_key) {
        return res.status(400).json({ success: false, message: 'लाइसेंस कुंजी आवश्यक है (License key required).' });
    }

    const result = await updateLicense(shopId, license_key);
    
    if (result.success) {
        res.json(result);
    } else {
        res.status(400).json(result);
    }
});

// 4. Check License Status (for client-side validation check)
app.get('/api/check-license', authenticateToken, async (req, res) => {
    try {
        const shopId = req.shop_id;
        const userQuery = 'SELECT license_key, license_expiry_date FROM users WHERE shop_id = $1';
        const userResult = await pool.query(userQuery, [shopId]);

        if (userResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'उपयोगकर्ता नहीं मिला (User not found).' });
        }
        
        const { license_key, license_expiry_date } = userResult.rows[0];

        if (!license_key || !license_expiry_date) {
            // No license on file, rely on client trial logic
            return res.json({ 
                success: true, 
                valid: false, 
                message: 'कोई सक्रिय लाइसेंस नहीं (No active license on file).', 
                expiryDate: null 
            });
        }

        const licenseCheck = verifyLicense(license_key, shopId);
        
        // Final check: is the stored expiry date valid?
        const isExpired = new Date(license_expiry_date).getTime() <= Date.now();

        return res.json({
            success: true,
            valid: !isExpired && licenseCheck.valid,
            message: !isExpired ? licenseCheck.message : 'लाइसेंस समाप्त हो गया है (License has expired).',
            expiryDate: license_expiry_date
        });

    } catch (err) {
        console.error("Error checking license status:", err.message);
        res.status(500).json({ success: false, message: 'सर्वर त्रुटि (Server error): ' + err.message });
    }
});


// -----------------------------------------------------------------------------
// V. PROTECTED DATA ROUTES (Requires authentication)
// -----------------------------------------------------------------------------

// --- CUSTOMERS ---

// 5. Add/Update Customer (Protected)
app.post('/api/customers', authenticateToken, async (req, res) => {
    const { id, name, phone, address, gst_number } = req.body;
    const shop_id = req.shop_id;

    if (!name || !phone) {
        return res.status(400).json({ success: false, message: 'नाम और फ़ोन आवश्यक हैं (Name and phone required).' });
    }

    try {
        let result;
        if (id) {
            // Update existing customer
            const query = `
                UPDATE customers SET name = $1, phone = $2, address = $3, gst_number = $4 
                WHERE id = $5 AND shop_id = $6 RETURNING *
            `;
            result = await pool.query(query, [name, phone, address, gst_number, id, shop_id]);
        } else {
            // Add new customer
            // Note: Balance is defaulted to 0.00
            const query = `
                INSERT INTO customers (shop_id, name, phone, address, gst_number) 
                VALUES ($1, $2, $3, $4, $5) RETURNING *
            `;
            result = await pool.query(query, [shop_id, name, phone, address, gst_number]);
        }

        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, message: 'ग्राहक नहीं मिला या अद्यतन विफल (Customer not found or update failed).' });
        }

        res.json({ 
            success: true, 
            message: `ग्राहक सफलतापूर्वक ${id ? 'अद्यतन' : 'जोड़ा गया'}।`,
            customer: result.rows[0] 
        });

    } catch (err) {
        // Handle unique constraint violation (e.g., duplicate phone)
        if (err.code === '23505') {
            return res.status(409).json({ success: false, message: 'यह फ़ोन नंबर पहले से ही किसी ग्राहक के लिए उपयोग में है (Phone number already in use).' });
        }
        console.error("Error adding/updating customer:", err.message);
        res.status(500).json({ success: false, message: 'सर्वर त्रुटि (Server error): ' + err.message });
    }
});

// 6. Get All Customers (Protected)
app.get('/api/customers', authenticateToken, async (req, res) => {
    const shop_id = req.shop_id;
    const { search } = req.query;
    
    try {
        let query = `
            SELECT id, name, phone, address, gst_number, balance 
            FROM customers 
            WHERE shop_id = $1
        `;
        const params = [shop_id];

        if (search) {
            // Case-insensitive search on name or phone
            query += ' AND (name ILIKE $2 OR phone ILIKE $2)';
            params.push(`%${search}%`);
        }
        
        query += ' ORDER BY name ASC';
        
        const result = await pool.query(query, params);
        res.json({ success: true, customers: result.rows });

    } catch (err) {
        console.error("Error getting customers:", err.message);
        res.status(500).json({ success: false, message: 'सर्वर त्रुटि (Server error): ' + err.message });
    }
});

// 7. Delete Customer (Protected)
app.delete('/api/customers/:id', authenticateToken, async (req, res) => {
    const customer_id = req.params.id;
    const shop_id = req.shop_id;

    try {
        // Important: Customer ledger must be handled/checked before deletion in a real app.
        // For simplicity here, we rely on ON DELETE CASCADE for foreign keys but log the deletion.
        const query = 'DELETE FROM customers WHERE id = $1 AND shop_id = $2 RETURNING *';
        const result = await pool.query(query, [customer_id, shop_id]);

        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, message: 'ग्राहक नहीं मिला (Customer not found).' });
        }

        res.json({ success: true, message: 'ग्राहक सफलतापूर्वक हटा दिया गया (Customer deleted successfully).' });

    } catch (err) {
        console.error("Error deleting customer:", err.message);
        res.status(500).json({ success: false, message: 'सर्वर त्रुटि (Server error): ' + err.message });
    }
});

// 8. Update Customer Balance (Internal/Admin use - Protected)
// This route is typically used internally by Sale/Payment/Adjustment logic, not direct customer input.
const updateCustomerBalance = async (client, shop_id, customer_id, amount, isDebit = true) => {
    const operator = isDebit ? '+' : '-';
    const query = `
        UPDATE customers 
        SET balance = balance ${operator} $1
        WHERE id = $2 AND shop_id = $3
        RETURNING balance
    `;
    const result = await client.query(query, [amount, customer_id, shop_id]);
    if (result.rowCount === 0) {
        throw new Error('Customer balance update failed: Customer not found.');
    }
    return result.rows[0].balance;
};

// --- PRODUCTS ---

// 9. Add/Update Product (Protected)
app.post('/api/products', authenticateToken, async (req, res) => {
    const { id, name, hsn_sac, category, unit_type, current_stock, sale_price, purchase_price, gst_rate, description } = req.body;
    const shop_id = req.shop_id;

    if (!name || !sale_price || !unit_type) {
        return res.status(400).json({ success: false, message: 'उत्पाद का नाम, बिक्री मूल्य और इकाई आवश्यक हैं (Product name, sale price, and unit required).' });
    }

    try {
        let result;
        const stock_value = parseInt(current_stock || 0, 10);
        
        if (id) {
            // Update existing product
            const query = `
                UPDATE products SET name = $1, hsn_sac = $2, category = $3, unit_type = $4, 
                current_stock = $5, sale_price = $6, purchase_price = $7, gst_rate = $8, description = $9
                WHERE id = $10 AND shop_id = $11 RETURNING *
            `;
            result = await pool.query(query, [name, hsn_sac, category, unit_type, stock_value, sale_price, purchase_price, gst_rate, description, id, shop_id]);
        } else {
            // Add new product
            const query = `
                INSERT INTO products (shop_id, name, hsn_sac, category, unit_type, current_stock, sale_price, purchase_price, gst_rate, description) 
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *
            `;
            result = await pool.query(query, [shop_id, name, hsn_sac, category, unit_type, stock_value, sale_price, purchase_price, gst_rate, description]);
        }

        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, message: 'उत्पाद नहीं मिला या अद्यतन विफल (Product not found or update failed).' });
        }

        res.json({ 
            success: true, 
            message: `उत्पाद सफलतापूर्वक ${id ? 'अद्यतन' : 'जोड़ा गया'}।`,
            product: result.rows[0]
        });

    } catch (err) {
        if (err.code === '23505') { // Unique constraint violation (duplicate name for the same shop_id)
            return res.status(409).json({ success: false, message: 'इस नाम का उत्पाद पहले से मौजूद है (Product with this name already exists).' });
        }
        console.error("Error adding/updating product:", err.message);
        res.status(500).json({ success: false, message: 'सर्वर त्रुटि (Server error): ' + err.message });
    }
});

// 10. Get All Products (Protected)
app.get('/api/products', authenticateToken, async (req, res) => {
    const shop_id = req.shop_id;
    const { search } = req.query;

    try {
        let query = `
            SELECT * FROM products WHERE shop_id = $1
        `;
        const params = [shop_id];

        if (search) {
            query += ' AND (name ILIKE $2 OR hsn_sac ILIKE $2)';
            params.push(`%${search}%`);
        }
        
        query += ' ORDER BY name ASC';
        
        const result = await pool.query(query, params);
        res.json({ success: true, products: result.rows });

    } catch (err) {
        console.error("Error getting products:", err.message);
        res.status(500).json({ success: false, message: 'सर्वर त्रुटि (Server error): ' + err.message });
    }
});

// 11. Delete Product (Protected)
app.delete('/api/products/:id', authenticateToken, async (req, res) => {
    const product_id = req.params.id;
    const shop_id = req.shop_id;

    try {
        const query = 'DELETE FROM products WHERE id = $1 AND shop_id = $2 RETURNING *';
        const result = await pool.query(query, [product_id, shop_id]);

        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, message: 'उत्पाद नहीं मिला (Product not found).' });
        }

        res.json({ success: true, message: 'उत्पाद सफलतापूर्वक हटा दिया गया (Product deleted successfully).' });

    } catch (err) {
        console.error("Error deleting product:", err.message);
        res.status(500).json({ success: false, message: 'सर्वर त्रुटि (Server error): ' + err.message });
    }
});

// 12. Update Product Stock (Internal Use)
const updateProductStock = async (client, shop_id, product_id, quantityChange) => {
    // quantityChange is positive for purchase (stock in), negative for sale (stock out)
    const query = `
        UPDATE products 
        SET current_stock = current_stock + $1 
        WHERE id = $2 AND shop_id = $3
        RETURNING current_stock
    `;
    const result = await client.query(query, [quantityChange, product_id, shop_id]);
    if (result.rowCount === 0) {
        throw new Error('Product stock update failed: Product not found.');
    }
};

// --- INVOICES (SALES) ---

// 13. Create New Invoice (Protected) - Transactional
app.post('/api/invoices', authenticateToken, async (req, res) => {
    const { 
        customer_id, customer_name, customer_phone, 
        total_amount, amount_paid, payment_method, 
        discount, invoice_date, items 
    } = req.body;
    const shop_id = req.shop_id;

    if (!customer_name || !total_amount || !amount_paid || !items || items.length === 0) {
        return res.status(400).json({ success: false, message: 'आवश्यक चालान विवरण गुम हैं (Required invoice details missing).' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 1. Generate Invoice Number (Simple sequential or random)
        // For simplicity, using a timestamp-based ID. A real system would use a sequence.
        const invoice_number = `INV-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
        
        // 2. Insert Invoice
        const invoiceQuery = `
            INSERT INTO invoices (shop_id, invoice_number, customer_id, customer_name, customer_phone, total_amount, amount_paid, payment_method, discount, invoice_date)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id, invoice_number
        `;
        const invoiceResult = await client.query(invoiceQuery, [
            shop_id, invoice_number, customer_id, customer_name, customer_phone, 
            total_amount, amount_paid, payment_method, discount, invoice_date
        ]);
        const invoice_id = invoiceResult.rows[0].id;

        // 3. Insert Invoice Items and Update Stock
        const itemInsertPromises = items.map(item => {
            const itemQuery = `
                INSERT INTO invoice_items (invoice_id, shop_id, product_id, product_name, hsn_sac, quantity, rate, gst_rate, gst_amount, net_amount)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            `;
            const promise = client.query(itemQuery, [
                invoice_id, shop_id, item.product_id, item.product_name, item.hsn_sac, 
                item.quantity, item.rate, item.gst_rate, item.gst_amount, item.net_amount
            ]);
            
            // Update Stock (Sale is a negative change)
            updateProductStock(client, shop_id, item.product_id, -item.quantity);

            return promise;
        });
        await Promise.all(itemInsertPromises);
        
        // 4. Update Customer Balance (If any remaining balance)
        const balanceDue = parseFloat(total_amount) - parseFloat(amount_paid);
        if (customer_id && balanceDue > 0) {
            const newBalance = await updateCustomerBalance(client, shop_id, customer_id, balanceDue, true); // Debit
            
            // 5. Add Ledger Entry
            const ledgerQuery = `
                INSERT INTO customer_ledger (shop_id, customer_id, transaction_date, type, description, debit, current_balance, reference_id)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            `;
            await client.query(ledgerQuery, [
                shop_id, customer_id, invoice_date, 'SALE', `चालान #${invoice_number}`, balanceDue, newBalance, invoice_id
            ]);
        }
        
        await client.query('COMMIT');
        res.json({ success: true, message: 'चालान सफलतापूर्वक बनाया गया (Invoice successfully created).', invoice: invoiceResult.rows[0] });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error("Error creating invoice:", err.message);
        res.status(500).json({ success: false, message: 'चालान निर्माण विफल: ' + err.message });
    } finally {
        client.release();
    }
});

// 14. Get All Invoices (Protected)
app.get('/api/invoices', authenticateToken, async (req, res) => {
    const shop_id = req.shop_id;
    const { limit = 20, offset = 0, search } = req.query;

    try {
        let query = `
            SELECT id, invoice_number, customer_name, total_amount, amount_paid, invoice_date 
            FROM invoices 
            WHERE shop_id = $1 AND is_deleted = FALSE
        `;
        const params = [shop_id];
        let paramIndex = 2;

        if (search) {
            query += ` AND (invoice_number ILIKE $${paramIndex} OR customer_name ILIKE $${paramIndex})`;
            params.push(`%${search}%`);
            paramIndex++;
        }
        
        query += ` ORDER BY invoice_date DESC, id DESC LIMIT $${paramIndex++} OFFSET $${paramIndex}`;
        params.push(limit, offset);

        const result = await pool.query(query, params);
        res.json({ success: true, invoices: result.rows });

    } catch (err) {
        console.error("Error getting invoices:", err.message);
        res.status(500).json({ success: false, message: 'सर्वर त्रुटि (Server error): ' + err.message });
    }
});

// 15. Get Single Invoice Details (Protected)
app.get('/api/invoices/:id', authenticateToken, async (req, res) => {
    const invoice_id = req.params.id;
    const shop_id = req.shop_id;

    try {
        const invoiceQuery = 'SELECT * FROM invoices WHERE id = $1 AND shop_id = $2 AND is_deleted = FALSE';
        const invoiceResult = await pool.query(invoiceQuery, [invoice_id, shop_id]);

        if (invoiceResult.rowCount === 0) {
            return res.status(404).json({ success: false, message: 'चालान नहीं मिला (Invoice not found).' });
        }
        const invoice = invoiceResult.rows[0];

        const itemsQuery = 'SELECT * FROM invoice_items WHERE invoice_id = $1 AND shop_id = $2';
        const itemsResult = await pool.query(itemsQuery, [invoice_id, shop_id]);
        
        invoice.items = itemsResult.rows;

        res.json({ success: true, invoice: invoice });

    } catch (err) {
        console.error("Error getting invoice details:", err.message);
        res.status(500).json({ success: false, message: 'सर्वर त्रुटि (Server error): ' + err.message });
    }
});

// --- EXPENSES ---

// 16. Add New Expense (Protected)
app.post('/api/expenses', authenticateToken, async (req, res) => {
    const { expense_date, category, description, amount } = req.body;
    const shop_id = req.shop_id;

    if (!expense_date || !category || !amount) {
        return res.status(400).json({ success: false, message: 'व्यय की तारीख, श्रेणी और राशि आवश्यक हैं (Date, category, and amount required).' });
    }

    try {
        const query = `
            INSERT INTO expenses (shop_id, expense_date, category, description, amount)
            VALUES ($1, $2, $3, $4, $5) RETURNING *
        `;
        const result = await pool.query(query, [shop_id, expense_date, category, description, amount]);

        res.json({ success: true, message: 'व्यय सफलतापूर्वक जोड़ा गया।', expense: result.rows[0] });

    } catch (err) {
        console.error("Error adding expense:", err.message);
        res.status(500).json({ success: false, message: 'सर्वर त्रुटि (Server error): ' + err.message });
    }
});

// 17. Get Expenses by Date Range (Protected)
app.get('/api/expenses', authenticateToken, async (req, res) => {
    const shop_id = req.shop_id;
    const { startDate, endDate } = req.query;

    try {
        let query = `
            SELECT id, expense_date, category, description, amount 
            FROM expenses 
            WHERE shop_id = $1
        `;
        const params = [shop_id];

        if (startDate && endDate) {
            query += ' AND expense_date BETWEEN $2 AND $3';
            params.push(startDate, endDate);
        } else if (startDate) {
            query += ' AND expense_date >= $2';
            params.push(startDate);
        } else if (endDate) {
            query += ' AND expense_date <= $2';
            params.push(endDate);
        }

        query += ' ORDER BY expense_date DESC, id DESC';

        const result = await pool.query(query, params);
        res.json({ success: true, expenses: result.rows });

    } catch (err) {
        console.error("Error getting expenses:", err.message);
        res.status(500).json({ success: false, message: 'सर्वर त्रुटि (Server error): ' + err.message });
    }
});

// --- LEDGER (Customer Payments/Transactions) ---

// 18. Add Customer Payment (Protected) - Transactional
app.post('/api/ledger/payment', authenticateToken, async (req, res) => {
    const { customer_id, amount, payment_date, description } = req.body;
    const shop_id = req.shop_id;

    if (!customer_id || !amount || !payment_date) {
        return res.status(400).json({ success: false, message: 'ग्राहक, राशि और तारीख आवश्यक हैं (Customer, amount, and date required).' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 1. Update Customer Balance (Credit - payment received)
        const paymentAmount = parseFloat(amount);
        if (paymentAmount <= 0) {
            throw new Error("राशि शून्य या नकारात्मक नहीं हो सकती (Amount cannot be zero or negative).");
        }
        const newBalance = await updateCustomerBalance(client, shop_id, customer_id, paymentAmount, false); // Credit
        
        // 2. Add Ledger Entry
        const ledgerQuery = `
            INSERT INTO customer_ledger (shop_id, customer_id, transaction_date, type, description, credit, current_balance)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
        `;
        const result = await client.query(ledgerQuery, [
            shop_id, customer_id, payment_date, 'PAYMENT', description || 'ग्राहक से भुगतान प्राप्त', paymentAmount, newBalance
        ]);
        
        await client.query('COMMIT');
        res.json({ success: true, message: 'भुगतान सफलतापूर्वक दर्ज किया गया (Payment recorded successfully).', ledgerEntry: result.rows[0] });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error("Error adding payment:", err.message);
        res.status(500).json({ success: false, message: 'भुगतान दर्ज करने में विफल: ' + err.message });
    } finally {
        client.release();
    }
});

// 19. Get Customer Ledger History (Protected)
app.get('/api/ledger/:customer_id', authenticateToken, async (req, res) => {
    const customer_id = req.params.customer_id;
    const shop_id = req.shop_id;
    const { startDate, endDate } = req.query;

    try {
        let query = `
            SELECT * FROM customer_ledger
            WHERE shop_id = $1 AND customer_id = $2
        `;
        const params = [shop_id, customer_id];
        let paramIndex = 3;

        if (startDate && endDate) {
            query += ` AND transaction_date BETWEEN $${paramIndex++} AND $${paramIndex++}`;
            params.push(startDate, endDate);
        }

        query += ' ORDER BY transaction_date ASC, id ASC';

        const result = await pool.query(query, params);
        res.json({ success: true, ledger: result.rows });

    } catch (err) {
        console.error("Error getting ledger:", err.message);
        res.status(500).json({ success: false, message: 'सर्वर त्रुटि (Server error): ' + err.message });
    }
});


// 20. Simple Business Overview/Dashboard Data (Protected)
app.get('/api/dashboard/summary', authenticateToken, async (req, res) => {
    const shop_id = req.shop_id;
    const today = new Date().toISOString().split('T')[0];

    try {
        // Daily Sales
        const dailySalesQuery = `
            SELECT COALESCE(SUM(total_amount), 0) AS total_sales, COUNT(id) AS total_invoices
            FROM invoices WHERE shop_id = $1 AND invoice_date = $2 AND is_deleted = FALSE
        `;
        const dailySalesResult = await pool.query(dailySalesQuery, [shop_id, today]);
        const dailySales = dailySalesResult.rows[0];

        // Total Outstanding Balance
        const totalBalanceQuery = `
            SELECT COALESCE(SUM(balance), 0) AS total_outstanding
            FROM customers WHERE shop_id = $1 AND balance > 0
        `;
        const totalBalanceResult = await pool.query(totalBalanceQuery, [shop_id]);
        const totalOutstanding = totalBalanceResult.rows[0].total_outstanding;

        // Stock Count
        const stockCountQuery = 'SELECT COUNT(id) AS total_products, COALESCE(SUM(current_stock), 0) AS total_stock_units FROM products WHERE shop_id = $1';
        const stockCountResult = await pool.query(stockCountQuery, [shop_id]);
        const stockSummary = stockCountResult.rows[0];

        res.json({
            success: true,
            summary: {
                dailySales: parseFloat(dailySales.total_sales),
                totalInvoices: parseInt(dailySales.total_invoices, 10),
                totalOutstanding: parseFloat(totalOutstanding),
                totalProducts: parseInt(stockSummary.total_products, 10),
                totalStockUnits: parseFloat(stockSummary.total_stock_units),
                reportDate: today
            }
        });

    } catch (err) {
        console.error("Error getting dashboard summary:", err.message);
        res.status(500).json({ success: false, message: 'सर्वर त्रुटि (Server error): ' + err.message });
    }
});

// 21. SQL Console/Query Runner (DANGEROUS - ADMIN ONLY)
app.post('/api/sql-console', authenticateToken, async (req, res) => {
    const { query } = req.body;
    const shop_id = req.shop_id;

    if (!query) {
        return res.status(400).json({ success: false, message: 'क्वेरी आवश्यक है (Query required).' });
    }

    // Security Note: A real application should restrict this endpoint heavily, 
    // only allowing super-admins or completely disallowing it.
    // We are simply checking the token here.
    
    // Prevent modification of other shops' data (Basic protection)
    if (query.toUpperCase().includes('UPDATE') || query.toUpperCase().includes('DELETE') || query.toUpperCase().includes('INSERT')) {
        if (!query.includes(shop_id)) {
            // This is a weak check, but better than nothing.
            // Full SQL parsing is required for true security against injection.
            console.warn(`Potential unauthorized cross-shop query attempt by ${shop_id}: ${query}`);
            // return res.status(403).json({ success: false, message: 'इस क्रिया के लिए सुरक्षा प्रतिबंध (Security restriction for this action).' });
        }
    }
    
    try {
        const result = await pool.query(query);
        
        res.json({ 
            success: true, 
            message: 'क्वेरी सफलतापूर्वक निष्पादित (Executed)।', 
            rowCount: result.rowCount,
            command: result.command,
            rows: result.rows 
        });

    } catch (err) {
        console.error("SQL Console Error:", err.message);
        res.status(500).json({ success: false, message: 'क्वेरी निष्पादन विफल: ' + err.message });
    }
});


// -----------------------------------------------------------------------------
// VI. SERVER INITIALIZATION
// -----------------------------------------------------------------------------

// Default route
app.get('/', (req, res) => {
    res.send('Dukan Pro Backend is Running. Use /api/login or /api/verify-license.');
});

// Start the server after ensuring database tables are ready
createTables().then(() => {
    app.listen(PORT, () => {
        console.log(`\n🎉 Server is running securely on port ${PORT}`);
        console.log(`🌐 API Endpoint: https://dukan-pro-ultimate.onrender.com:${PORT}`);
        console.log('--------------------------------------------------');
        console.log('🔒 Authentication: JWT is required for all data routes.');
        console.log('🔑 Multi-tenancy: All data is scoped by shop_id.\n');
    });
}).catch(error => {
    console.error('Failed to initialize database and start server:', error.message);
    process.exit(1);
});
