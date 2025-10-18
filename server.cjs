// server.cjs (Dukan Pro - Ultimate Backend) - MULTI-USER/SECURE VERSION (1150+ LINES)
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
const SECRET_KEY = process.env.SECRET_KEY ||
'a_very_strong_secret_key_for_hashing'; // Must be secure!
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
// Stronger JWT Secret

// --- Encryption Constants (Retained for license key hashing) ---
const ENCRYPTION_KEY = crypto.createHash('sha256').update(SECRET_KEY).digest();
const SALT_ROUNDS = 10;
// 🔒 Bcrypt salt rounds for password hashing

// --- Middlewares ---
app.use(cors({
    origin: '*', // सभी ऑरिजिन को अनुमति दें (डिबगिंग के लिए)
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// --- Database Setup ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});
// -----------------------------------------------------------------------------
// I. DATABASE SCHEMA CREATION AND UTILITIES
// -----------------------------------------------------------------------------

/**
 * Ensures all necessary tables and columns exist in the PostgreSQL database.
 * NOTE: All data tables now include 'shop_id' for multi-tenancy.
 */
async function createTables() {
    const client = await pool.connect();
    try {
        console.log('Attempting to ensure all tables and columns exist...');

        // 0. Shops / Tenant Table (Stores shop information)
        await client.query('CREATE TABLE IF NOT EXISTS shops (id SERIAL PRIMARY KEY, shop_name TEXT NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);');

        // 0.5. Users Table (Stores login credentials and roles, linked to a shop)
        // 🌟 FIX: Added 'status' column to users table
        await client.query('CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, name TEXT NOT NULL, role TEXT DEFAULT \'CASHIER\' CHECK (role IN (\'ADMIN\', \'MANAGER\', \'CASHIER\')), status TEXT DEFAULT \'pending\' CHECK (status IN (\'active\', \'pending\', \'disabled\')), created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);');
        
        // 🛑 NEW: Add license_expiry_date column to users table
        await client.query(`
            DO $$ BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = (SELECT oid FROM pg_class WHERE relname = 'users') AND attname = 'license_expiry_date') THEN
                    ALTER TABLE users ADD COLUMN license_expiry_date TIMESTAMP WITH TIME ZONE DEFAULT NULL;
                END IF;
            END $$;
        `);
        // END NEW 🛑

        // 1. Licenses Table (Global, checked before registration)
        await client.query('CREATE TABLE IF NOT EXISTS licenses (key_hash TEXT PRIMARY KEY, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, expiry_date TIMESTAMP WITH TIME ZONE, is_trial BOOLEAN DEFAULT FALSE);');

        // --- Multi-tenant modification: Add shop_id to all data tables ---
        const dataTables = ['stock', 'customers', 'invoices', 'invoice_items', 'purchases', 'expenses'];
        for (const table of dataTables) {
            // Safely add shop_id column if it doesn't exist
            await client.query(`
                DO $$ BEGIN
                    IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = (SELECT oid FROM pg_class WHERE relname = '${table}') AND attname = 'shop_id') THEN
                        ALTER TABLE ${table} ADD COLUMN shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE;
                        CREATE INDEX IF NOT EXISTS idx_${table}_shop_id ON ${table} (shop_id);
                    END IF;
                END $$;
            `);
        }

        // 2. Stock Table (Now scoped by shop_id)
        await client.query('CREATE TABLE IF NOT EXISTS stock (id SERIAL PRIMARY KEY, shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE, sku TEXT NOT NULL, name TEXT NOT NULL, quantity NUMERIC NOT NULL, unit TEXT, purchase_price NUMERIC NOT NULL, sale_price NUMERIC NOT NULL, cost_price NUMERIC, category TEXT, gst NUMERIC DEFAULT 0, updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, UNIQUE (shop_id, sku));');
        // 3. Customers Table
        await client.query('CREATE TABLE IF NOT EXISTS customers (id SERIAL PRIMARY KEY, shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE, name TEXT NOT NULL, phone TEXT, email TEXT, address TEXT, balance NUMERIC DEFAULT 0, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);');
        // 4. Invoices/Sales Table
        await client.query('CREATE TABLE IF NOT EXISTS invoices (id SERIAL PRIMARY KEY, shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE, customer_id INTEGER REFERENCES customers(id) ON DELETE SET NULL, total_amount NUMERIC NOT NULL, total_cost NUMERIC DEFAULT 0, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);');
        // 5. Invoice Items (Items sold in a sale)
        await client.query('CREATE TABLE IF NOT EXISTS invoice_items (id SERIAL PRIMARY KEY, invoice_id INTEGER REFERENCES invoices(id) ON DELETE CASCADE, item_name TEXT NOT NULL, item_sku TEXT NOT NULL, quantity NUMERIC NOT NULL, sale_price NUMERIC NOT NULL, purchase_price NUMERIC);');
        // 6. Purchases Table (Stock Inflow)
        await client.query('CREATE TABLE IF NOT EXISTS purchases (id SERIAL PRIMARY KEY, shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE, supplier_name TEXT NOT NULL, item_details TEXT, total_cost NUMERIC NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);');
        // 7. Expenses Table
        await client.query('CREATE TABLE IF NOT EXISTS expenses (id SERIAL PRIMARY KEY, shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE, description TEXT NOT NULL, category TEXT, amount NUMERIC NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);');
        console.log('✅ All tables and columns (including shop_id) checked/created successfully.');

    } catch (err) {
        console.error('❌ Error ensuring database schema:', err.message);
        process.exit(1);
    } finally {
        client.release();
    }
}

// --- License Utilities ---
function hashKey(key) {
    return crypto.createHash('sha256').update(key).digest('hex');
}

// --- Auth Utilities ---
async function hashPassword(password) {
    return await bcrypt.hash(password, SALT_ROUNDS);
}

function generateToken(user) {
    // 🔑 Token includes user ID, email, shopId, and role for security and multi-tenancy
    return jwt.sign(
        { id: user.id, email: user.email, shopId: user.shop_id, role: user.role, status: user.status }, // 🌟 FIX: Added status to token
        JWT_SECRET,
        { expiresIn: '30d' } // Token valid for 30 days for better UX
    );
}

// -----------------------------------------------------------------------------
// II. MIDDLEWARES (AUTHENTICATION & AUTHORIZATION)
// -----------------------------------------------------------------------------

/**
 * Middleware to verify JWT and attach user/shop information to the request.
 * All protected routes must use this first.
 */
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const token = authHeader.split(' ')[1]; // Expects 'Bearer <token>'

        jwt.verify(token, JWT_SECRET, (err, user) => {
            if (err) {
                console.warn('JWT Verification Failed:', err.message);
                return res.status(403).json({ success: false, message: 'अमान्य या समाप्त टोकन। कृपया पुनः लॉगिन करें।' });
            }
          
            // Attach user info and shop_id to the request object
            req.user = user;
            req.shopId = user.shopId; // Crucial for multi-tenancy scoping
            req.userRole = user.role;
            next();
        });
    } else {
        // No token provided
        res.status(401).json({ success: false, message: 'अनधिकृत पहुँच। प्रमाणीकरण आवश्यक है।' });
    }
};

/**
 * Middleware for Role-Based Access Control (RBAC).
 * Role hierarchy: ADMIN (3) > MANAGER (2) > CASHIER (1)
 */
const checkRole = (requiredRole) => (req, res, next) => {
    const roles = { 'ADMIN': 3, 'MANAGER': 2, 'CASHIER': 1 };
    const userRoleValue = roles[req.userRole];
    const requiredRoleValue = roles[requiredRole.toUpperCase()];

    if (userRoleValue >= requiredRoleValue) {
        next(); // Authorized
    } else {
        res.status(403).json({ success: false, message: 'इस कार्य को करने के लिए पर्याप्त अनुमतियाँ नहीं हैं। (आवश्यक: ' + requiredRole + ')' });
    }
};

// -----------------------------------------------------------------------------
// III. AUTHENTICATION AND LICENSE ROUTES (PUBLIC/SETUP)
// -----------------------------------------------------------------------------

// 🌟 FIX: This route is now /api/admin/generate-key and uses GLOBAL_ADMIN_PASSWORD
// 1. License Key Generation (Now accessible by global ADMIN password)
app.post('/api/admin/generate-key', async (req, res) => {
    const { adminPassword, days, customerName, customerMobile } = req.body; // customer info is optional

    // 1. Check Global Admin Password
    if (!process.env.GLOBAL_ADMIN_PASSWORD) {
        return res.status(500).json({ success: false, message: 'सर्वर पर GLOBAL_ADMIN_PASSWORD सेट नहीं है।' });
    }
    if (adminPassword !== process.env.GLOBAL_ADMIN_PASSWORD) {
        return res.status(401).json({ success: false, message: 'अमान्य एडमिन पासवर्ड।' });
    }

    // 2. Validate Days
    if (typeof days !== 'number' || days < 1) {
        return res.status(400).json({ success: false, message: 'दिनों की संख्या मान्य होनी चाहिए।' });
    }

    // 3. Generate Key
    const rawKey = `DUKANPRO-${crypto.randomBytes(16).toString('hex').toUpperCase()}`;
    const keyHash = hashKey(rawKey);
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + days);

    try {
        await pool.query(
            'INSERT INTO licenses (key_hash, expiry_date, is_trial) VALUES ($1, $2, $3)',
            [keyHash, expiryDate, days === 5]
        );
        res.json({ 
            success: true, 
            key: rawKey, 
            message: 'लाइसेंस कुंजी सफलतापूर्वक बनाई गई।',
            duration_days: days,
            valid_until: expiryDate.toISOString(),
            customer: customerName || 'N/A' // Return customer name for confirmation
        });
    } catch (err) {
        console.error("Error generating key:", err.message);
        if (err.constraint === 'licenses_pkey') {
            return res.status(500).json({ success: false, message: 'कुंजी बनाने में विफल: डुप्लिकेट कुंजी। कृपया पुनः प्रयास करें।' });
        }
        res.status(500).json({ success: false, message: 'कुंजी बनाने में विफल: डेटाबेस त्रुटि।' });
    }
});
// 2. Verify License Key (Used before login/registration, still public)
app.get('/api/verify-license', async (req, res) => {
    const rawKey = req.query.key;
    if (!rawKey) {
        return res.status(400).json({ success: false, message: 'कुंजी आवश्यक है।' });
    }

    const keyHash = hashKey(rawKey);

    try {
        const result = await pool.query('SELECT expiry_date, is_trial FROM licenses WHERE key_hash = $1', [keyHash]);
        
        if (result.rows.length === 0) {
            return res.json({ success: false, valid: false, message: 'अमान्य लाइसेंस कुंजी।' });
        }

        const license = result.rows[0];
        const expiryDate = new Date(license.expiry_date);
        const now = new Date();
        const isValid = expiryDate > now;

        if (isValid) {
            return res.json({
                success: true,
                valid: true,
                isTrial: license.is_trial,
                message: 'लाइसेंस सत्यापित और सक्रिय है।',
                expiryDate: expiryDate.toISOString()
            });
        } else {
            return res.json({ success: false, valid: false, message: 'लाइसेंस की समय सीमा समाप्त हो गई है।' });
        }
    } catch (err) {
        console.error("Error verifying license:", err.message);
        res.status(500).json({ success: false, message: 'सत्यापन विफल: सर्वर त्रुटि।' });
    }
});
// 3. User Registration (Creates a new shop and the first ADMIN user)
app.post('/api/register', async (req, res) => {
    const { shopName, name, email, password } = req.body;
    
    // इनपुट सत्यापन (Input Validation)
    if (!shopName || !name || !email || !password) {
        return res.status(400).json({ success: false, message: 'सभी फ़ील्ड (शॉप का नाम, आपका नाम, ईमेल, पासवर्ड) आवश्यक हैं।' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN'); // लेन-देन शुरू करें (Start Transaction)

        // 1. ईमेल डुप्लीकेसी की जाँच करें (Check for Email Duplicacy FIRST)
        const existingUser = await client.query('SELECT id FROM users WHERE email = $1', [email]);
        if (existingUser.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(409).json({ success: false, message: 'यह ईमेल पहले से पंजीकृत है। कृपया लॉगिन करें।' });
        }

        // 2. नई शॉप/टेनेंट बनाएं
        const shopResult = await client.query(
            'INSERT INTO shops (shop_name) VALUES ($1) RETURNING id',
            [shopName]
        );
        const shopId = shopResult.rows[0].id; // `shops` टेबल में ID को 'id' कहा गया है।
        
        // 3. पासवर्ड को हैश करें
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        
        // 4. पहले उपयोगकर्ता (मालिक/एडमिन) को बनाएं
        // 🚀 **सुधार: status कॉलम को 'active' पर सेट करें**
        const userInsertQuery = `
            INSERT INTO users (shop_id, email, password_hash, name, role, status) 
            VALUES ($1, $2, $3, $4, $5, 'active') 
            RETURNING id, shop_id, email, name, role, status
        `;
        const userResult = await client.query(userInsertQuery, [shopId, email, hashedPassword, name, 'ADMIN']);
        const user = userResult.rows[0];
        
        // 5. JWT टोकन जनरेट करें 
        const tokenUser = { 
            id: user.id, 
            email: user.email, 
            shopId: user.shop_id, 
            name: user.name, 
            role: user.role, 
            shopName: shopName, // ShopName जोड़ना
            status: user.status 
        };
        const token = jwt.sign(tokenUser, JWT_SECRET, { expiresIn: '30d' });

        await client.query('COMMIT'); // लेन-देन पूरा करें
        
        res.json({ 
            success: true, 
            message: 'शॉप और एडमिन अकाउंट सफलतापूर्वक बनाया गया।',
            token: token,
            user: tokenUser
        });
    } catch (err) {
        await client.query('ROLLBACK'); // गलती होने पर रोलबैक करें
        console.error("Error registering user/shop:", err.message);
        // यदि कोई अन्य constraint त्रुटि होती है
        if (err.constraint) {
             return res.status(500).json({ success: false, message: 'रजिस्ट्रेशन विफल: डेटाबेस त्रुटि (' + err.constraint + ')' });
        }
        res.status(500).json({ success: false, message: 'रजिस्ट्रेशन विफल: ' + err.message });
    } finally {
        client.release();
    }
});

// 4. User Login (Authenticates and returns JWT)
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    // इनपुट सत्यापन
    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'ईमेल और पासवर्ड आवश्यक हैं।' });
    }

    try {
        // 🔑 Query now fetches all user columns, including license_expiry_date
        const result = await pool.query(
            'SELECT u.*, s.shop_name FROM users u JOIN shops s ON u.shop_id = s.id WHERE u.email = $1', 
            [email]
        );
        
        if (result.rows.length === 0) {
            console.log(`DEBUG LOGIN: User not found for email: ${email}`); 
            return res.status(401).json({ success: false, message: 'अमान्य ईमेल या पासवर्ड।' });
        }

        let user = result.rows[0];
        
        // 1. पासवर्ड की तुलना करें (Bcrypt)
        const isMatch = await bcrypt.compare(password, user.password_hash);
        console.log(`DEBUG LOGIN: Password Match? ${isMatch}`); 

        if (!isMatch) {
            return res.status(401).json({ success: false, message: 'अमान्य ईमेल या पासवर्ड।' });
        }

        // 2. खाता सक्रियण (Auto-Activate on Password Match)
        // चूंकि आपको DB एक्सेस नहीं है, इसलिए हम पासवर्ड सही होने पर 'pending' को 'active' पर सेट करते हैं।
        if (user.status !== 'active') {
             await pool.query(
                'UPDATE users SET status = $1 WHERE id = $2',
                ['active', user.id]
             );
             user.status = 'active'; // In-memory update
             console.log('DEBUG LOGIN: User status set to active (Auto-Activate).');
        }

        // 🛑 3. लाइसेंस की जाँच (License Check)
        const expiryDate = user.license_expiry_date ? new Date(user.license_expiry_date) : null;
        const currentDate = new Date();
        currentDate.setHours(0, 0, 0, 0); 
        
        // यदि समाप्ति तिथि NULL है OR यदि समाप्ति तिथि आज की तारीख से पहले की है (समाप्त हो गई है)
        if (!expiryDate || expiryDate < currentDate) {
             console.log('DEBUG LOGIN: License is missing or expired. Requires key.');
             
             // फ्रंटएंड को संकेत दें कि उसे लाइसेंस मॉडाल दिखाना चाहिए
             return res.status(403).json({ 
                 success: false, 
                 message: 'आपका खाता सक्रिय है, लेकिन लाइसेंस समाप्त हो गया है। कृपया लाइसेंस कुंजी दर्ज करें।',
                 requiresLicense: true 
             });
        }
        
        // 4. सफल लॉगिन (यदि लाइसेंस मान्य है)
        const tokenUser = { 
            id: user.id, 
            email: user.email, 
            shopId: user.shop_id, 
            name: user.name, 
            role: user.role, 
            shopName: user.shop_name,
            licenseExpiryDate: user.license_expiry_date, // NEW: Include expiry date
            status: user.status 
        };
        const token = jwt.sign(tokenUser, JWT_SECRET, { expiresIn: '30d' });
        
        res.json({ 
            success: true, 
            message: 'लॉगिन सफल।',
            token: token,
            user: tokenUser
        });
    } catch (err) {
        console.error("Error logging in:", err.message);
        res.status(500).json({ success: false, message: 'लॉगिन विफल: ' + err.message });
    }
});

// 5. License Activation Route (Securely update license expiry)
// 🔑 Note: This route is protected and requires a valid JWT 
app.post('/api/activate-license', authenticateJWT, async (req, res) => {
    // authenticateJWT मिडलवेयर से req.user प्राप्त करें
    const { licenseKey } = req.body;
    const userId = req.user.id; 

    if (!licenseKey) {
        return res.status(400).json({ success: false, message: 'लाइसेंस कुंजी आवश्यक है।' });
    }
    
    // 💡 यह डमी लाइसेंस कुंजी जाँच है
    let daysToAdd = 0;
    
    if (licenseKey === '5D-TRIAL-KEY') {
        daysToAdd = 5;
    } else if (licenseKey === '30D-MONTHLY-KEY') {
        daysToAdd = 30;
    } else if (licenseKey === '182D-HALFYR-KEY') {
        daysToAdd = 182;
    } else if (licenseKey === '365D-YEARLY-KEY') {
        daysToAdd = 365;
    } else {
        return res.status(400).json({ success: false, message: 'अमान्य लाइसेंस कुंजी।' });
    }
    
    try {
        // वर्तमान लाइसेंस समाप्ति तिथि (यदि कोई है) प्राप्त करें
        const currentLicenseResult = await pool.query(
            'SELECT license_expiry_date FROM users WHERE id = $1',
            [userId]
        );
        
        const currentExpiryDate = currentLicenseResult.rows[0].license_expiry_date 
                              ? new Date(currentLicenseResult.rows[0].license_expiry_date) 
                              : new Date();
        
        // यदि वर्तमान समाप्ति तिथि आज से पहले की है, तो आज से शुरू करें; अन्यथा, वर्तमान समाप्ति तिथि से जोड़ें।
        const currentDate = new Date();
        currentDate.setHours(0, 0, 0, 0); 
        
        const startDate = (currentExpiryDate > currentDate) ? currentExpiryDate : currentDate;
        
        // नई समाप्ति तिथि की गणना करें
        const newExpiryDate = new Date(startDate);
        newExpiryDate.setDate(newExpiryDate.getDate() + daysToAdd);
        
        // DB को अपडेट करें
        await pool.query(
            'UPDATE users SET license_expiry_date = $1 WHERE id = $2',
            [newExpiryDate, userId]
        );
        
        // अपडेटेड यूज़र डेटा (शॉप का नाम सहित) को फिर से फ़ेच करें
        const updatedUserResult = await pool.query(
            'SELECT u.*, s.shop_name FROM users u JOIN shops s ON u.shop_id = s.id WHERE u.id = $1', 
            [userId]
        );
        
        const updatedUser = updatedUserResult.rows[0];
        
        // नए लाइसेंस की अवधि के साथ JWT टोकन जनरेट करें और वापस भेजें
        const tokenUser = { 
            id: updatedUser.id, 
            email: updatedUser.email, 
            shopId: updatedUser.shop_id, 
            name: updatedUser.name, 
            role: updatedUser.role, 
            shopName: updatedUser.shop_name,
            licenseExpiryDate: updatedUser.license_expiry_date,
            status: updatedUser.status 
        };
        const token = jwt.sign(tokenUser, JWT_SECRET, { expiresIn: '30d' });

        res.json({
            success: true,
            message: `लाइसेंस ${daysToAdd} दिनों के लिए सफलतापूर्वक सक्रिय हो गया है।`,
            token: token,
            user: tokenUser
        });

    } catch (err) {
        console.error("License Activation Error:", err.message);
        res.status(500).json({ success: false, message: 'लाइसेंस सक्रियण विफल: ' + err.message });
    }
});

// -----------------------------------------------------------------------------
// IV. MULTI-TENANT SHOP DATA ROUTES (PROTECTED & SCOPED)
// -----------------------------------------------------------------------------

// --- 6. User Management (Shop Admin Only) ---

// 6.1 Add New User to the Current Shop
app.post('/api/users', authenticateJWT, checkRole('ADMIN'), async (req, res) => { 
    // 🌟 FIX: Added 'status' field
    const { name, email, password, role = 'CASHIER', status = 'pending' } = req.body;
    const shopId = req.shopId;
    
    if (!name || !email || !password || !['ADMIN', 'MANAGER', 'CASHIER'].includes(role.toUpperCase())) {
        return res.status(400).json({ success: false, message: 'मान्य नाम, ईमेल, पासवर्ड और रोल आवश्यक है।' });
    }
    
   try {
        const hashedPassword = await hashPassword(password);
        const result = await pool.query(
            'INSERT INTO users (shop_id, name, email, password_hash, role, status) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, email, role, status',
            [shopId, name, email, hashedPassword, role.toUpperCase(), status]
        );
        res.json({ success: true, user: result.rows[0], message: 'यूजर सफलतापूर्वक जोड़ा गया।' });
    } catch (err) {
        if (err.constraint === 'users_email_key') {
            return res.status(409).json({ success: false, message: 'यह ईमेल आपकी शॉप में पहले से उपयोग में है।' });
        }
        console.error("Error adding user:", err.message);
        res.status(500).json({ success: false, message: 'यूजर जोड़ने में विफल: ' + err.message });
    }
});
// 6.2 Get All Users for the Current Shop
app.get('/api/users', authenticateJWT, checkRole('MANAGER'), async (req, res) => { // Manager can view staff
    const shopId = req.shopId;
    try {
        // 🌟 FIX: Added 'status' to SELECT
        const result = await pool.query('SELECT id, name, email, role, status, created_at FROM users WHERE shop_id = $1 ORDER BY created_at ASC', [shopId]);
        res.json({ success: true, users: result.rows });
    } catch (err) {
        console.error("Error fetching users:", err.message);
        res.status(500).json({ success: false, message: 'यूजर सूची प्राप्त करने में विफल।' });
    }
});
// 6.3 Update User Role/Name/Status
app.put('/api/users/:userId', authenticateJWT, checkRole('ADMIN'), async (req, res) => {
    const { userId } = req.params;
    // 🌟 FIX: Added 'status'
    const { name, role, status } = req.body;
    const shopId = req.shopId;

    if (!name && !role && !status) {
        return res.status(400).json({ success: false, message: 'अपडेट करने के लिए कम से कम एक फ़ील्ड आवश्यक है।' });
    }

    // Prevents an Admin from locking themselves out
    if (parseInt(userId) === req.user.id) {
        return res.status(403).json({ success: false, message: 'आप अपनी खुद की भूमिका/नाम/स्थिति नहीं बदल सकते।' });
    }

    try {
        let updateParts = [];
        let queryParams = [shopId, userId];
        
        if (name) { updateParts.push(`name = $${queryParams.length + 1}`); queryParams.push(name); }
        if (role) { 
            const upperRole = role.toUpperCase();
            if (!['ADMIN', 'MANAGER', 'CASHIER'].includes(upperRole)) {
                return res.status(400).json({ success: false, message: 'अमान्य भूमिका।' });
            }
            updateParts.push(`role = $${queryParams.length + 1}`); 
            queryParams.push(upperRole);
        }
        // 🌟 FIX: Added status update logic
        if (status) { 
            const upperStatus = status.toLowerCase();
            if (!['active', 'pending', 'disabled'].includes(upperStatus)) {
                return res.status(400).json({ success: false, message: 'अमान्य स्थिति।' });
            }
            updateParts.push(`status = $${queryParams.length + 1}`); 
            queryParams.push(upperStatus);
        }

        if (updateParts.length === 0) {
             return res.status(200).json({ success: true, message: 'कोई बदलाव लागू नहीं किया गया।' });
        }

        // 🔑 Ensure update is scoped by shop_id and user ID
        const result = await pool.query(
            `UPDATE users SET ${updateParts.join(', ')} WHERE shop_id = $1 AND id = $2 RETURNING id, name, email, role, status`,
            queryParams
        );
        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, message: 'यूजर नहीं मिला या आपकी शॉप से संबंधित नहीं है।' });
        }
        
        res.json({ success: true, user: result.rows[0], message: 'यूजर सफलतापूर्वक अपडेट किया गया।' });
    } catch (err) {
        console.error("Error updating user:", err.message);
        res.status(500).json({ success: false, message: 'यूजर अपडेट करने में विफल: ' + err.message });
    }
});
// 6.4 Delete User from the Current Shop
app.delete('/api/users/:userId', authenticateJWT, checkRole('ADMIN'), async (req, res) => {
    const { userId } = req.params;
    const shopId = req.shopId;

    // Prevents an Admin from deleting themselves
    if (parseInt(userId) === req.user.id) {
        return res.status(403).json({ success: false, message: 'आप अपनी खुद की प्रोफाइल डिलीट नहीं कर सकते।' });
    }

    try {
        // 🔑 Ensure deletion is scoped by shop_id
        const result = await pool.query('DELETE FROM users WHERE shop_id = $1 AND id = $2', [shopId, userId]);

        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, message: 'यूजर नहीं मिला या आपकी शॉप से संबंधित नहीं है।' });
        }
        
        res.json({ success: true, message: 'यूजर सफलतापूर्वक डिलीट किया गया।' });
    } catch (err) {
        console.error("Error deleting user:", err.message);
        res.status(500).json({ success: false, message: 'यूजर डिलीट करने में विफल: ' + err.message });
    }
});


// --- 7. Stock Management ---

// 7.1 Stock Management - Add/Update (SCOPED & Transactional)
app.post('/api/stock', authenticateJWT, checkRole('MANAGER'), async (req, res) => { 
    const { sku, name, quantity, unit, purchase_price, sale_price, gst, cost_price, category } = req.body;
    const shopId = req.shopId; 

    if (!sku || !name || typeof quantity === 'undefined' || typeof purchase_price === 'undefined' || typeof sale_price === 'undefined') {
        return res.status(400).json({ success: false, message: 'SKU, नाम, मात्रा, खरीद मूल्य और बिक्री मूल्य आवश्यक हैं।' });
    }
   
    const safeQuantity = parseFloat(quantity);
    const safePurchasePrice = parseFloat(purchase_price);
    const safeSalePrice = parseFloat(sale_price);
    const safeGst = parseFloat(gst || 0);
    const safeCostPrice = parseFloat(cost_price || safePurchasePrice); 

    if (isNaN(safeQuantity) || isNaN(safePurchasePrice) || isNaN(safeSalePrice)) {
        return res.status(400).json({ success: false, message: 'मात्रा, खरीद मूल्य और बिक्री मूल्य मान्य संख्याएँ होनी चाहिए।' });
    }

    try {
        // 🔑 Query now includes shop_id in INSERT and WHERE clause for ON CONFLICT
        const result = await pool.query(
            `INSERT INTO stock (shop_id, sku, name, quantity, unit, purchase_price, sale_price, gst, cost_price, category) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) 
             ON CONFLICT (shop_id, sku) DO UPDATE 
             SET quantity = stock.quantity + EXCLUDED.quantity, 
                 name = EXCLUDED.name, 
                 purchase_price = EXCLUDED.purchase_price, 
                 sale_price = EXCLUDED.sale_price, 
                 gst = EXCLUDED.gst, 
                 cost_price = EXCLUDED.cost_price, 
                 category = EXCLUDED.category, 
                 updated_at = CURRENT_TIMESTAMP 
             WHERE stock.shop_id = EXCLUDED.shop_id RETURNING *;`,
            [shopId, sku, name, safeQuantity, unit, safePurchasePrice, safeSalePrice, safeGst, safeCostPrice, category]
        );
        res.json({ success: true, stock: result.rows[0], message: 'स्टॉक सफलतापूर्वक जोड़ा/अपडेट किया गया।' });
    } catch (err) {
        console.error("Error adding stock:", err.message);
        res.status(500).json({ success: false, message: 'स्टॉक जोड़ने में विफल: ' + err.message });
    }
});
// 7.2 Stock Management - Get All (SCOPED)
app.get('/api/stock', authenticateJWT, async (req, res) => { 
    const shopId = req.shopId; 
    try {
        // 🔑 Query now includes WHERE shop_id = $1
        const result = await pool.query('SELECT * FROM stock WHERE shop_id = $1 ORDER BY updated_at DESC', [shopId]);
        res.json({ success: true, stock: result.rows });
    } catch (err) {
        console.error("Error fetching stock:", err.message);
        res.status(500).json({ success: false, message: 'स्टॉक सूची प्राप्त करने में विफल।' });
    }
});
// 7.3 Stock Management - Search Items (SCOPED)
app.get('/api/search-items', authenticateJWT, async (req, res) => { 
    const query = req.query.query;
    const shopId = req.shopId; 
    
    if (!query || query.length < 2) {
        return res.json({ success: true, data: [] });
    }

    try {
        // 🔑 Query now includes WHERE shop_id = $2
        const result = await pool.query(
            'SELECT sku, name AS item_name, quantity, unit, sale_price, purchase_price, id FROM stock WHERE shop_id = $2 AND (name ILIKE $1 OR sku ILIKE $1) LIMIT 50', 
            [`%${query}%`, shopId]
        );
        res.json({ success: true, data: result.rows });
    } catch (err) {
        console.error("Error searching stock items:", err.message);
        res.status(500).json({ success: false, message: 'आइटम खोजने में विफल: ' + err.message });
    }
});
// 7.4 Stock Management - Get Single Item by SKU (SCOPED)
app.get('/api/get-stock-item/:sku', authenticateJWT, async (req, res) => { 
    const { sku } = req.params;
    const shopId = req.shopId;
    try {
        // 🔑 Query now includes WHERE shop_id = $2
        const result = await pool.query('SELECT name, sale_price, gst AS gst_rate, purchase_price, quantity FROM stock WHERE sku = $1 AND shop_id = $2', [sku, shopId]);
        if (result.rows.length > 0) {
            res.json({ success: true, data: result.rows[0] });
        } else {
            res.status(404).json({ success: false, message: 'SKU स्टॉक में नहीं मिला या आपकी शॉप से संबंधित नहीं है।' });
        }
    } catch (error) {
        console.error("Error fetching single stock item:", error.message);
        res.status(500).json({ success: false, message: 'स्टॉक आइटम प्राप्त करने में विफल।' });
    }
});
// 7.5 Stock Management - Delete Item (SCOPED)
app.delete('/api/stock/:sku', authenticateJWT, checkRole('ADMIN'), async (req, res) => { // Requires ADMIN/OWNER
    const { sku } = req.params;
    const shopId = req.shopId;
    try {
        // 🔑 Ensure deletion is scoped by shop_id and sku
        const result = await pool.query('DELETE FROM stock WHERE shop_id = $1 AND sku = $2', [shopId, sku]);
        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, message: 'स्टॉक आइटम नहीं मिला या आपकी शॉप से संबंधित नहीं है।' });
        }
        res.json({ success: true, message: `SKU ${sku} सफलतापूर्वक स्टॉक से डिलीट किया गया।` });
    } catch (err) {
        console.error("Error deleting stock:", err.message);
        res.status(500).json({ success: false, message: 'स्टॉक आइटम डिलीट करने में विफल: ' + err.message });
    }
});


// --- 8. Invoice/Sales Management ---

// 8.1 Process New Sale / Create Invoice (SCOPED & TRANSACTIONAL) - (Completed route 22)
app.post('/api/invoices', authenticateJWT, async (req, res) => {
    const { customerName, total_amount, sale_items } = req.body;
    const shopId = req.shopId;
    
    if (!total_amount || !Array.isArray(sale_items) || sale_items.length === 0) {
        return res.status(400).json({ success: false, message: 'कुल राशि और बिक्री आइटम आवश्यक हैं।' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN'); // Transaction Start

        let customerId = null;
        if (customerName && customerName.trim() !== 'अनाम ग्राहक') {
            // Check/Insert customer only within this shop_id
            const customerResult = await client.query('SELECT id FROM customers WHERE shop_id = $1 AND name = $2', [shopId, customerName.trim()]);
            if (customerResult.rows.length > 0) {
                customerId = customerResult.rows[0].id;
            } else {
                const newCustomerResult = await client.query('INSERT INTO customers (shop_id, name) VALUES ($1, $2) RETURNING id', [shopId, customerName.trim()]);
                customerId = newCustomerResult.rows[0].id;
            }
        }

        const safeTotalAmount = parseFloat(total_amount);
        let calculatedTotalCost = 0;

        // 🔑 Insert invoice with shop_id
        const invoiceResult = await client.query(
            `INSERT INTO invoices (shop_id, customer_id, total_amount) VALUES ($1, $2, $3) RETURNING id`,
            [shopId, customerId, safeTotalAmount]
        );
        const invoiceId = invoiceResult.rows[0].id;

        for (const item of sale_items) {
            const safeQuantity = parseFloat(item.quantity);
            const safePurchasePrice = parseFloat(item.purchase_price || 0);
            
            calculatedTotalCost += safeQuantity * safePurchasePrice;

            await client.query(
                `INSERT INTO invoice_items (invoice_id, item_name, item_sku, quantity, sale_price, purchase_price) VALUES ($1, $2, $3, $4, $5, $6)`,
                [invoiceId, item.name, item.sku, safeQuantity, parseFloat(item.sale_price), safePurchasePrice]
            );

            // 🔑 Update stock quantity only for the current shop_id
            await client.query(
                `UPDATE stock SET quantity = quantity - $1 WHERE sku = $2 AND shop_id = $3`,
                [safeQuantity, item.sku, shopId]
            );
        }

        // Update the invoice with the calculated total cost of goods sold (COGS)
        await client.query(
            `UPDATE invoices SET total_cost = $1 WHERE id = $2`,
            [calculatedTotalCost, invoiceId]
        );

        await client.query('COMMIT'); // Transaction End

        res.json({ success: true, invoiceId: invoiceId, message: 'बिक्री सफलतापूर्वक दर्ज की गई और स्टॉक अपडेट किया गया।' });
    } catch (err) {
        await client.query('ROLLBACK'); // Rollback on any error
        console.error("Error processing invoice:", err.message);
        res.status(500).json({ success: false, message: 'बिक्री विफल: ' + err.message });
    } finally {
        client.release();
    }
});
// 8.2 Get Invoices/Sales List (SCOPED)
app.get('/api/invoices', authenticateJWT, async (req, res) => {
    const shopId = req.shopId;
    try {
        // 🔑 Query now includes WHERE i.shop_id = $1
        const result = await pool.query("SELECT i.id, i.total_amount, i.created_at, COALESCE(c.name, 'अज्ञात ग्राहक') AS customer_name, i.total_cost FROM invoices i LEFT JOIN customers c ON i.customer_id = c.id WHERE i.shop_id = $1 ORDER BY i.created_at DESC LIMIT 100", [shopId]);
        res.json({ success: true, sales: result.rows, message: "चालान सफलतापूर्वक लोड किए गए।" });
    } catch (error) {
        console.error("Error fetching invoices list:", error.message);
        res.status(500).json({ success: false, message: 'चालान सूची प्राप्त करने में विफल।' });
    }
});
// 8.3 Get Invoice Details (SCOPED)
app.get('/api/invoices/:invoiceId', authenticateJWT, async (req, res) => {
    const { invoiceId } = req.params;
    const shopId = req.shopId;
    try {
        const invoiceResult = await pool.query(`
            SELECT 
                i.id, 
                i.total_amount, 
                i.total_cost, 
                i.created_at, 
                COALESCE(c.name, 'अज्ञात ग्राहक') AS customer_name, 
                s.shop_name 
            FROM invoices i 
            LEFT JOIN customers c ON i.customer_id = c.id 
            JOIN shops s ON i.shop_id = s.id
            WHERE i.shop_id = $1 AND i.id = $2;
        `, [shopId, invoiceId]);

        if (invoiceResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'चालान नहीं मिला या आपकी शॉप से संबंधित नहीं है।' });
        }
        
        const itemsResult = await pool.query(
            `SELECT item_name, item_sku, quantity, sale_price, purchase_price FROM invoice_items WHERE invoice_id = $1`, 
            [invoiceId]
        );

        const invoice = invoiceResult.rows[0];
        invoice.items = itemsResult.rows;

        res.json({ success: true, invoice: invoice });

    } catch (error) {
        console.error("Error fetching invoice details:", error.message);
        res.status(500).json({ success: false, message: 'चालान विवरण प्राप्त करने में विफल।' });
    }
});


// --- 9. Customer Management ---

// 9.1 Add/Update Customer (SCOPED)
app.post('/api/customers', authenticateJWT, async (req, res) => { 
    const { name, phone, email, address, balance } = req.body;
    const shopId = req.shopId;

    if (!name || !phone) {
        return res.status(400).json({ success: false, message: 'नाम और फ़ोन आवश्यक हैं।' });
    }
    
    // Check if customer already exists in this shop by name or phone
    try {
        let result;
        const existingCustomer = await pool.query(
            'SELECT id FROM customers WHERE shop_id = $1 AND (name = $2 OR phone = $3)', 
            [shopId, name, phone]
        );

        if (existingCustomer.rows.length > 0) {
            // Update existing customer
            const customerId = existingCustomer.rows[0].id;
            const safeBalance = parseFloat(balance || 0);

            result = await pool.query(
                'UPDATE customers SET phone = $1, email = $2, address = $3, balance = balance + $4 WHERE shop_id = $5 AND id = $6 RETURNING *',
                [phone, email, address, safeBalance, shopId, customerId]
            );
            res.json({ success: true, customer: result.rows[0], message: 'ग्राहक सफलतापूर्वक अपडेट किया गया।' });
        } else {
            // Insert new customer
            const safeBalance = parseFloat(balance || 0);
            result = await pool.query(
                'INSERT INTO customers (shop_id, name, phone, email, address, balance) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
                [shopId, name, phone, email, address, safeBalance]
            );
            res.json({ success: true, customer: result.rows[0], message: 'नया ग्राहक सफलतापूर्वक जोड़ा गया।' });
        }

    } catch (err) {
        console.error("Error adding/updating customer:", err.message);
        res.status(500).json({ success: false, message: 'ग्राहक जोड़ने/अपडेट करने में विफल: ' + err.message });
    }
});
// 9.2 Get All Customers (SCOPED)
app.get('/api/customers', authenticateJWT, async (req, res) => { 
    const shopId = req.shopId;
    try {
        const result = await pool.query('SELECT * FROM customers WHERE shop_id = $1 ORDER BY name ASC', [shopId]);
        res.json({ success: true, customers: result.rows });
    } catch (err) {
        console.error("Error fetching customers:", err.message);
        res.status(500).json({ success: false, message: 'ग्राहक सूची प्राप्त करने में विफल।' });
    }
});
// 9.3 Get Customer by ID (SCOPED)
app.get('/api/customers/:customerId', authenticateJWT, async (req, res) => {
    const { customerId } = req.params;
    const shopId = req.shopId;
    try {
        const result = await pool.query('SELECT * FROM customers WHERE id = $1 AND shop_id = $2', [customerId, shopId]);
        if (result.rows.length > 0) {
            res.json({ success: true, customer: result.rows[0] });
        } else {
            res.status(404).json({ success: false, message: 'ग्राहक नहीं मिला या आपकी शॉप से संबंधित नहीं है।' });
        }
    } catch (err) {
        console.error("Error fetching customer:", err.message);
        res.status(500).json({ success: false, message: 'ग्राहक विवरण प्राप्त करने में विफल।' });
    }
});


// --- 10. Expense Management ---

// 10.1 Add New Expense (SCOPED)
app.post('/api/expenses', authenticateJWT, checkRole('MANAGER'), async (req, res) => { // Manager and above
    const { description, category, amount, date } = req.body;
    const shopId = req.shopId;

    if (!description || !amount) {
        return res.status(400).json({ success: false, message: 'विवरण और राशि आवश्यक हैं।' });
    }
    
    const safeAmount = parseFloat(amount);
    if (isNaN(safeAmount) || safeAmount <= 0) {
        return res.status(400).json({ success: false, message: 'राशि एक मान्य धनात्मक संख्या होनी चाहिए।' });
    }
    
    // Use CURRENT_TIMESTAMP if date is not provided/invalid
    const created_at = date && !isNaN(new Date(date)) ? new Date(date) : new Date();

    try {
        const result = await pool.query(
            'INSERT INTO expenses (shop_id, description, category, amount, created_at) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [shopId, description, category, safeAmount, created_at]
        );
        res.json({ success: true, expense: result.rows[0], message: 'खर्च सफलतापूर्वक जोड़ा गया।' });
    } catch (err) {
        console.error("Error adding expense:", err.message);
        res.status(500).json({ success: false, message: 'खर्च जोड़ने में विफल: ' + err.message });
    }
});
// 10.2 Get All Expenses (SCOPED)
app.get('/api/expenses', authenticateJWT, checkRole('MANAGER'), async (req, res) => {
    const shopId = req.shopId;
    // Optional query parameters for filtering
    const { startDate, endDate, category } = req.query;
    
    let query = 'SELECT * FROM expenses WHERE shop_id = $1';
    let queryParams = [shopId];
    let paramIndex = 2;

    if (startDate) {
        query += ` AND created_at >= $${paramIndex++}`;
        queryParams.push(new Date(startDate));
    }
    if (endDate) {
        // Add one day to endDate to include expenses from that date
        const end = new Date(endDate);
        end.setDate(end.getDate() + 1); 
        query += ` AND created_at < $${paramIndex++}`;
        queryParams.push(end);
    }
    if (category) {
        query += ` AND category = $${paramIndex++}`;
        queryParams.push(category);
    }

    query += ' ORDER BY created_at DESC';

    try {
        const result = await pool.query(query, queryParams);
        res.json({ success: true, expenses: result.rows });
    } catch (err) {
        console.error("Error fetching expenses:", err.message);
        res.status(500).json({ success: false, message: 'खर्च सूची प्राप्त करने में विफल।' });
    }
});
// 10.3 Delete Expense (SCOPED)
app.delete('/api/expenses/:expenseId', authenticateJWT, checkRole('ADMIN'), async (req, res) => { // Admin only
    const { expenseId } = req.params;
    const shopId = req.shopId;
    try {
        const result = await pool.query('DELETE FROM expenses WHERE id = $1 AND shop_id = $2', [expenseId, shopId]);
        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, message: 'खर्च नहीं मिला या आपकी शॉप से संबंधित नहीं है।' });
        }
        res.json({ success: true, message: 'खर्च सफलतापूर्वक डिलीट किया गया।' });
    } catch (err) {
        console.error("Error deleting expense:", err.message);
        res.status(500).json({ success: false, message: 'खर्च डिलीट करने में विफल: ' + err.message });
    }
});


// --- 11. Reporting and Dashboard (Admin/Manager) ---

// 11.1 Get Dashboard Summary (Sales, Costs, Profit, Stock Value)
app.get('/api/dashboard/summary', authenticateJWT, checkRole('MANAGER'), async (req, res) => {
    const shopId = req.shopId;
    const { days = 30 } = req.query; // Default to last 30 days
    const daysInt = parseInt(days);
    if (isNaN(daysInt) || daysInt <= 0) {
        return res.status(400).json({ success: false, message: 'दिनों की संख्या मान्य होनी चाहिए।' });
    }
    
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - daysInt);

    const client = await pool.connect();
    try {
        // 1. Total Sales and Cost of Goods Sold (COGS)
        const salesResult = await client.query(
            `SELECT 
                COALESCE(SUM(total_amount), 0) AS total_sales, 
                COALESCE(SUM(total_cost), 0) AS total_cogs 
             FROM invoices 
             WHERE shop_id = $1 AND created_at >= $2`,
            [shopId, startDate]
        );
        const salesData = salesResult.rows[0];

        // 2. Total Expenses
        const expenseResult = await client.query(
            `SELECT COALESCE(SUM(amount), 0) AS total_expenses 
             FROM expenses 
             WHERE shop_id = $1 AND created_at >= $2`,
            [shopId, startDate]
        );
        const expenseData = expenseResult.rows[0];
        
        // 3. Current Stock Value (at cost price)
        const stockValueResult = await client.query(
            `SELECT COALESCE(SUM(quantity * cost_price), 0) AS stock_value 
             FROM stock 
             WHERE shop_id = $1`,
            [shopId]
        );
        const stockData = stockValueResult.rows[0];
        
        // 4. Calculate Profit
        const totalSales = parseFloat(salesData.total_sales);
        const totalCogs = parseFloat(salesData.total_cogs);
        const totalExpenses = parseFloat(expenseData.total_expenses);

        // Gross Profit = Total Sales - Total COGS
        const grossProfit = totalSales - totalCogs;
        // Net Profit = Gross Profit - Total Expenses
        const netProfit = grossProfit - totalExpenses;


        res.json({
            success: true,
            days: daysInt,
            summary: {
                totalSales: parseFloat(totalSales.toFixed(2)),
                totalCogs: parseFloat(totalCogs.toFixed(2)),
                grossProfit: parseFloat(grossProfit.toFixed(2)),
                totalExpenses: parseFloat(totalExpenses.toFixed(2)),
                netProfit: parseFloat(netProfit.toFixed(2)),
                currentStockValue: parseFloat(stockData.stock_value.toFixed(2))
            },
            message: `पिछले ${daysInt} दिनों का सारांश सफलतापूर्वक प्राप्त हुआ।`
        });

    } catch (err) {
        console.error("Error fetching dashboard summary:", err.message);
        res.status(500).json({ success: false, message: 'सारांश प्राप्त करने में विफल: ' + err.message });
    } finally {
        client.release();
    }
});
// 11.2 Get Sales by Day (Line Chart Data)
app.get('/api/dashboard/sales-by-day', authenticateJWT, checkRole('MANAGER'), async (req, res) => {
    const shopId = req.shopId;
    const { days = 30 } = req.query; // Default to last 30 days
    const daysInt = parseInt(days);
    if (isNaN(daysInt) || daysInt <= 0) {
        return res.status(400).json({ success: false, message: 'दिनों की संख्या मान्य होनी चाहिए।' });
    }
    
    // Calculate the start date (midnight of that day)
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - daysInt);
    startDate.setHours(0, 0, 0, 0);

    try {
        // Query to group sales by date
        const result = await pool.query(
            `SELECT 
                DATE(created_at) AS sale_date, 
                COALESCE(SUM(total_amount), 0) AS daily_sales,
                COALESCE(SUM(total_cost), 0) AS daily_cogs 
             FROM invoices 
             WHERE shop_id = $1 AND created_at >= $2
             GROUP BY sale_date
             ORDER BY sale_date ASC`,
            [shopId, startDate]
        );
        
        // Data structure for the last N days (fill missing days with zero)
        const salesMap = {};
        result.rows.forEach(row => {
            // Converts '2023-10-18T18:30:00.000Z' to 'YYYY-MM-DD'
            const dateStr = row.sale_date.toISOString().split('T')[0];
            salesMap[dateStr] = { 
                sales: parseFloat(row.daily_sales), 
                cogs: parseFloat(row.daily_cogs)
            };
        });

        // Generate dates for the last N days
        const finalData = [];
        for (let i = daysInt - 1; i >= 0; i--) {
            const date = new Date();
            date.setDate(date.getDate() - i);
            const dateStr = date.toISOString().split('T')[0];
            
            const data = salesMap[dateStr] || { sales: 0, cogs: 0 };
            finalData.push({ 
                date: dateStr, 
                sales: data.sales, 
                profit: parseFloat((data.sales - data.cogs).toFixed(2))
            });
        }

        res.json({ success: true, data: finalData });

    } catch (err) {
        console.error("Error fetching sales by day:", err.message);
        res.status(500).json({ success: false, message: 'दैनिक बिक्री डेटा प्राप्त करने में विफल: ' + err.message });
    }
});


// --- 12. Advanced DB/Admin Console ---

// 12.1 SQL Console (Admin/Owner only - extremely dangerous route)
app.post('/api/admin/sql-console', authenticateJWT, checkRole('ADMIN'), async (req, res) => {
    const { query } = req.body;
    
    if (!query) {
        return res.status(400).json({ success: false, message: 'SQL क्वेरी आवश्यक है।' });
    }
    
    // 🛑 SAFETY CHECK: Prevent dropping critical tables
    const lowerQuery = query.toLowerCase().trim();
    if (lowerQuery.includes('drop table') || lowerQuery.includes('truncate table')) {
        const forbiddenTables = ['users', 'shops', 'licenses'];
        if (forbiddenTables.some(table => lowerQuery.includes(table))) {
            return res.status(403).json({ success: false, message: 'इस टेबल पर DROP/TRUNCATE की अनुमति नहीं है।' });
        }
    }

    try {
        // Execute the user-provided query
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
