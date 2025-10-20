// server.cjs (Dukan Pro - Ultimate Backend) - MULTI-USER/SECURE VERSION (1174 LINES)
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
       await client.query('CREATE TABLE IF NOT EXISTS shops (id SERIAL PRIMARY KEY, shop_name TEXT NOT NULL, shop_logo TEXT, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);');
        // 0.5. Users Table (Stores login credentials and roles, linked to a shop)
        // 🛑 FIX 1: Removed 'status' and 'license_expiry_date' from here.
        // We ensure basic table exists and then use ALTER TABLE for missing columns.
        await client.query('CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, name TEXT NOT NULL, role TEXT DEFAULT \'CASHIER\' CHECK (role IN (\'ADMIN\', \'MANAGER\', \'CASHIER\')), created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);');
        
        // 🛑 FIX 2: Add 'status' column safely (Fixes the current error)
        await client.query(`
            DO $$ BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = (SELECT oid FROM pg_class WHERE relname = 'users') AND attname = 'status') THEN
                    ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'pending' CHECK (status IN ('active', 'pending', 'disabled'));
                END IF;
            END $$;
        `);
        // END FIX 2 🛑
        
        // 🛑 FIX 3: Add license_expiry_date column safely
        await client.query(`
            DO $$ BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = (SELECT oid FROM pg_class WHERE relname = 'users') AND attname = 'license_expiry_date') THEN
                    ALTER TABLE users ADD COLUMN license_expiry_date TIMESTAMP WITH TIME ZONE DEFAULT NULL;
                END IF;
            END $$;
        `);
        // END FIX 3 🛑

        // 1. Licenses Table (Global, checked before registration)
       // [ server.cjs में बदलें ]//
        // (FIX) यूज़र को लिंक करने के लिए 'user_id' और ग्राहक की जानकारी के लिए 'customer_details' जोड़ा गया //
        await client.query('CREATE TABLE IF NOT EXISTS licenses (key_hash TEXT PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, customer_details JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, expiry_date TIMESTAMP WITH TIME ZONE, is_trial BOOLEAN DEFAULT FALSE);');

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
        await client.query('CREATE TABLE IF NOT EXISTS stock (id SERIAL PRIMARY KEY, shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE, sku TEXT NOT NULL, name TEXT NOT NULL, quantity NUMERIC NOT NULL, unit TEXT, purchase_price NUMERIC NOT NULL, sale_price NUMERIC NOT NULL, cost_price NUMERIC DEFAULT 0, category TEXT, gst NUMERIC DEFAULT 0, updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, UNIQUE (shop_id, sku));');
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
        // 8. Daily Closings Table (NEW)
        await client.query('CREATE TABLE IF NOT EXISTS daily_closings (id SERIAL PRIMARY KEY, shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE, closing_date DATE NOT NULL, total_sales NUMERIC DEFAULT 0, total_cogs NUMERIC DEFAULT 0, total_expenses NUMERIC DEFAULT 0, net_profit NUMERIC DEFAULT 0, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, UNIQUE (shop_id, closing_date));');

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
// [ server.cjs में इस पूरे फ़ंक्शन को बदलें ]

// 1. License Key Generation (Now accessible by global ADMIN password)
app.post('/api/admin/generate-key', async (req, res) => {
    // (FIX) 'customerAddress' को जोड़ा गया
    const { adminPassword, days, customerName, customerMobile, customerAddress } = req.body; 

    if (!process.env.GLOBAL_ADMIN_PASSWORD) {
        return res.status(500).json({ success: false, message: 'सर्वर पर GLOBAL_ADMIN_PASSWORD सेट नहीं है।' });
    }
    if (adminPassword !== process.env.GLOBAL_ADMIN_PASSWORD) {
         return res.status(401).json({ success: false, message: 'अमान्य एडमिन पासवर्ड।' });
    }

    if (typeof days !== 'number' || days < 1) {
        return res.status(400).json({ success: false, message: 'दिनों की संख्या मान्य होनी चाहिए।' });
    }
    
    // (FIX) ग्राहक विवरण को एक JSON ऑब्जेक्ट में सहेजें
    const customer_details = {
        name: customerName,
        mobile: customerMobile,
        address: customerAddress || 'N/A'
    };

    const rawKey = `DUKANPRO-${crypto.randomBytes(16).toString('hex').toUpperCase()}`;
    const keyHash = hashKey(rawKey);
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + days);

    try {
        await pool.query(
            // (FIX) 'customer_details' को JSONB के रूप में डालें
            'INSERT INTO licenses (key_hash, expiry_date, is_trial, customer_details) VALUES ($1, $2, $3, $4)',
            [keyHash, expiryDate, (days === 5), customer_details]
        );
        res.json({ 
            success: true, 
            key: rawKey, 
            message: 'लाइसेंस कुंजी सफलतापूर्वक बनाई गई।',
            duration_days: days,
            valid_until: expiryDate.toISOString(),
            customer: customerName || 'N/A'
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

// [ server.cjs फ़ाइल में यह कोड बदलें ]

// [ server.cjs में इस पूरे फ़ंक्शन को बदलें ]

// 4. User Login (Authenticates and returns JWT)
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'ईमेल और पासवर्ड आवश्यक हैं।' });
    }

    try {
        const result = await pool.query(
            'SELECT u.*, s.shop_name FROM users u JOIN shops s ON u.shop_id = s.id WHERE u.email = $1', 
            [email]
        );
        
        if (result.rows.length === 0) {
            console.log(`DEBUG LOGIN: User not found for email: ${email}`); 
            return res.status(401).json({ success: false, message: 'अमान्य ईमेल या पासवर्ड।' });
        }

        let user = result.rows[0];
        const isMatch = await bcrypt.compare(password, user.password_hash);
        console.log(`DEBUG LOGIN: Password Match? ${isMatch}`); 

        if (!isMatch) {
            return res.status(401).json({ success: false, message: 'अमान्य ईमेल या पासवर्ड।' });
        }

        if (user.status !== 'active') {
             await pool.query('UPDATE users SET status = $1 WHERE id = $2', ['active', user.id]);
             user.status = 'active';
             console.log('DEBUG LOGIN: User status set to active (Auto-Activate).');
        }

        // --- (FIXED LOGIC START) ---
        // 1. टोकन पेलोड तैयार करें (लाइसेंस की परवाह किए बिना)
        const tokenUser = { 
            id: user.id, 
            email: user.email, 
            shopId: user.shop_id, 
            name: user.name, 
            role: user.role, 
            shopName: user.shop_name,
            licenseExpiryDate: user.license_expiry_date,
            status: user.status 
        };
        const token = jwt.sign(tokenUser, JWT_SECRET, { expiresIn: '30d' });

        // 2. अब लाइसेंस की जाँच करें
        const expiryDate = user.license_expiry_date ? new Date(user.license_expiry_date) : null;
        const currentDate = new Date();
        currentDate.setHours(0, 0, 0, 0);
        
        if (!expiryDate || expiryDate < currentDate) {
             console.log('DEBUG LOGIN: License is missing or expired. Requires key.');
             // 3. (FIX) लाइसेंस समाप्त है, लेकिन फिर भी टोकन के साथ 200 OK भेजें
             return res.json({ 
                 success: true, // लॉगिन सफल रहा
                 message: 'आपका खाता सक्रिय है, लेकिन लाइसेंस समाप्त हो गया है। कृपया लाइसेंस कुंजी दर्ज करें।',
                 requiresLicense: true, // क्लाइंट को Modal दिखाने के लिए कहें
                 token: token, // सक्रियण के लिए टोकन प्रदान करें
                 user: tokenUser
             });
        }
        
        // 4. सफल लॉगिन (यदि लाइसेंस मान्य है)
        res.json({ 
            success: true, 
            message: 'लॉगिन सफल।',
            requiresLicense: false,
            token: token,
            user: tokenUser
        });
        // --- (FIXED LOGIC END) ---

    } catch (err) {
        console.error("Error logging in:", err.message);
        res.status(500).json({ success: false, message: 'लॉगिन विफल: ' + err.message });
    }
});
// [ server.cjs में इस पूरे फ़ंक्शन को बदलें ]

// 5. License Activation Route (Securely update license expiry)
// 🔑 (FIXED) यह रूट अब 'licenses' टेबल में असली (hashed) कीज़ की जाँच करेगा
app.post('/api/activate-license', authenticateJWT, async (req, res) => {
    const { licenseKey } = req.body;
    const userId = req.user.id; 
    const shopId = req.user.shopId;

    if (!licenseKey) {
        return res.status(400).json({ success: false, message: 'लाइसेंस कुंजी आवश्यक है।' });
    }

    const keyHash = hashKey(licenseKey); // कुंजी को हैश करें
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        // 1. देखें कि क्या कुंजी 'licenses' टेबल में मौजूद है
        const licenseResult = await client.query(
            'SELECT expiry_date, user_id FROM licenses WHERE key_hash = $1',
            [keyHash]
        );

        if (licenseResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({ success: false, message: 'अमान्य लाइसेंस कुंजी।' });
        }

        const license = licenseResult.rows[0];
        const newExpiryDate = new Date(license.expiry_date);
        const now = new Date();

        // 2. देखें कि क्या कुंजी पहले ही समाप्त हो चुकी है
        if (newExpiryDate < now) {
            await client.query('ROLLBACK');
            return res.status(400).json({ success: false, message: 'यह लाइसेंस कुंजी पहले ही समाप्त हो चुकी है।' });
        }
        
        // 3. देखें कि क्या कुंजी पहले ही किसी और यूज़र द्वारा उपयोग की जा चुकी है
        // (नोट: यदि user_id NULL है, तो इसका उपयोग किया जा सकता है)
        if (license.user_id && license.user_id !== userId) {
            await client.query('ROLLBACK');
            return res.status(400).json({ success: false, message: 'यह लाइसेंस कुंजी पहले ही किसी अन्य खाते द्वारा उपयोग की जा चुकी है।' });
        }

        // 4. सब ठीक है! यूज़र की समाप्ति तिथि अपडेट करें
        await client.query(
            'UPDATE users SET license_expiry_date = $1 WHERE id = $2',
            [newExpiryDate, userId]
        );

        // 5. कुंजी को "used" के रूप में चिह्नित करें (इसे इस यूज़र से लिंक करें)
        await client.query(
            'UPDATE licenses SET user_id = $1 WHERE key_hash = $2',
            [userId, keyHash]
        );

        // 6. यूज़र का अपडेटेड डेटा (शॉप नाम सहित) पुनः प्राप्त करें
        const updatedUserResult = await client.query(
            'SELECT u.*, s.shop_name FROM users u JOIN shops s ON u.shop_id = s.id WHERE u.id = $1', 
            [userId]
        );
        const updatedUser = updatedUserResult.rows[0];
        
        // 7. नया टोकन जनरेट करें और वापस भेजें
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

        await client.query('COMMIT');
        
        res.json({
            success: true,
            message: `लाइसेंस सफलतापूर्वक सक्रिय हो गया है। नई समाप्ति तिथि: ${newExpiryDate.toLocaleDateString()}`,
            token: token,
            user: tokenUser
        });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error("License Activation Error:", err.message);
        res.status(500).json({ success: false, message: 'लाइसेंस सक्रियण विफल: ' + err.message });
    } finally {
        client.release();
    }
});

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

// [ server.cjs फ़ाइल में यह कोड जोड़ें ]

// -----------------------------------------------------------------------------
// 10.5. PURCHASE MANAGEMENT (NEW)
// -----------------------------------------------------------------------------
// (यह एक सरल कार्यान्वयन है। यह स्टॉक को स्वचालित रूप से अपडेट नहीं करता है।)

// 10.5.1 Add New Purchase Record (SCOPED)
app.post('/api/purchases', authenticateJWT, checkRole('MANAGER'), async (req, res) => {
    // 'created_at' को 'date' के रूप में स्वीकार करें, जैसा कि expenses करता है
    const { supplier_name, item_details, total_cost, date } = req.body;
    const shopId = req.shopId;

    if (!supplier_name || !total_cost) {
        return res.status(400).json({ success: false, message: 'आपूर्तिकर्ता (Supplier) का नाम और कुल लागत आवश्यक हैं।' });
    }
    
    const safeTotalCost = parseFloat(total_cost);
    if (isNaN(safeTotalCost) || safeTotalCost <= 0) {
        return res.status(400).json({ success: false, message: 'लागत एक मान्य धनात्मक संख्या होनी चाहिए।' });
    }
    
    const purchase_date = date && !isNaN(new Date(date)) ? new Date(date) : new Date();

    try {
        const result = await pool.query(
            'INSERT INTO purchases (shop_id, supplier_name, item_details, total_cost, created_at) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [shopId, supplier_name, item_details || 'N/A', safeTotalCost, purchase_date]
        );
        res.json({ success: true, purchase: result.rows[0], message: 'खरीद सफलतापूर्वक जोड़ी गई।' });
    } catch (err) {
        console.error("Error adding purchase:", err.message);
        res.status(500).json({ success: false, message: 'खरीद जोड़ने में विफल: ' + err.message });
    }
});

// 10.5.2 Get All Purchases (SCOPED)
app.get('/api/purchases', authenticateJWT, checkRole('MANAGER'), async (req, res) => {
    const shopId = req.shopId;
    try {
        const result = await pool.query(
            'SELECT * FROM purchases WHERE shop_id = $1 ORDER BY created_at DESC', 
            [shopId]
        );
        res.json({ success: true, purchases: result.rows });
    } catch (err) {
        console.error("Error fetching purchases:", err.message);
        res.status(500).json({ success: false, message: 'खरीद सूची प्राप्त करने में विफल।' });
    }
});

// 10.5.3 Delete Purchase (SCOPED)
app.delete('/api/purchases/:purchaseId', authenticateJWT, checkRole('ADMIN'), async (req, res) => {
    const { purchaseId } = req.params;
    const shopId = req.shopId;
    try {
        const result = await pool.query('DELETE FROM purchases WHERE id = $1 AND shop_id = $2', [purchaseId, shopId]);
        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, message: 'खरीद रिकॉर्ड नहीं मिला या आपकी शॉप से संबंधित नहीं है।' });
        }
        res.json({ success: true, message: 'खरीद रिकॉर्ड सफलतापूर्वक डिलीट किया गया।' });
    } catch (err) {
        console.error("Error deleting purchase:", err.message);
        res.status(500).json({ success: false, message: 'खरीद रिकॉर्ड डिलीट करने में विफल: ' + err.message });
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
       // [ server.cjs में बदलें ]
        const stockData = stockValueResult.rows[0];
        // ...
        res.json({
            // ...
            summary: {
                // ...
                // FIX: .toFixed() को parseFloat() के बाद लगाएँ
                currentStockValue: parseFloat(stockData.stock_value).toFixed(2)
            },
        });
        
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

// [ server.cjs में यह नया सेक्शन जोड़ें ]

// -----------------------------------------------------------------------------
// V. ADMIN PANEL API ROUTES (GLOBAL ADMIN ONLY)
// -----------------------------------------------------------------------------
// (यह 'ADMIN' रोल वाले यूज़र्स को सभी शॉप्स का डेटा देखने की अनुमति देता है)

// 11.5 Shop Settings (Logo/Name Update)
app.post('/api/shop/settings', authenticateJWT, async (req, res) => {
    const { shop_name, shop_logo } = req.body;
    const shopId = req.shopId;
    const userId = req.user.id;

    if (!shop_name) {
        return res.status(400).json({ success: false, message: 'शॉप का नाम खाली नहीं हो सकता।' });
    }

    try {
        // शॉप का नाम और लोगो (Base64) अपडेट करें
        await pool.query(
            'UPDATE shops SET shop_name = $1, shop_logo = $2 WHERE id = $3',
            [shop_name, shop_logo, shopId]
        );

        // यूज़र का डेटा पुनः प्राप्त करें (क्योंकि 'shopName' बदल गया होगा)
        const updatedUserResult = await pool.query(
            'SELECT u.*, s.shop_name, s.shop_logo FROM users u JOIN shops s ON u.shop_id = s.id WHERE u.id = $1', 
            [userId]
        );
        const updatedUser = updatedUserResult.rows[0];

        // नया टोकन जनरेट करें जिसमें नया shopName और shopLogo हो
        const tokenUser = { 
            id: updatedUser.id, 
            email: updatedUser.email, 
            shopId: updatedUser.shop_id, 
            name: updatedUser.name, 
            role: updatedUser.role, 
            shopName: updatedUser.shop_name, // (Updated)
            shopLogo: updatedUser.shop_logo, // (Updated)
            licenseExpiryDate: updatedUser.license_expiry_date,
            status: updatedUser.status 
        };
        const token = jwt.sign(tokenUser, JWT_SECRET, { expiresIn: '30d' });

        res.json({
            success: true,
            message: 'शॉप सेटिंग्स सफलतापूर्वक अपडेट की गईं।',
            token: token,
            user: tokenUser
        });

    } catch (err) {
        console.error("Error updating shop settings:", err.message);
        res.status(500).json({ success: false, message: 'सेटिंग्स अपडेट करने में विफल: ' + err.message });
    }
});

// 11.6 Shop-Specific Backup
app.get('/api/backup', authenticateJWT, async (req, res) => {
    const shopId = req.shopId;
    const client = await pool.connect();
    try {
        const tables = ['stock', 'customers', 'invoices', 'invoice_items', 'purchases', 'expenses'];
        const backupData = {};
        
        for (const table of tables) {
            const result = await client.query(`SELECT * FROM ${table} WHERE shop_id = $1`, [shopId]);
            backupData[table] = result.rows;
        }
        
        // शॉप की जानकारी भी शामिल करें
        const shopResult = await client.query('SELECT * FROM shops WHERE id = $1', [shopId]);
        backupData['shop_details'] = shopResult.rows;

        res.json({ success: true, backupData: backupData });
    } catch (err) {
        res.status(500).json({ success: false, message: 'शॉप बैकअप विफल: ' + err.message });
    } finally {
        client.release();
    }
});

// 12.1 Get All Users (Global)
app.get('/api/admin/all-users', authenticateJWT, checkRole('ADMIN'), async (req, res) => {
    try {
        const result = await pool.query('SELECT id, shop_id, name, email, role, status FROM users ORDER BY shop_id, id');
        res.json({ success: true, users: result.rows });
    } catch (err) {
        res.status(500).json({ success: false, message: 'सभी यूज़र्स को लाने में विफल: ' + err.message });
    }
});

// 12.2 Get All Shops (Global)
app.get('/api/admin/shops', authenticateJWT, checkRole('ADMIN'), async (req, res) => {
    try {
        const result = await pool.query('SELECT id, shop_name, created_at FROM shops ORDER BY id');
        res.json({ success: true, shops: result.rows });
    } catch (err) {
        res.status(500).json({ success: false, message: 'सभी शॉप्स को लाने में विफल: ' + err.message });
    }
});

// 12.3 Get All Licenses (Global)
app.get('/api/admin/licenses', authenticateJWT, checkRole('ADMIN'), async (req, res) => {
    try {
        // (FIX) customer_details को JSONB से चुनें
        const result = await pool.query('SELECT key_hash, user_id, expiry_date, is_trial, customer_details FROM licenses ORDER BY created_at DESC');
        res.json({ success: true, licenses: result.rows });
    } catch (err) {
        res.status(500).json({ success: false, message: 'सभी लाइसेंस को लाने में विफल: ' + err.message });
    }
});

// 12.4 Update User Status/Role (Global)
app.put('/api/admin/user-status/:userId', authenticateJWT, checkRole('ADMIN'), async (req, res) => {
    const { userId } = req.params;
    const { name, role, status } = req.body;
    
    // एडमिन को खुद को डिसेबल करने से रोकें
    if (parseInt(userId) === req.user.id && status === 'disabled') {
        return res.status(403).json({ success: false, message: 'आप खुद को अक्षम (disable) नहीं कर सकते।' });
    }

    try {
        await pool.query(
            'UPDATE users SET name = $1, role = $2, status = $3 WHERE id = $4',
            [name, role, status, userId]
        );
        res.json({ success: true, message: 'यूज़र सफलतापूर्वक अपडेट किया गया।' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'यूज़र अपडेट करने में विफल: ' + err.message });
    }
});

// 12.5 Full Database Backup (Global)
app.get('/api/admin/backup-all', authenticateJWT, checkRole('ADMIN'), async (req, res) => {
    const client = await pool.connect();
    try {
        const tables = ['shops', 'users', 'licenses', 'stock', 'customers', 'invoices', 'invoice_items', 'purchases', 'expenses'];
        const backupData = {};
        for (const table of tables) {
            const result = await client.query(`SELECT * FROM ${table}`);
            backupData[table] = result.rows;
        }
        res.json({ success: true, backupData: backupData });
    } catch (err) {
        res.status(500).json({ success: false, message: 'डेटाबेस बैकअप विफल: ' + err.message });
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
// 13. DAILY CLOSING API (NEW)
// -----------------------------------------------------------------------------

// 13.1 Run Daily Closing (SCOPED & TRANSACTIONAL)
app.post('/api/closing/run', authenticateJWT, checkRole('MANAGER'), async (req, res) => {
    const shopId = req.shopId;
    // आज की तारीख सर्वर टाइमज़ोन के अनुसार
    const today = new Date().toISOString().split('T')[0];

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 1. जांचें कि क्या आज की क्लोजिंग पहले ही हो चुकी है
        const checkResult = await client.query(
            'SELECT id FROM daily_closings WHERE shop_id = $1 AND closing_date = $2',
            [shopId, today]
        );
        
        if (checkResult.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({ success: false, message: 'आज की क्लोजिंग पहले ही रन हो चुकी है।' });
        }

        // 2. आज की बिक्री (Invoices) की गणना करें
        const salesResult = await client.query(
            `SELECT COALESCE(SUM(total_amount), 0) AS sales, COALESCE(SUM(total_cost), 0) AS cogs 
             FROM invoices 
             WHERE shop_id = $1 AND DATE(created_at) = $2`,
            [shopId, today]
        );
        const { sales, cogs } = salesResult.rows[0];

        // 3. आज के खर्च (Expenses) की गणना करें
        const expensesResult = await client.query(
            `SELECT COALESCE(SUM(amount), 0) AS expenses 
             FROM expenses 
             WHERE shop_id = $1 AND DATE(created_at) = $2`,
            [shopId, today]
        );
        const { expenses } = expensesResult.rows[0];

        // 4. शुद्ध लाभ (Net Profit) की गणना करें
        const netProfit = parseFloat(sales) - parseFloat(cogs) - parseFloat(expenses);

        // 5. क्लोजिंग रिपोर्ट सहेजें
        await client.query(
            `INSERT INTO daily_closings (shop_id, closing_date, total_sales, total_cogs, total_expenses, net_profit) 
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [shopId, today, parseFloat(sales), parseFloat(cogs), parseFloat(expenses), netProfit]
        );

        await client.query('COMMIT');
        res.json({ 
            success: true, 
            message: `आज (${today}) की क्लोजिंग सफलतापूर्वक सहेज ली गई।`,
            report: {
                date: today,
                sales,
                cogs,
                expenses,
                netProfit
            }
        });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error("Error running daily closing:", err.message);
        res.status(500).json({ success: false, message: 'क्लोजिंग रन करने में विफल: ' + err.message });
    } finally {
        client.release();
    }
});

// 13.2 Get All Closing Reports (SCOPED)
app.get('/api/closing/reports', authenticateJWT, checkRole('MANAGER'), async (req, res) => {
    const shopId = req.shopId;
    try {
        const result = await pool.query(
            'SELECT * FROM daily_closings WHERE shop_id = $1 ORDER BY closing_date DESC',
            [shopId]
        );
        res.json({ success: true, reports: result.rows });
    } catch (err) {
        console.error("Error fetching closing reports:", err.message);
        res.status(500).json({ success: false, message: 'रिपोर्ट्स लाने में विफल: ' + err.message });
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







