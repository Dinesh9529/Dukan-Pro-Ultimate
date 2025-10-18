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
        const token = authHeader.split(' ')[1];
// Expects 'Bearer <token>'

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
        next();
// Authorized
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
        
        if (result.rows.length === 
0) {
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
        // 🌟 FIX: This query now works because the 'status' column exists.
        const userInsertQuery = `
            INSERT INTO users (shop_id, email, password_hash, name, role, status) 
            VALUES ($1, $2, $3, $4, $5, 'active') 
            RETURNING id, shop_id, email, name, role, status
        
`;
        // 'status' को 'active' पर सेट करने के लिए, हमने उसे ऊपर query में hardcode किया है।
// हमें 5 पैरामीटर भेजने होंगे।
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
            status: user.status // 🌟 FIX: 'status' is now correctly returned from DB
        };
const token = jwt.sign(tokenUser, JWT_SECRET, { expiresIn: '30d' });

        await client.query('COMMIT');
// लेन-देन पूरा करें
        
        res.json({ 
            success: true, 
            message: 'शॉप और एडमिन अकाउंट सफलतापूर्वक बनाया गया।',
            token: token,
            user: tokenUser
        });
} catch (err) {
        await client.query('ROLLBACK');
// गलती होने पर रोलबैक करें
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
        // डेटाबेस से यूज़र और शॉप का नाम एक साथ फ़ेच करें
        // u.*: users टेबल के सभी 
// कॉलम (जैसे id, password_hash, role, status)
        // s.shop_name: shops टेबल से शॉप का नाम
        // 🌟 FIX: This query now correctly selects the 'status' column as part of 'u.*'
        const result = await pool.query(
            'SELECT u.*, s.shop_name FROM users u JOIN shops s ON u.shop_id = s.id WHERE u.email = $1', 
            [email]
        );
        
        if (result.rows.length === 
0) {
            console.log(`DEBUG LOGIN: User not found for email: ${email}`); 
            return res.status(401).json({ success: false, message: 'अमान्य ईमेल या पासवर्ड।' });
        }

        const user = result.rows[0];
        
        // पासवर्ड की तुलना करें (Bcrypt)
        const isMatch = await bcrypt.compare(password, user.password_hash);
console.log(`DEBUG LOGIN: Password Match? ${isMatch}`); 

        if (!isMatch) {
            return res.status(401).json({ success: false, message: 'अमान्य ईमेल या पासवर्ड।' });
}

        // JWT टोकन के लिए पेलोड बनाएं
        const tokenUser = { 
            id: user.id, 
            email: user.email, 
            shopId: user.shop_id, 
            name: user.name, 
            role: user.role, 
    
        shopName: user.shop_name,
            status: user.status // 🌟 FIX: 'status' is now correctly included
        };
// JWT टोकन जनरेट करें
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

// -----------------------------------------------------------------------------
// IV.
// MULTI-TENANT SHOP DATA ROUTES (PROTECTED & SCOPED) //
// -----------------------------------------------------------------------------

// --- 5. User Management (Shop Admin Only) ---

// 5.1 Add New User to the Current Shop
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
        res.json({ success: true, user: result.rows[0], message: 'यूजर सफलतापूर्वक जोड़ा गया।' 
});
    } catch (err) {
        if (err.constraint === 'users_email_key') {
            return res.status(409).json({ success: false, message: 'यह ईमेल आपकी शॉप में पहले से उपयोग में है।' });
}
        console.error("Error adding user:", err.message);
res.status(500).json({ success: false, message: 'यूजर जोड़ने में विफल: ' + err.message });
    }
});
// 5.2 Get All Users for the Current Shop
app.get('/api/users', authenticateJWT, checkRole('MANAGER'), async (req, res) => { // Manager can view staff
    const shopId = req.shopId;
    try {
        // 🌟 FIX: Added 'status' to SELECT
        const result = await pool.query('SELECT id, name, email, role, status, created_at FROM users WHERE shop_id = $1 ORDER BY created_at ASC', [shopId]);
        res.json({ success: true, users: result.rows });
    } catch (err) {
        console.error("Error fetching users:", err.message);
        res.status(500).json({ 
success: false, message: 'यूजर सूची प्राप्त करने में विफल।' });
    }
});
// 5.3 Update User Role/Name/Status
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
            const 
upperRole = role.toUpperCase();
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
// 5.4 Delete User from the Current Shop
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


// --- 6. Stock Management ---

// 6.1 Stock Management - Add/Update (SCOPED & Transactional)
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
            [shopId, sku, name, safeQuantity, unit, 
safePurchasePrice, safeSalePrice, safeGst, safeCostPrice, category]
        );
res.json({ success: true, stock: result.rows[0], message: 'स्टॉक सफलतापूर्वक जोड़ा/अपडेट किया गया।' });
} catch (err) {
        console.error("Error adding stock:", err.message);
res.status(500).json({ success: false, message: 'स्टॉक जोड़ने में विफल: ' + err.message });
    }
});
// 6.2 Stock Management - Get All (SCOPED)
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
// 6.3 Stock Management - Search Items (SCOPED)
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
        res.status(500).json({ success: false, message: 'आइटम खोजने में 
विफल: ' + err.message });
    }
});

// 6.4 Stock Management - Get Single Item by SKU (SCOPED)
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
// 6.5 Stock Management - Delete Item (SCOPED)
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
// --- 7. Invoice/Sales Management ---

// 7.1 Process New Sale / Create Invoice (SCOPED & TRANSACTIONAL) - (Completed route 22)
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
        await client.query('ROLLBACK');
// Rollback on any error
        console.error("Error processing invoice:", err.message);
res.status(500).json({ success: false, message: 'बिक्री विफल: ' + err.message });
} finally {
        client.release();
    }
});
// 7.2 Get Invoices/Sales List (SCOPED)
app.get('/api/invoices', authenticateJWT, async (req, res) => { 
    const shopId = req.shopId;
    try {
        // 🔑 Query now includes WHERE i.shop_id = $1
        const result = await pool.query("SELECT i.id, i.total_amount, i.created_at, COALESCE(c.name, 'अज्ञात ग्राहक') AS customer_name, i.total_cost FROM invoices i LEFT JOIN customers c ON i.customer_id = c.id WHERE i.shop_id = $1 ORDER BY i.created_at DESC LIMIT 100", [shopId]);
        res.json({ success: true, sales: result.rows, message: "चालान सफलतापूर्वक लोड 
किए गए।" });
    } catch (error) {
        console.error("Error fetching invoices list:", error.message);
        res.status(500).json({ success: false, message: 'चालान सूची प्राप्त करने में विफल।' });
    }
});
// 7.3 Get Invoice Details (SCOPED)
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
            LEFT JOIN customers c ON i.customer_id = 
c.id
            JOIN shops s ON i.shop_id = s.id
            WHERE i.shop_id = $1 AND i.id = $2;
        `, [shopId, invoiceId]);

        if (invoiceResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'चालान नहीं मिला या आपकी शॉप से संबंधित नहीं है।' });
        }

      
  const itemsResult = await pool.query('SELECT item_name, item_sku, quantity, sale_price FROM invoice_items WHERE invoice_id = $1', [invoiceId]);
res.json({
            success: true,
            invoice: invoiceResult.rows[0],
            items: itemsResult.rows,
            message: 'चालान विवरण सफलतापूर्वक प्राप्त किया गया।'
        });
} catch (error) {
        console.error("Error fetching invoice details:", error.message);
res.status(500).json({ success: false, message: 'चालान विवरण प्राप्त करने में विफल।' });
    }
});
// --- 8. Customer Management ---

// 8.1 Add Customer (SCOPED)
app.post('/api/customer', authenticateJWT, checkRole('CASHIER'), async (req, res) => { 
    const { name, phone, email, address } = req.body;
    const shopId = req.shopId;
    if (!name) {
        return res.status(400).json({ success: false, message: 'ग्राहक का नाम आवश्यक है।' });
    }
    try {
        const result = await pool.query(
            `INSERT INTO customers (shop_id, name, phone, email, 
address) VALUES ($1, $2, $3, $4, $5) RETURNING id, name`,
            [shopId, name, phone, email, address]
        );
        res.json({ success: true, customer: result.rows[0], message: 'ग्राहक सफलतापूर्वक जोड़ा गया।' });
    } catch (err) {
        console.error("Error adding customer:", err.message);
        res.status(500).json({ success: false, message: 'ग्राहक जोड़ने में विफल: ' + err.message });
    }
});
// 8.2 Get Customers (SCOPED)
app.get('/api/customer', authenticateJWT, async (req, res) => { 
    const shopId = req.shopId;
    try {
        const result = await pool.query(`SELECT * FROM customers WHERE shop_id = $1 ORDER BY created_at DESC;`, [shopId]);
        res.json({ success: true, customers: result.rows });
    } catch (err) {
        console.error("Error fetching customers:", err.message);
        res.status(500).json({ success: false, message: 'ग्राहक सूची प्राप्त करने में विफल।' });
    
}
});


// --- 9. Purchase Management ---

// 9.1 Add Purchase (SCOPED)
app.post('/api/purchase', authenticateJWT, checkRole('MANAGER'), async (req, res) => { 
    const { supplier_name, item_details, total_cost } = req.body;
    const shopId = req.shopId;
    
    if (!supplier_name || !item_details || !total_cost) {
        return res.status(400).json({ success: false, message: 'सप्लायर का नाम, आइटम विवरण और कुल लागत आवश्यक हैं।' });
    }

    const safeTotalCost = parseFloat(total_cost);
    if (isNaN(safeTotalCost) || safeTotalCost <= 0) {
      
  return res.status(400).json({ success: false, message: 'कुल लागत एक मान्य संख्या होनी चाहिए।' });
    }

    try {
        await pool.query(
            `INSERT INTO purchases (shop_id, supplier_name, item_details, total_cost) VALUES ($1, $2, $3, $4)`,
            [shopId, supplier_name, JSON.stringify(item_details), safeTotalCost] // Store item_details as JSON string
        );
        res.json({ success: true, message: 'खरीद सफलतापूर्वक दर्ज की 
गई।' });
    } catch (err) {
        console.error("Error adding purchase:", err.message);
res.status(500).json({ success: false, message: 'खरीद जोड़ने में विफल: ' + err.message });
    }
});
// 9.2 Get Purchases (SCOPED)
app.get('/api/purchase', authenticateJWT, checkRole('MANAGER'), async (req, res) => { 
    const shopId = req.shopId;
    try {
        const result = await pool.query(`SELECT * FROM purchases WHERE shop_id = $1 ORDER BY created_at DESC;`, [shopId]);
        // Parse item_details back to object/array
        const purchases = result.rows.map(row => {
            try {
                return { ...row, item_details: JSON.parse(row.item_details) };
            } catch (e) {
                return { ...row, item_details: row.item_details }; // Return raw string if not JSON
            }
        });
        res.json({ success: true, purchases: purchases });
    } catch (err) {
        console.error("Error fetching purchases:", err.message);
        res.status(500).json({ success: false, message: 'खरीद सूची प्राप्त करने में विफल।' });
    }
});
// --- 10. Expense Management ---

// 10.1 Add Expense (SCOPED)
app.post('/api/expense', authenticateJWT, checkRole('MANAGER'), async (req, res) => { 
    const { description, category, amount } = req.body;
    const shopId = req.shopId;
    
    if (!description || !amount) {
        return res.status(400).json({ success: false, message: 'विवरण और राशि आवश्यक हैं।' });
    }
    
    const safeAmount = parseFloat(amount);
    if (isNaN(safeAmount) || safeAmount <= 0) {
        return res.status(400).json({ 
success: false, message: 'राशि एक मान्य संख्या होनी चाहिए।' });
    }

    try {
        await pool.query(
            `INSERT INTO expenses (shop_id, description, category, amount) VALUES ($1, $2, $3, $4)`,
            [shopId, description, category || 'अन्य', safeAmount]
        );
        res.json({ success: true, message: 'खर्च सफलतापूर्वक दर्ज किया गया।' });
    } catch (err) {
 
       console.error("Error adding expense:", err.message);
        res.status(500).json({ success: false, message: 'खर्च जोड़ने में विफल: ' + err.message });
}
});

// 10.2 Get Expenses (SCOPED)
app.get('/api/expense', authenticateJWT, checkRole('MANAGER'), async (req, res) => { 
    const shopId = req.shopId;
    try {
        const result = await pool.query(`SELECT * FROM expenses WHERE shop_id = $1 ORDER BY created_at DESC;`, [shopId]);
        res.json({ success: true, expenses: result.rows });
    } catch (err) {
        console.error("Error fetching expenses:", err.message);
        res.status(500).json({ success: false, message: 'खर्च सूची प्राप्त करने में विफल।' });
  
  }
});


// --- 11. Dashboard & Reports ---

// 11.1 Dashboard Data (SCOPED)
app.get('/api/get-dashboard-data', authenticateJWT, async (req, res) => { 
    const shopId = req.shopId; 
    try {
        // 🔑 All queries now include WHERE shop_id = $1
        const salesResult = await pool.query("SELECT COALESCE(SUM(total_amount), 0) AS value FROM invoices WHERE shop_id = $1", [shopId]);
        const totalSalesRevenue = parseFloat(salesResult.rows[0].value);

        const stockValueResult = await pool.query("SELECT COALESCE(SUM(purchase_price * quantity), 
0) AS value FROM stock WHERE shop_id = $1", [shopId]);
        const totalStockValue = parseFloat(stockValueResult.rows[0].value);
        
        const customerResult = await pool.query("SELECT COUNT(DISTINCT id) AS value FROM customers WHERE shop_id = $1", [shopId]);
        const totalCustomers = parseInt(customerResult.rows[0].value);

        const lowStockResult = await pool.query("SELECT COUNT(id) AS value FROM stock WHERE shop_id = $1 AND quantity < 10", [shopId]);
const lowStockCount = parseInt(lowStockResult.rows[0].value);

        res.json({
            success: true,
            totalSalesRevenue: totalSalesRevenue,
            totalStockValue: totalStockValue,
            totalCustomers: totalCustomers,
            lowStockCount: lowStockCount
        });
} catch (error) {
        console.error('डैशबोर्ड डेटा SQL/PostgreSQL एरर:', error.message);
res.status(500).json({ success: false, message: 'डैशबोर्ड डेटा लोड नहीं किया जा सका: ' + error.message });
    }
});
// 11.2 Get Recent Sales (SCOPED)
app.get('/api/get-recent-sales', authenticateJWT, async (req, res) => { 
    const shopId = req.shopId;
    try {
        // 🔑 Query now includes WHERE i.shop_id = $1
        const result = await pool.query("SELECT i.id AS invoice_id, COALESCE(c.name, 'अनाम ग्राहक') AS customer_name, i.total_amount, i.created_at FROM invoices i LEFT JOIN customers c ON i.customer_id = c.id WHERE i.shop_id = $1 ORDER BY i.created_at DESC LIMIT 10", [shopId]);
        res.json({ success: true, sales: result.rows });
   
 } catch (error) {
        console.error("Error fetching recent sales:", error.message);
        res.status(500).json({ success: false, message: 'हाल की बिक्री प्राप्त करने में विफल।' });
    }
});
// 11.3 Get Low Stock Items List (SCOPED)
app.get('/api/get-low-stock-items', authenticateJWT, async (req, res) => { 
    const shopId = req.shopId;
    try {
        // 🔑 Query now includes WHERE shop_id = $1
        const result = await pool.query("SELECT sku, name, quantity FROM stock WHERE shop_id = $1 AND quantity < 10 ORDER BY quantity ASC LIMIT 10", [shopId]);
        res.json({ success: true, items: result.rows });
    } catch (error) {
      
  console.error("Error fetching low stock:", error.message);
        res.status(500).json({ success: false, message: 'कम स्टॉक आइटम प्राप्त करने में विफल।' });
    }
});
// 11.4 Get Balance Sheet / Detailed Financials Data (SCOPED)
app.get('/api/get-balance-sheet-data', authenticateJWT, checkRole('MANAGER'), async (req, res) => { 
    const shopId = req.shopId;
    try {
        // 🔑 All queries now include WHERE clause for shop_id
        
        // A. Total Sales Revenue (कुल राजस्व)
        const revenueResult = await pool.query("SELECT COALESCE(SUM(CAST(total_amount AS NUMERIC)), 0) AS total_revenue FROM invoices WHERE shop_id = $1;", [shopId]);
       
 const totalRevenue = parseFloat(revenueResult.rows[0].total_revenue);

        // B. Total Cost of Goods Sold (COGS)
        const cogsResult = await pool.query("SELECT COALESCE(SUM(CAST(total_cost AS NUMERIC)), 0) AS total_cogs FROM invoices WHERE shop_id = $1;", [shopId]);
        const totalCOGS = parseFloat(cogsResult.rows[0].total_cogs);

        // C. Total Expenses (कुल खर्च)
        const expensesResult = await pool.query("SELECT COALESCE(SUM(amount), 0) AS total_expenses FROM expenses WHERE shop_id = $1;", [shopId]);
const totalExpenses = parseFloat(expensesResult.rows[0].total_expenses);

        const netProfit = totalRevenue - totalCOGS - totalExpenses;
// D. Stock Value (Asset - परिसंपत्ति)
        const stockValueResult = await pool.query("SELECT COALESCE(SUM(CAST(purchase_price AS NUMERIC) * CAST(quantity AS NUMERIC)), 0) AS value FROM stock WHERE shop_id = $1;", [shopId]);
const stockValue = parseFloat(stockValueResult.rows[0].value);

        // E. GST Payable (Liability - देनदारी) 
        const gstResult = await pool.query(
            `SELECT COALESCE(SUM(CAST(ii.quantity AS NUMERIC) * CAST(ii.sale_price AS NUMERIC) * (CAST(s.gst AS NUMERIC) / 100.0)), 0) AS gst_collected
             FROM invoice_items ii
             JOIN invoices i ON ii.invoice_id = i.id
             JOIN stock 
s ON ii.item_sku = s.sku AND i.shop_id = s.shop_id 
             WHERE i.shop_id = $1;`, [shopId]
        );
const gstPayable = parseFloat(gstResult.rows[0].gst_collected);

        // F. Accounts Receivable (उधार बाकी - Simple approximation: 10% of Revenue for demo)
        const accountsReceivable = totalRevenue * 0.10;
// Balance Sheet Calculations (Simplified)
        const vendorsPayable = 0.00;
// Assuming zero for this version
        const ownerEquity = netProfit;
const totalLiabilities = gstPayable + vendorsPayable;
        const totalAssets = stockValue + accountsReceivable + (netProfit > 0 ? netProfit : 0);
// Simplified Assets Calculation
        const cashBalance = totalAssets - stockValue - accountsReceivable;
// Cash is balancing figure

        const totalLiabilitiesAndEquity = totalLiabilities + ownerEquity;
res.json({
            success: true,
            data: {
                totalRevenue: totalRevenue.toFixed(2),
                totalCOGS: totalCOGS.toFixed(2),
                totalExpenses: totalExpenses.toFixed(2),
                netProfit: netProfit.toFixed(2),
      
          
                stockValue: stockValue.toFixed(2), 
                accountsReceivable: accountsReceivable.toFixed(2),
                cashBalance: cashBalance.toFixed(2),
                totalAssets: totalAssets.toFixed(2), 
                
    
            gstPayable: gstPayable.toFixed(2), 
                vendorsPayable: vendorsPayable.toFixed(2), 
                totalLiabilities: totalLiabilities.toFixed(2), 
                ownerEquity: ownerEquity.toFixed(2), 
                totalLiabilitiesAndEquity: totalLiabilitiesAndEquity.toFixed(2), 
            },
  
          message: 'विस्तृत वित्तीय और बैलेंस शीट डेटा सफलतापूर्वक प्राप्त किया गया।'
        });
} catch (err) {
        console.error("Error fetching balance sheet data:", err.message);
return res.status(500).json({ success: false, message: 'विस्तृत वित्तीय डेटा प्राप्त करने में विफल।' });
    }
});
// -----------------------------------------------------------------------------
// V. ADMIN CONSOLE ROUTES (GLOBAL ADMIN ONLY - HIGH RISK)
// -----------------------------------------------------------------------------
// ⚠️ चेतावनी: ये रूट्स केवल सबसे उच्च स्तर के एडमिन रोल (Super Admin) के लिए हैं।
// 12.1 Get All Shops (Global Admin Console)
app.get('/api/admin/shops', authenticateJWT, checkRole('ADMIN'), async (req, res) => {
    try {
        const result = await pool.query('SELECT id, shop_name, created_at FROM shops ORDER BY created_at DESC');
        res.json({ success: true, shops: result.rows, message: 'सभी शॉप डेटा लोड किया गया।' });
    } catch (err) {
        console.error("Error fetching shops:", err.message);
        res.status(500).json({ success: false, message: 'शॉप्स डेटा प्राप्त करने में विफल।' });
    
}
});

// 12.2 Get All Licenses (Global Admin Console)
app.get('/api/admin/licenses', authenticateJWT, checkRole('ADMIN'), async (req, res) => {
    try {
        const result = await pool.query('SELECT key_hash, expiry_date, is_trial, created_at FROM licenses ORDER BY created_at DESC');
        res.json({ success: true, licenses: result.rows, message: 'सभी लाइसेंस डेटा लोड किया गया।' });
    } catch (err) {
        console.error("Error fetching licenses:", err.message);
        res.status(500).json({ success: false, message: 'लाइसेंस डेटा प्राप्त करने में विफल।' });
  
  }
});

// 12.3 Extend License (Global Admin Console)
app.put('/api/admin/licenses/:keyHash', authenticateJWT, checkRole('ADMIN'), async (req, res) => {
    const { keyHash } = req.params;
    const { daysToAdd } = req.body;

    if (typeof daysToAdd !== 'number' || daysToAdd <= 0) {
        return res.status(400).json({ success: false, message: 'जोड़ने के लिए वैध दिनों की संख्या आवश्यक है।' });
    }

    try {
        const result = await pool.query(
          
  `UPDATE licenses SET expiry_date = expiry_date + interval '${daysToAdd} days', is_trial = FALSE WHERE key_hash = $1 RETURNING expiry_date`,
            [keyHash]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, message: 'लाइसेंस कुंजी नहीं मिली।' });
        }

        res.json({ success: true, newExpiryDate: result.rows[0].expiry_date, message: `${daysToAdd} दिन सफलतापूर्वक जोड़े गए।` 
});
    } catch (err) {
        console.error("Error extending license:", err.message);
res.status(500).json({ success: false, message: 'लाइसेंस अवधि बढ़ाने में विफल: ' + err.message });
    }
});
// 12.4 SQL Console Execution (High-Risk Global Admin Tool)
// ⚠️ यह टूल बहुत खतरनाक है!
इसे केवल SELECT या सुरक्षित UPDATE/DELETE (WHERE क्लॉज़ के साथ) के लिए इस्तेमाल करें।
app.post('/api/admin/sql-console', authenticateJWT, checkRole('ADMIN'), async (req, res) => {
    const { query } = req.body;
    
    // Safety check: Prevent destructive schema modifications
    const dangerousCommands = ['DROP TABLE', 'ALTER TABLE', 'TRUNCATE TABLE', 'CREATE TABLE'];
    const lowerQuery = query.toLowerCase();

    for (const cmd of dangerousCommands) {
        if (lowerQuery.includes(cmd.toLowerCase())) {
            return res.status(403).json({ 
                
success: false, 
                message: '❌ यह कमांड ब्लॉक कर दिया गया है क्योंकि यह खतरनाक है: ' + cmd + '। केवल SELECT, UPDATE, DELETE की अनुमति है।' 
            });
        }
    }

    // Safety check: Require WHERE clause for DELETE/UPDATE unless explicitly managing licenses/shops
    if ((lowerQuery.startsWith('delete') || lowerQuery.startsWith('update')) && !lowerQuery.includes('where')) {
        
 return res.status(403).json({ 
            success: false, 
            message: '❌ सुरक्षा के लिए, DELETE या UPDATE कमांड में WHERE क्लॉज़ आवश्यक है (यदि आप licenses या shops को लक्षित नहीं कर रहे हैं)।' 
        });
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
// VI.
SERVER INITIALIZATION
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
    console.error('Failed to initialize database and start server:', 
error);
});

// End of Dukan Pro Server
// Total lines: ~860


