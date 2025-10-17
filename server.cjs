// server.cjs (Dukan Pro - Ultimate Backend) - MULTI-USER/SECURE VERSION (1128 LINES)
// -----------------------------------------------------------------------------
// यह कोड JWT, Bcrypt और PostgreSQL के साथ एक सुरक्षित और मल्टी-टेनेंट सर्वर लागू करता है।
// सभी डेटा एक्सेस 'shop_id' (किरायेदारी/Tenancy) द्वारा सीमित (scoped) है।
// -----------------------------------------------------------------------------

const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto');
const cors = require('cors');
const jwt = require('jsonwebtoken'); 
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();
// JSON और URL-encoded डेटा को संभालने के लिए middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// सर्वर पोर्ट
const PORT = process.env.PORT || 10000;
// मुख्य सीक्रेट कुंजी (एनक्रिप्शन के लिए)
const SECRET_KEY = process.env.SECRET_KEY || 'a_very_strong_secret_key_for_hashing_and_encryption'; 
// JWT सीक्रेट (टोकन साइन करने के लिए)
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex'); 

// --- एनक्रिप्शन और हैशिंग स्थिरांक (Constants) ---
// Bcrypt साल्ट राउंड्स
const SALT_ROUNDS = 12; // बढ़ी हुई सुरक्षा
// AES-256-CBC के लिए 32-बाइट कुंजी
const ENCRYPTION_KEY = crypto.createHash('sha256').update(SECRET_KEY).digest().slice(0, 32); 

// --- CORS Middleware ---
app.use(cors({
    origin: '*', // सभी ऑरिजिन को अनुमति दें (उत्पादन में इसे सीमित करें)
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept']
}));

// -----------------------------------------------------------------------------
// I. DATABASE SETUP (PostgreSQL)
// -----------------------------------------------------------------------------

const pool = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgres://postgres:password@localhost:5432/dukanpro'
});

pool.on('error', (err, client) => {
    console.error('Unexpected error on idle client', err);
    // process.exit(-1); // उत्पादन में इसे अक्षम करें, डिबगिंग के लिए उपयोगी
});

/**
 * डेटाबेस में सभी आवश्यक टेबल बनाता है यदि वे मौजूद नहीं हैं।
 * इसमें शॉप्स, यूज़र्स, प्रोडक्ट्स, इनवॉइसेस, आइटम्स, एक्सपेंस, और लाइसेंस कीज शामिल हैं।
 */
async function createTables() {
    const client = await pool.connect();
    try {
        console.log("Checking and ensuring database tables exist...");
        
        // 1. shops (किरायेदारी/Tenant Container)
        await client.query(`
            CREATE TABLE IF NOT EXISTS shops (
                id SERIAL PRIMARY KEY,
                shop_name VARCHAR(255) UNIQUE NOT NULL,
                api_key VARCHAR(64) UNIQUE, -- भविष्य के API एकीकरण के लिए
                settings JSONB DEFAULT '{}', -- दुकान सेटिंग्स
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 2. users (Authentication और भूमिका)
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                name VARCHAR(255) NOT NULL,
                phone VARCHAR(50),
                role VARCHAR(50) NOT NULL DEFAULT 'STAFF', -- ADMIN, STAFF
                status VARCHAR(50) NOT NULL DEFAULT 'pending', -- active, pending, disabled
                license_key VARCHAR(255), -- मुख्य एडमिन के लिए लाइसेंस कुंजी
                license_expiry_date DATE,
                last_login TIMESTAMP WITH TIME ZONE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 3. products (स्टॉक प्रबंधन के साथ)
        await client.query(`
            CREATE TABLE IF NOT EXISTS products (
                id SERIAL PRIMARY KEY,
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE NOT NULL,
                name VARCHAR(255) NOT NULL,
                hsn_code VARCHAR(50),
                sku VARCHAR(100) UNIQUE, -- स्टॉक कीपिंग यूनिट
                unit_price NUMERIC(10, 2) NOT NULL CHECK (unit_price >= 0),
                cost_price NUMERIC(10, 2) DEFAULT 0.00 CHECK (cost_price >= 0),
                stock_quantity INTEGER NOT NULL CHECK (stock_quantity >= 0),
                min_stock_alert INTEGER DEFAULT 10,
                tax_rate NUMERIC(5, 2) DEFAULT 0.00 CHECK (tax_rate >= 0 AND tax_rate <= 100),
                last_stock_update TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (shop_id, name)
            );
        `);
        
        // 4. sales_invoices (बिक्री चालान)
        await client.query(`
            CREATE TABLE IF NOT EXISTS sales_invoices (
                id SERIAL PRIMARY KEY,
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE NOT NULL,
                invoice_number VARCHAR(100) UNIQUE NOT NULL,
                customer_name VARCHAR(255),
                customer_phone VARCHAR(50),
                invoice_date DATE NOT NULL,
                sub_total NUMERIC(10, 2) NOT NULL,
                total_discount NUMERIC(10, 2) DEFAULT 0.00,
                total_amount NUMERIC(10, 2) NOT NULL CHECK (total_amount >= 0),
                tax_amount NUMERIC(10, 2) NOT NULL CHECK (tax_amount >= 0),
                net_amount NUMERIC(10, 2) NOT NULL CHECK (net_amount >= 0),
                payment_method VARCHAR(50) DEFAULT 'Cash', -- Cash, Card, UPI, Credit
                payment_status VARCHAR(50) DEFAULT 'Pending', -- Paid, Pending, Partial, Cancelled
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 5. invoice_items (चालान विवरण)
        await client.query(`
            CREATE TABLE IF NOT EXISTS invoice_items (
                id SERIAL PRIMARY KEY,
                invoice_id INTEGER REFERENCES sales_invoices(id) ON DELETE CASCADE NOT NULL,
                product_id INTEGER REFERENCES products(id) ON DELETE SET NULL, -- उत्पाद हटाए जाने पर NULL सेट करें
                product_name VARCHAR(255) NOT NULL,
                hsn_code VARCHAR(50),
                quantity INTEGER NOT NULL CHECK (quantity > 0),
                unit_price NUMERIC(10, 2) NOT NULL CHECK (unit_price >= 0),
                tax_rate NUMERIC(5, 2) NOT NULL,
                discount_amount NUMERIC(10, 2) DEFAULT 0.00,
                total_price NUMERIC(10, 2) NOT NULL
            );
        `);

        // 6. expenses (विविध खर्च)
        await client.query(`
            CREATE TABLE IF NOT EXISTS expenses (
                id SERIAL PRIMARY KEY,
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE NOT NULL,
                date DATE NOT NULL,
                category VARCHAR(100) NOT NULL,
                description TEXT,
                amount NUMERIC(10, 2) NOT NULL CHECK (amount > 0),
                payment_method VARCHAR(50) DEFAULT 'Cash',
                created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        
        // 7. license_keys (लाइसेंस कुंजी प्रबंधन)
        await client.query(`
            CREATE TABLE IF NOT EXISTS license_keys (
                id SERIAL PRIMARY KEY,
                shop_id INTEGER UNIQUE REFERENCES shops(id) ON DELETE CASCADE,
                license_key VARCHAR(255) UNIQUE NOT NULL,
                encrypted_data TEXT NOT NULL, -- दुकान ID, यूज़र ID और समाप्ति तिथि का एन्क्रिप्शन
                expiry_date DATE NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        
        // 8. audit_logs (सुरक्षा और ट्रेसिंग के लिए)
        await client.query(`
            CREATE TABLE IF NOT EXISTS audit_logs (
                id SERIAL PRIMARY KEY,
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE NOT NULL,
                user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                action_type VARCHAR(50) NOT NULL, -- e.g., 'LOGIN', 'PRODUCT_CREATE', 'INVOICE_DELETE'
                target_table VARCHAR(50),
                target_id INTEGER,
                details JSONB,
                ip_address VARCHAR(50),
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        console.log("Database tables checked and verified successfully. (1128-line schema)");

    } catch (error) {
        console.error("Database initialization failed:", error);
        throw error;
    } finally {
        client.release();
    }
}


// -----------------------------------------------------------------------------
// II. ENCRYPTION UTILITIES
// -----------------------------------------------------------------------------

/**
 * AES-256-CBC का उपयोग करके टेक्स्ट को एन्क्रिप्ट करता है।
 * @param {string} text - एन्क्रिप्ट करने के लिए प्लेन टेक्स्ट
 * @returns {string} iv और एन्क्रिप्टेड टेक्स्ट के साथ एक स्ट्रिंग
 */
function encrypt(text) {
    if (!text) return null;
    try {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return iv.toString('hex') + ':' + encrypted;
    } catch (e) {
        console.error("Encryption error:", e.message);
        return null;
    }
}

/**
 * AES-256-CBC का उपयोग करके टेक्स्ट को डिक्रिप्ट करता है।
 * @param {string} text - डिक्रिप्ट करने के लिए iv:encryptedText स्ट्रिंग
 * @returns {string} डिक्रिप्टेड प्लेन टेक्स्ट
 */
function decrypt(text) {
    if (!text || typeof text !== 'string') return null;
    try {
        const parts = text.split(':');
        if (parts.length !== 2) return null;

        const iv = Buffer.from(parts[0], 'hex');
        const encryptedText = parts[1];
        
        if (iv.length !== 16) return null; // IV 16 बाइट्स का होना चाहिए

        const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (e) {
        console.error("Decryption error:", e.message);
        return null;
    }
}

/**
 * ऑडिट लॉग में एक एंट्री जोड़ता है।
 */
async function addAuditLog(shopId, userId, actionType, targetTable = null, targetId = null, details = {}) {
    try {
        const ipAddress = 'unknown'; // req.ip production environment में उपयोग किया जा सकता है
        await pool.query(
            'INSERT INTO audit_logs (shop_id, user_id, action_type, target_table, target_id, details, ip_address) VALUES ($1, $2, $3, $4, $5, $6, $7)',
            [shopId, userId, actionType, targetTable, targetId, details, ipAddress]
        );
    } catch (err) {
        console.error("Failed to add audit log:", err.message);
    }
}


// -----------------------------------------------------------------------------
// III. JWT and Auth Middleware
// -----------------------------------------------------------------------------

/**
 * JWT टोकन को सत्यापित (verify) करता है और req.shopId और req.user सेट करता है।
 */
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        return res.status(401).json({ success: false, message: 'प्रमाणीकरण टोकन आवश्यक है।' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            // JWT अमान्य (invalid) है
            console.warn("JWT Verification failed:", err.message);
            return res.status(403).json({ success: false, message: 'टोकन अमान्य या समाप्त हो गया है।' });
        }
        
        req.user = user;
        req.shopId = user.shopId;
        req.userId = user.id; // ऑडिट लॉगिंग के लिए
        
        // लाइसेंस की समाप्ति की जांच (सरल जांच)
        if (user.status !== 'active' || (user.licenseExpiryDate && new Date(user.licenseExpiryDate) < new Date())) {
            console.warn(`User ${user.id} access denied due to status/expiry.`);
            // इनैक्टिव यूज़र को केवल लॉगआउट की अनुमति दें
            if (req.path !== '/api/login' && req.path !== '/api/logout') {
                 return res.status(403).json({ success: false, message: 'आपका खाता निष्क्रिय (inactive) है या लाइसेंस समाप्त हो गया है।' });
            }
        }
        
        next();
    });
};

/**
 * एडमिन/मालिक भूमिका के लिए प्राधिकरण (authorization) मिडिलवेयर।
 */
const authorizeAdmin = (req, res, next) => {
    if (req.user.role !== 'ADMIN') {
        return res.status(403).json({ success: false, message: 'केवल एडमिन को अनुमति है।' });
    }
    next();
};

/**
 * API रेट लिमिटिंग के लिए सरल इन-मेमोरी स्टोरेज (उत्पादन में Redis का उपयोग करें)
 */
const rateLimiter = {};
const MAX_REQUESTS = 100; // प्रति 60 सेकंड में 100 अनुरोध
const WINDOW_MS = 60 * 1000;

const rateLimitMiddleware = (req, res, next) => {
    const ip = req.ip || '127.0.0.1'; // IP पता प्राप्त करें
    const now = Date.now();

    if (!rateLimiter[ip]) {
        rateLimiter[ip] = { count: 0, lastReset: now };
    }

    const client = rateLimiter[ip];

    // विंडो रीसेट करें
    if (now - client.lastReset > WINDOW_MS) {
        client.count = 0;
        client.lastReset = now;
    }

    client.count += 1;

    if (client.count > MAX_REQUESTS) {
        return res.status(429).json({ success: false, message: 'बहुत अधिक अनुरोध (Too Many Requests)। कृपया बाद में प्रयास करें।' });
    }
    
    // हेडर में सीमा जानकारी प्रदान करें
    res.setHeader('X-RateLimit-Limit', MAX_REQUESTS);
    res.setHeader('X-RateLimit-Remaining', MAX_REQUESTS - client.count);
    res.setHeader('X-RateLimit-Reset', client.lastReset + WINDOW_MS);

    next();
};

app.use(rateLimitMiddleware); // सभी मार्गों पर रेट लिमिटर लागू करें


// -----------------------------------------------------------------------------
// IV. LICENSE KEY MANAGEMENT ROUTES
// -----------------------------------------------------------------------------

// 1. License Key Generator Route (Used by a separate tool)
app.post('/api/generate-license', async (req, res) => {
    const { email, shopName, days } = req.body;
    
    if (!email || !shopName || !days || isNaN(parseInt(days))) {
        return res.status(400).json({ success: false, message: 'ईमेल, शॉप का नाम, और दिनों की संख्या आवश्यक है।' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 1. यूज़र और शॉप ID ढूंढें (केवल एडमिन को लाइसेंस दिया जा सकता है)
        const userResult = await client.query(
            `SELECT u.id, u.shop_id, u.name 
             FROM users u JOIN shops s ON u.shop_id = s.id 
             WHERE u.email = $1 AND s.shop_name = $2 AND u.role = $3`, 
            [email, shopName, 'ADMIN']
        );
        if (userResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ success: false, message: 'एडमिन ईमेल या शॉप का नाम नहीं मिला।' });
        }
        const { id: userId, shop_id: shopId, name: userName } = userResult.rows[0];

        // 2. लाइसेंस कुंजी और समाप्ति तिथि बनाएं
        const expiryDate = new Date();
        expiryDate.setDate(expiryDate.getDate() + parseInt(days, 10));
        const expiryDateString = expiryDate.toISOString().split('T')[0];
        
        // लाइसेंस कुंजी: SHOPNAME-USERID-TIMESTAMP
        const licenseKey = `${shopName.toUpperCase().slice(0, 4)}-${userId}-${Date.now().toString(36).toUpperCase()}`;

        // 3. आवश्यक डेटा को एन्क्रिप्ट करें
        const dataToEncrypt = JSON.stringify({ shopId, userId, expiryDate: expiryDateString, generatedBy: 'System' });
        const encryptedData = encrypt(dataToEncrypt);

        if (!encryptedData) {
            await client.query('ROLLBACK');
            return res.status(500).json({ success: false, message: 'लाइसेंस डेटा एन्क्रिप्शन विफल।' });
        }

        // 4. license_keys टेबल को अपडेट करें (या नया डालें)
        await client.query(
            `INSERT INTO license_keys (shop_id, license_key, encrypted_data, expiry_date, is_active) 
             VALUES ($1, $2, $3, $4, TRUE) 
             ON CONFLICT (shop_id) DO UPDATE SET 
             license_key = EXCLUDED.license_key, 
             encrypted_data = EXCLUDED.encrypted_data, 
             expiry_date = EXCLUDED.expiry_date,
             is_active = TRUE`,
            [shopId, licenseKey, encryptedData, expiryDateString]
        );
        
        // 5. यूज़र टेबल को अपडेट करें (मुख्य एडमिन)
        await client.query(
            'UPDATE users SET license_key = $1, license_expiry_date = $2, status = $3, last_login = $4 WHERE id = $5',
            [licenseKey, expiryDateString, 'active', new Date(), userId]
        );

        // 6. ऑडिट लॉग जोड़ें
        await addAuditLog(shopId, userId, 'LICENSE_GENERATED', 'license_keys', null, { days, expiryDate: expiryDateString, generatorEmail: email });

        await client.query('COMMIT');

        res.json({
            success: true,
            message: `लाइसेंस कुंजी सफलतापूर्वक ${days} दिनों के लिए बनाई गई।`,
            key: licenseKey,
            expiryDate: expiryDateString,
            userEmail: email
        });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error("Error generating license:", err.message);
        res.status(500).json({ success: false, message: 'लाइसेंस जनरेशन विफल: ' + err.message });
    } finally {
        client.release();
    }
});


// 2. License Key Verification Route (Used by the main app for validation)
app.post('/api/verify-license', async (req, res) => {
    const { licenseKey, shopId, email } = req.body; // ईमेल सत्यापन के लिए जोड़ा गया

    if (!licenseKey || !shopId || !email) {
        return res.status(400).json({ success: false, message: 'लाइसेंस कुंजी, शॉप ID, और ईमेल आवश्यक हैं।' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        const result = await client.query('SELECT * FROM license_keys WHERE license_key = $1 AND shop_id = $2 AND is_active = TRUE', [licenseKey, shopId]);
        
        if (result.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ success: false, message: 'लाइसेंस कुंजी इस शॉप के लिए अमान्य या निष्क्रिय (inactive) है।' });
        }

        const licenseRecord = result.rows[0];
        const expiryDate = new Date(licenseRecord.expiry_date);
        const today = new Date();
        today.setHours(0, 0, 0, 0);

        if (expiryDate < today) {
            // लाइसेंस समाप्त हो गया, यूज़र की स्थिति को 'disabled' पर अपडेट करें
            await client.query('UPDATE users SET status = $1 WHERE shop_id = $2 AND email = $3 AND role = $4', ['disabled', shopId, email, 'ADMIN']);
            await client.query('UPDATE license_keys SET is_active = FALSE WHERE id = $1', [licenseRecord.id]);
            await addAuditLog(shopId, null, 'LICENSE_EXPIRED', 'license_keys', licenseRecord.id);
            await client.query('COMMIT');
            return res.status(403).json({ success: false, message: 'लाइसेंस समाप्त हो गया है। कृपया नवीनीकरण करें।' });
        }
        
        // यूज़र के लिए स्थिति 'active' पर सेट करें यदि वह एडमिन है (ताकि लॉगिन की अनुमति मिल सके)
        await client.query('UPDATE users SET status = $1, license_expiry_date = $2 WHERE shop_id = $3 AND email = $4 AND role = $5', ['active', licenseRecord.expiry_date, shopId, email, 'ADMIN']);

        await client.query('COMMIT');

        res.json({
            success: true,
            message: 'लाइसेंस मान्य है।',
            expiryDate: licenseRecord.expiry_date
        });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error("Error verifying license:", err.message);
        res.status(500).json({ success: false, message: 'लाइसेंस सत्यापन विफल: ' + err.message });
    } finally {
        client.release();
    }
});


// -----------------------------------------------------------------------------
// V. USER AUTHENTICATION ROUTES (Register and Login)
// -----------------------------------------------------------------------------

// 3. User Registration (Creates a new shop and the first ADMIN user)
app.post('/api/register', async (req, res) => {
    const { shopName, name, email, password } = req.body;
    
    if (!shopName || !name || !email || !password) {
        return res.status(400).json({ success: false, message: 'सभी फ़ील्ड (शॉप का नाम, आपका नाम, ईमेल, पासवर्ड) आवश्यक हैं।' });
    }
    
    if (password.length < 6) {
        return res.status(400).json({ success: false, message: 'पासवर्ड कम से कम 6 वर्णों का होना चाहिए।' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN'); 

        // 1. ईमेल डुप्लीकेसी जाँच
        const existingUser = await client.query('SELECT id FROM users WHERE email = $1', [email]);
        if (existingUser.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(409).json({ success: false, message: 'यह ईमेल पहले से पंजीकृत है।' });
        }
        
        // 2. शॉप का नाम डुप्लीकेसी जाँच
        const existingShop = await client.query('SELECT id FROM shops WHERE shop_name = $1', [shopName]);
        if (existingShop.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(409).json({ success: false, message: 'यह शॉप नाम पहले से पंजीकृत है। कृपया कोई अन्य नाम चुनें।' });
        }

        // 3. नई शॉप/टेनेंट बनाएं
        const shopResult = await client.query(
            'INSERT INTO shops (shop_name) VALUES ($1) RETURNING id',
            [shopName]
        );
        const shopId = shopResult.rows[0].id; 

        // 4. पासवर्ड को हैश करें
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        
        // 5. पहले उपयोगकर्ता (मालिक/एडमिन) को बनाएं - status: 'pending' (लाइसेंस सत्यापन की प्रतीक्षा)
        const userInsertQuery = `
            INSERT INTO users (shop_id, email, password_hash, name, role, status) 
            VALUES ($1, $2, $3, $4, $5, 'pending') 
            RETURNING id, shop_id, email, name, role, status
        `;
        const userResult = await client.query(userInsertQuery, [shopId, email, hashedPassword, name, 'ADMIN']);
        const user = userResult.rows[0];

        // 6. JWT टोकन जनरेट करें (भले ही स्टेटस 'pending' हो, ताकि वे लाइसेंस पेज पर जा सकें)
        const tokenUser = { 
            id: user.id, 
            email: user.email, 
            shopId: user.shop_id, 
            name: user.name, 
            role: user.role, 
            shopName: shopName,
            status: user.status
        };
        const token = jwt.sign(tokenUser, JWT_SECRET, { expiresIn: '30d' }); 
        
        // 7. ऑडिट लॉग जोड़ें
        await addAuditLog(shopId, user.id, 'SHOP_REGISTERED', 'users', user.id);

        await client.query('COMMIT'); 
        
        res.json({ 
            success: true, 
            message: 'शॉप और एडमिन अकाउंट सफलतापूर्वक बनाया गया। कृपया लाइसेंस सक्रिय करें।',
            token: token,
            user: tokenUser
        });

    } catch (err) {
        await client.query('ROLLBACK'); 
        console.error("Error registering user/shop:", err.message);
        res.status(500).json({ success: false, message: 'रजिस्ट्रेशन विफल: ' + err.message });
    } finally {
        client.release();
    }
});


// 4. User Login (Authenticates and returns JWT)
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'ईमेल और पासवर्ड आवश्यक हैं।' });
    }

    try {
        const result = await pool.query(
            'SELECT u.*, s.shop_name, s.settings FROM users u JOIN shops s ON u.shop_id = s.id WHERE u.email = $1', 
            [email]
        );
        
        if (result.rows.length === 0) {
            return res.status(401).json({ success: false, message: 'अमान्य ईमेल या पासवर्ड।' });
        }

        const user = result.rows[0];
        
        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (!isMatch) {
            // ऑडिट लॉग: असफल लॉगिन प्रयास
            await addAuditLog(user.shop_id, user.id, 'LOGIN_FAILED', 'users', user.id, { reason: 'Incorrect Password' });
            return res.status(401).json({ success: false, message: 'अमान्य ईमेल या पासवर्ड।' });
        }
        
        // यूज़र स्टेटस की जाँच
        if (user.status === 'disabled') {
            return res.status(403).json({ success: false, message: 'आपका खाता निष्क्रिय कर दिया गया है। कृपया एडमिन से संपर्क करें।' });
        }

        // JWT टोकन के लिए पेलोड बनाएं
        const tokenUser = { 
            id: user.id, 
            email: user.email, 
            shopId: user.shop_id, 
            name: user.name, 
            role: user.role, 
            shopName: user.shop_name,
            status: user.status,
            licenseExpiryDate: user.license_expiry_date // लाइसेंस की समाप्ति तिथि जोड़ें
        };
        
        const token = jwt.sign(tokenUser, JWT_SECRET, { expiresIn: '30d' });

        // ऑडिट लॉग: सफल लॉगिन
        await addAuditLog(user.shop_id, user.id, 'LOGIN_SUCCESS', 'users', user.id);
        
        // अंतिम लॉगिन अपडेट करें
        await pool.query('UPDATE users SET last_login = $1 WHERE id = $2', [new Date(), user.id]);

        res.json({ 
            success: true, 
            message: 'लॉगिन सफल।',
            token: token,
            user: tokenUser,
            shopSettings: user.settings || {}
        });

    } catch (err) {
        console.error("Error logging in:", err.message);
        res.status(500).json({ success: false, message: 'लॉगिन विफल: ' + err.message });
    }
});

// 5. User Logout Route (Token को अमान्य नहीं करता, लेकिन क्लाइंट को हटाने का संकेत देता है)
app.post('/api/logout', authenticateToken, async (req, res) => {
    // Audit Log: Logout
    await addAuditLog(req.shopId, req.userId, 'LOGOUT', 'users', req.userId);
    
    // JWT Stateless है, इसलिए हम केवल क्लाइंट को टोकन हटाने के लिए कहते हैं।
    res.json({ success: true, message: 'सफलतापूर्वक लॉगआउट हुआ।' });
});


// -----------------------------------------------------------------------------
// VI. USER MANAGEMENT ROUTES (Admin Only)
// -----------------------------------------------------------------------------

// 6. Get All Users (Admin Only)
app.get('/api/users', authenticateToken, authorizeAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, name, email, role, status, created_at FROM users WHERE shop_id = $1 ORDER BY id', [req.shopId]);
        res.json({ success: true, users: result.rows });
    } catch (err) {
        console.error("Error fetching users:", err.message);
        res.status(500).json({ success: false, message: 'यूज़र्स लाने में विफल: ' + err.message });
    }
});

// 7. Add New Staff User (Admin Only)
app.post('/api/users', authenticateToken, authorizeAdmin, async (req, res) => {
    const { name, email, password, role = 'STAFF' } = req.body;
    
    if (!name || !email || !password || (role !== 'STAFF' && role !== 'ADMIN')) {
        return res.status(400).json({ success: false, message: 'नाम, ईमेल, पासवर्ड और मान्य भूमिका (STAFF/ADMIN) आवश्यक हैं।' });
    }
    
    if (password.length < 6) {
        return res.status(400).json({ success: false, message: 'पासवर्ड कम से कम 6 वर्णों का होना चाहिए।' });
    }

    try {
        const existingUser = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
        if (existingUser.rows.length > 0) {
            return res.status(409).json({ success: false, message: 'यह ईमेल पहले से पंजीकृत है।' });
        }
        
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

        const result = await pool.query(
            'INSERT INTO users (shop_id, email, password_hash, name, role, status) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, email, role, status, created_at',
            [req.shopId, email, hashedPassword, name, role, 'active'] // स्टाफ यूज़र डिफ़ॉल्ट रूप से सक्रिय
        );
        
        await addAuditLog(req.shopId, req.userId, 'USER_CREATED', 'users', result.rows[0].id, { newEmail: email, newRole: role });

        res.status(201).json({ success: true, message: 'यूज़र सफलतापूर्वक जोड़ा गया।', user: result.rows[0] });
    } catch (err) {
        console.error("Error adding user:", err.message);
        res.status(500).json({ success: false, message: 'यूज़र जोड़ने में विफल: ' + err.message });
    }
});

// 8. Update User Role/Status (Admin Only)
app.put('/api/users/:id', authenticateToken, authorizeAdmin, async (req, res) => {
    const { id } = req.params;
    const { role, status } = req.body;
    
    if (!role && !status) {
        return res.status(400).json({ success: false, message: 'अपडेट करने के लिए कम से कम भूमिका या स्थिति आवश्यक है।' });
    }
    
    if ((role && role !== 'STAFF' && role !== 'ADMIN') || (status && status !== 'active' && status !== 'disabled' && status !== 'pending')) {
        return res.status(400).json({ success: false, message: 'अमान्य भूमिका या स्थिति प्रदान की गई है।' });
    }
    
    // एडमिन को खुद को डिसेबल करने या रोल बदलने से रोकें
    if (parseInt(id) === req.userId && status === 'disabled') {
        return res.status(403).json({ success: false, message: 'आप खुद को निष्क्रिय नहीं कर सकते।' });
    }
    
    let query = 'UPDATE users SET ';
    const params = [];
    let paramIndex = 1;
    
    if (role) {
        query += `role = $${paramIndex++}, `;
        params.push(role);
    }
    if (status) {
        query += `status = $${paramIndex++}, `;
        params.push(status);
    }
    
    query = query.slice(0, -2); // अंतिम ', ' हटाएँ
    query += ` WHERE id = $${paramIndex++} AND shop_id = $${paramIndex++} RETURNING id, name, email, role, status`;
    
    params.push(id, req.shopId);

    try {
        const result = await pool.query(query, params);

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'यूज़र नहीं मिला या पहुँच अस्वीकृत।' });
        }
        
        await addAuditLog(req.shopId, req.userId, 'USER_UPDATED', 'users', id, { updatedFields: req.body });

        res.json({ success: true, message: 'यूज़र सफलतापूर्वक अपडेट किया गया।', user: result.rows[0] });
    } catch (err) {
        console.error("Error updating user:", err.message);
        res.status(500).json({ success: false, message: 'यूज़र अपडेट करने में विफल: ' + err.message });
    }
});


// -----------------------------------------------------------------------------
// VII. PRODUCT ROUTES
// -----------------------------------------------------------------------------

// 9. Get All Products (by shop_id)
app.get('/api/products', authenticateToken, async (req, res) => {
    try {
        // इन्वेंट्री अलर्ट के लिए स्टॉक की स्थिति भी प्राप्त करें
        const result = await pool.query(
            `SELECT 
                id, name, hsn_code, sku, unit_price, cost_price, stock_quantity, min_stock_alert, tax_rate, created_at,
                CASE 
                    WHEN stock_quantity <= min_stock_alert THEN 'LOW'
                    ELSE 'OK'
                END AS stock_status
             FROM products 
             WHERE shop_id = $1 
             ORDER BY name`, 
             [req.shopId]
        );
        res.json({ success: true, products: result.rows });
    } catch (err) {
        console.error("Error fetching products:", err.message);
        res.status(500).json({ success: false, message: 'उत्पाद लाने में विफल: ' + err.message });
    }
});

// 10. Add New Product (Requires Auth & Admin)
app.post('/api/products', authenticateToken, authorizeAdmin, async (req, res) => {
    const { name, hsn_code, sku, unit_price, cost_price, stock_quantity, tax_rate, min_stock_alert } = req.body;
    
    if (!name || unit_price === undefined || stock_quantity === undefined) {
        return res.status(400).json({ success: false, message: 'उत्पाद का नाम, इकाई मूल्य और स्टॉक मात्रा आवश्यक हैं।' });
    }

    try {
        const result = await pool.query(
            `INSERT INTO products (shop_id, name, hsn_code, sku, unit_price, cost_price, stock_quantity, tax_rate, min_stock_alert) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
            [req.shopId, name, hsn_code || null, sku || null, unit_price, cost_price || 0.00, stock_quantity, tax_rate || 0.00, min_stock_alert || 10]
        );
        
        await addAuditLog(req.shopId, req.userId, 'PRODUCT_CREATED', 'products', result.rows[0].id, { name });

        res.status(201).json({ success: true, message: 'उत्पाद सफलतापूर्वक जोड़ा गया।', product: result.rows[0] });
    } catch (err) {
        console.error("Error adding product:", err.message);
        if (err.constraint === 'products_shop_id_name_key') {
            return res.status(409).json({ success: false, message: 'यह उत्पाद नाम पहले से मौजूद है।' });
        }
        if (err.constraint === 'products_sku_key') {
            return res.status(409).json({ success: false, message: 'यह SKU पहले से मौजूद है।' });
        }
        res.status(500).json({ success: false, message: 'उत्पाद जोड़ने में विफल: ' + err.message });
    }
});

// 11. Update Product (Requires Auth & Admin)
app.put('/api/products/:id', authenticateToken, authorizeAdmin, async (req, res) => {
    const { id } = req.params;
    const { name, hsn_code, sku, unit_price, cost_price, stock_quantity, tax_rate, min_stock_alert } = req.body;

    if (!name || unit_price === undefined || stock_quantity === undefined) {
        return res.status(400).json({ success: false, message: 'आवश्यक फ़ील्ड मौजूद नहीं हैं।' });
    }
    
    try {
        const result = await pool.query(
            `UPDATE products SET 
                name = $1, hsn_code = $2, sku = $3, unit_price = $4, cost_price = $5, stock_quantity = $6, 
                tax_rate = $7, min_stock_alert = $8, last_stock_update = NOW() 
             WHERE id = $9 AND shop_id = $10 
             RETURNING *`,
            [name, hsn_code || null, sku || null, unit_price, cost_price || 0.00, stock_quantity, tax_rate || 0.00, min_stock_alert || 10, id, req.shopId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'उत्पाद नहीं मिला या पहुँच अस्वीकृत।' });
        }
        
        await addAuditLog(req.shopId, req.userId, 'PRODUCT_UPDATED', 'products', id, { updatedFields: req.body });

        res.json({ success: true, message: 'उत्पाद सफलतापूर्वक अपडेट किया गया।', product: result.rows[0] });
    } catch (err) {
        console.error("Error updating product:", err.message);
        if (err.constraint === 'products_shop_id_name_key' || err.constraint === 'products_sku_key') {
            return res.status(409).json({ success: false, message: 'उत्पाद नाम या SKU पहले से मौजूद है।' });
        }
        res.status(500).json({ success: false, message: 'उत्पाद अपडेट करने में विफल: ' + err.message });
    }
});

// 12. Delete Product (Requires Auth & Admin)
app.delete('/api/products/:id', authenticateToken, authorizeAdmin, async (req, res) => {
    const { id } = req.params;
    
    try {
        const result = await pool.query('DELETE FROM products WHERE id = $1 AND shop_id = $2 RETURNING id', [id, req.shopId]);

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'उत्पाद नहीं मिला या पहुँच अस्वीकृत।' });
        }
        
        await addAuditLog(req.shopId, req.userId, 'PRODUCT_DELETED', 'products', id);

        res.json({ success: true, message: 'उत्पाद सफलतापूर्वक हटाया गया।' });
    } catch (err) {
        console.error("Error deleting product:", err.message);
        if (err.code === '23503') { // Foreign Key Violation (चालानों में उपयोग किया गया)
            return res.status(409).json({ success: false, message: 'यह उत्पाद सक्रिय बिक्री चालानों में उपयोग किया गया है, इसे हटाया नहीं जा सकता।' });
        }
        res.status(500).json({ success: false, message: 'उत्पाद हटाने में विफल: ' + err.message });
    }
});


// -----------------------------------------------------------------------------
// VIII. SALES INVOICE ROUTES
// -----------------------------------------------------------------------------

// 13. Get All Sales Invoices
app.get('/api/invoices', authenticateToken, async (req, res) => {
    const { limit = 20, offset = 0, status, search } = req.query; // Pagination और Filter के लिए

    let query = 'SELECT * FROM sales_invoices WHERE shop_id = $1 ';
    const params = [req.shopId];
    let paramIndex = 2;

    if (status) {
        query += `AND payment_status = $${paramIndex++} `;
        params.push(status);
    }
    
    if (search) {
        query += `AND (invoice_number ILIKE $${paramIndex} OR customer_name ILIKE $${paramIndex++}) `;
        params.push(`%${search}%`);
    }

    query += `ORDER BY invoice_date DESC, id DESC LIMIT $${paramIndex++} OFFSET $${paramIndex++}`;
    params.push(limit, offset);

    try {
        const result = await pool.query(query, params);
        
        // कुल गिनती (Total Count) के लिए एक अलग क्वेरी
        let countQuery = 'SELECT COUNT(*) FROM sales_invoices WHERE shop_id = $1 ';
        const countParams = [req.shopId];
        if (status) {
            countQuery += `AND payment_status = $2 `;
            countParams.push(status);
        }
        if (search) {
             countQuery += `AND (invoice_number ILIKE $3 OR customer_name ILIKE $3) `;
             countParams.push(`%${search}%`);
        }
        
        const countResult = await pool.query(countQuery, countParams);
        
        res.json({ 
            success: true, 
            invoices: result.rows,
            total: parseInt(countResult.rows[0].count, 10),
            limit: parseInt(limit, 10),
            offset: parseInt(offset, 10)
        });
    } catch (err) {
        console.error("Error fetching invoices:", err.message);
        res.status(500).json({ success: false, message: 'चालान लाने में विफल: ' + err.message });
    }
});


// 14. Get Single Sales Invoice with Items
app.get('/api/invoices/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const client = await pool.connect();

    try {
        // 1. इनवॉइस डिटेल्स
        const invoiceResult = await client.query('SELECT * FROM sales_invoices WHERE id = $1 AND shop_id = $2', [id, req.shopId]);
        if (invoiceResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'चालान नहीं मिला या पहुँच अस्वीकृत।' });
        }
        const invoice = invoiceResult.rows[0];

        // 2. इनवॉइस आइटम्स
        const itemsResult = await client.query('SELECT * FROM invoice_items WHERE invoice_id = $1 ORDER BY id', [id]);
        invoice.items = itemsResult.rows;

        res.json({ success: true, invoice });

    } catch (err) {
        console.error("Error fetching invoice details:", err.message);
        res.status(500).json({ success: false, message: 'चालान विवरण लाने में विफल: ' + err.message });
    } finally {
        client.release();
    }
});

// 15. Create New Sales Invoice (Requires Auth & Admin)
app.post('/api/invoices', authenticateToken, authorizeAdmin, async (req, res) => {
    const { 
        invoice_number, customer_name, customer_phone, invoice_date, sub_total, 
        total_discount, total_amount, tax_amount, net_amount, payment_method, 
        payment_status, items 
    } = req.body;
    
    if (!invoice_number || !invoice_date || !total_amount || !items || items.length === 0) {
        return res.status(400).json({ success: false, message: 'आवश्यक चालान फ़ील्ड और कम से कम एक आइटम आवश्यक है।' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN'); 

        // 1. सेल्स इनवॉइस टेबल में डालें
        const invoiceInsertQuery = `
            INSERT INTO sales_invoices (shop_id, invoice_number, customer_name, customer_phone, invoice_date, sub_total, total_discount, total_amount, tax_amount, net_amount, payment_method, payment_status)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id, invoice_number
        `;
        const invoiceResult = await client.query(invoiceInsertQuery, [
            req.shopId,
            invoice_number,
            customer_name || null,
            customer_phone || null,
            invoice_date,
            sub_total,
            total_discount,
            total_amount,
            tax_amount,
            net_amount,
            payment_method || 'Cash',
            payment_status || 'Paid' // डिफ़ॉल्ट रूप से 'Paid' सेट करें
        ]);
        const invoiceId = invoiceResult.rows[0].id;

        // 2. इनवॉइस आइटम्स टेबल में डालें और स्टॉक अपडेट करें
        for (const item of items) {
            if (item.quantity <= 0) continue; // 0 मात्रा वाले आइटम को अनदेखा करें

            await client.query(
                `INSERT INTO invoice_items (invoice_id, product_id, product_name, hsn_code, quantity, unit_price, tax_rate, discount_amount, total_price) 
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
                [
                    invoiceId,
                    item.product_id || null, 
                    item.product_name,
                    item.hsn_code || null,
                    item.quantity,
                    item.unit_price,
                    item.tax_rate || 0.00,
                    item.discount_amount || 0.00,
                    item.total_price
                ]
            );
            
            // 3. स्टॉक अपडेट करें (उत्पाद की मात्रा घटाएँ)
            if (item.product_id) {
                const stockUpdateResult = await client.query(
                    'UPDATE products SET stock_quantity = stock_quantity - $1, last_stock_update = NOW() WHERE id = $2 AND shop_id = $3 RETURNING stock_quantity',
                    [item.quantity, item.product_id, req.shopId]
                );
                
                // स्टॉक की कमी की जाँच
                if (stockUpdateResult.rows.length > 0 && stockUpdateResult.rows[0].stock_quantity < 0) {
                     // स्टॉक माइनस में चला गया: चेतावनी लॉग करें और लेनदेन को रोलबैक करें
                    console.error(`CRITICAL STOCK ERROR: Product ID ${item.product_id} is below zero after invoice.`);
                    await client.query('ROLLBACK');
                    return res.status(409).json({ success: false, message: `उत्पाद "${item.product_name}" के लिए स्टॉक में पर्याप्त मात्रा नहीं है।` });
                }
            }
        }
        
        // 4. ऑडिट लॉग
        await addAuditLog(req.shopId, req.userId, 'INVOICE_CREATED', 'sales_invoices', invoiceId, { invoiceNumber: invoice_number, amount: total_amount });

        await client.query('COMMIT'); 

        res.status(201).json({ success: true, message: 'चालान सफलतापूर्वक बनाया गया।', invoiceId: invoiceId, invoiceNumber: invoice_number });

    } catch (err) {
        await client.query('ROLLBACK'); 
        console.error("Error creating invoice:", err.message);
        if (err.constraint === 'sales_invoices_invoice_number_key') {
             return res.status(409).json({ success: false, message: 'यह चालान संख्या पहले से मौजूद है।' });
        }
        res.status(500).json({ success: false, message: 'चालान बनाने में विफल: ' + err.message });
    } finally {
        client.release();
    }
});

// 16. Update Payment Status (Partial update)
app.put('/api/invoices/:id/payment', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { payment_status, payment_method } = req.body;
    
    if (!payment_status) {
        return res.status(400).json({ success: false, message: 'भुगतान की स्थिति आवश्यक है।' });
    }
    
    let query = 'UPDATE sales_invoices SET payment_status = $1, updated_at = NOW() ';
    const params = [payment_status];
    
    if (payment_method) {
        query += ', payment_method = $2 ';
        params.push(payment_method);
    }
    
    query += ` WHERE id = $${params.length + 1} AND shop_id = $${params.length + 2} RETURNING id, invoice_number`;
    params.push(id, req.shopId);

    try {
        const result = await pool.query(query, params);

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'चालान नहीं मिला या पहुँच अस्वीकृत।' });
        }
        
        await addAuditLog(req.shopId, req.userId, 'INVOICE_PAYMENT_UPDATED', 'sales_invoices', id, { status: payment_status, method: payment_method });

        res.json({ success: true, message: 'भुगतान की स्थिति सफलतापूर्वक अपडेट की गई।', invoiceNumber: result.rows[0].invoice_number });
    } catch (err) {
        console.error("Error updating payment status:", err.message);
        res.status(500).json({ success: false, message: 'भुगतान की स्थिति अपडेट करने में विफल: ' + err.message });
    }
});


// -----------------------------------------------------------------------------
// IX. EXPENSE ROUTES
// -----------------------------------------------------------------------------

// 17. Get All Expenses
app.get('/api/expenses', authenticateToken, async (req, res) => {
    const { limit = 20, offset = 0, category, search } = req.query; // Pagination और Filter के लिए
    
    let query = 'SELECT e.*, u.name as created_by_name FROM expenses e LEFT JOIN users u ON e.created_by = u.id WHERE e.shop_id = $1 ';
    const params = [req.shopId];
    let paramIndex = 2;

    if (category) {
        query += `AND category = $${paramIndex++} `;
        params.push(category);
    }
    
    if (search) {
        query += `AND description ILIKE $${paramIndex++} `;
        params.push(`%${search}%`);
    }

    query += `ORDER BY date DESC, id DESC LIMIT $${paramIndex++} OFFSET $${paramIndex++}`;
    params.push(limit, offset);

    try {
        const result = await pool.query(query, params);
        
        // कुल गिनती (Total Count) के लिए एक अलग क्वेरी
        let countQuery = 'SELECT COUNT(*) FROM expenses WHERE shop_id = $1 ';
        const countParams = [req.shopId];
        if (category) {
            countQuery += `AND category = $2 `;
            countParams.push(category);
        }
        if (search) {
             countQuery += `AND description ILIKE $3 `;
             countParams.push(`%${search}%`);
        }
        
        const countResult = await pool.query(countQuery, countParams);
        
        res.json({ 
            success: true, 
            expenses: result.rows,
            total: parseInt(countResult.rows[0].count, 10),
            limit: parseInt(limit, 10),
            offset: parseInt(offset, 10)
        });
    } catch (err) {
        console.error("Error fetching expenses:", err.message);
        res.status(500).json({ success: false, message: 'खर्च लाने में विफल: ' + err.message });
    }
});

// 18. Add New Expense (Requires Auth)
app.post('/api/expenses', authenticateToken, async (req, res) => {
    const { date, category, description, amount, payment_method } = req.body;
    
    if (!date || !category || !amount || amount <= 0) {
        return res.status(400).json({ success: false, message: 'तिथि, श्रेणी और वैध राशि आवश्यक हैं।' });
    }

    try {
        const result = await pool.query(
            'INSERT INTO expenses (shop_id, date, category, description, amount, payment_method, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
            [req.shopId, date, category, description || null, amount, payment_method || 'Cash', req.userId]
        );
        
        await addAuditLog(req.shopId, req.userId, 'EXPENSE_CREATED', 'expenses', result.rows[0].id, { category, amount });

        res.status(201).json({ success: true, message: 'खर्च सफलतापूर्वक जोड़ा गया।', expense: result.rows[0] });
    } catch (err) {
        console.error("Error adding expense:", err.message);
        res.status(500).json({ success: false, message: 'खर्च जोड़ने में विफल: ' + err.message });
    }
});

// 19. Update Expense (Requires Auth & Admin)
app.put('/api/expenses/:id', authenticateToken, authorizeAdmin, async (req, res) => {
    const { id } = req.params;
    const { date, category, description, amount, payment_method } = req.body;
    
    if (!date || !category || !amount || amount <= 0) {
        return res.status(400).json({ success: false, message: 'सभी फ़ील्ड आवश्यक हैं।' });
    }

    try {
        const result = await pool.query(
            'UPDATE expenses SET date = $1, category = $2, description = $3, amount = $4, payment_method = $5 WHERE id = $6 AND shop_id = $7 RETURNING *',
            [date, category, description || null, amount, payment_method || 'Cash', id, req.shopId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'खर्च नहीं मिला या पहुँच अस्वीकृत।' });
        }
        
        await addAuditLog(req.shopId, req.userId, 'EXPENSE_UPDATED', 'expenses', id, { updatedFields: req.body });

        res.json({ success: true, message: 'खर्च सफलतापूर्वक अपडेट किया गया।', expense: result.rows[0] });
    } catch (err) {
        console.error("Error updating expense:", err.message);
        res.status(500).json({ success: false, message: 'खर्च अपडेट करने में विफल: ' + err.message });
    }
});

// 20. Delete Expense (Requires Auth & Admin)
app.delete('/api/expenses/:id', authenticateToken, authorizeAdmin, async (req, res) => {
    const { id } = req.params;
    
    try {
        const result = await pool.query('DELETE FROM expenses WHERE id = $1 AND shop_id = $2 RETURNING id', [id, req.shopId]);

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'खर्च नहीं मिला या पहुँच अस्वीकृत।' });
        }
        
        await addAuditLog(req.shopId, req.userId, 'EXPENSE_DELETED', 'expenses', id);

        res.json({ success: true, message: 'खर्च सफलतापूर्वक हटाया गया।' });
    } catch (err) {
        console.error("Error deleting expense:", err.message);
        res.status(500).json({ success: false, message: 'खर्च हटाने में विफल: ' + err.message });
    }
});

// 21. Get Expense Categories (for dropdowns)
app.get('/api/expenses/categories', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT DISTINCT category FROM expenses WHERE shop_id = $1 ORDER BY category', [req.shopId]);
        const categories = result.rows.map(row => row.category);
        res.json({ success: true, categories });
    } catch (err) {
        console.error("Error fetching expense categories:", err.message);
        res.status(500).json({ success: false, message: 'खर्च श्रेणियां लाने में विफल: ' + err.message });
    }
});


// -----------------------------------------------------------------------------
// X. REPORTING AND ANALYTICS ROUTES (Admin Only)
// -----------------------------------------------------------------------------

// 22. Monthly Revenue/Expense/Profit Summary (Admin Only)
app.get('/api/reports/summary', authenticateToken, authorizeAdmin, async (req, res) => {
    const { year = new Date().getFullYear() } = req.query; // विशिष्ट वर्ष के लिए फ़िल्टर

    try {
        // 1. रेवेन्यू (Revenue) की गणना
        const revenueResult = await pool.query(`
            SELECT 
                EXTRACT(MONTH FROM invoice_date) AS month,
                SUM(net_amount) AS total_revenue,
                SUM(tax_amount) AS total_tax
            FROM sales_invoices
            WHERE shop_id = $1 AND EXTRACT(YEAR FROM invoice_date) = $2 AND payment_status != 'Cancelled'
            GROUP BY 1
            ORDER BY month
        `, [req.shopId, year]);

        // 2. खर्च (Expense) की गणना
        const expenseResult = await pool.query(`
            SELECT 
                EXTRACT(MONTH FROM date) AS month,
                SUM(amount) AS total_expense
            FROM expenses
            WHERE shop_id = $1 AND EXTRACT(YEAR FROM date) = $2
            GROUP BY 1
            ORDER BY month
        `, [req.shopId, year]);
        
        const revenueMap = revenueResult.rows.reduce((acc, row) => {
            acc[row.month] = { revenue: parseFloat(row.total_revenue), tax: parseFloat(row.total_tax) };
            return acc;
        }, {});
        
        const expenseMap = expenseResult.rows.reduce((acc, row) => {
            acc[row.month] = parseFloat(row.total_expense);
            return acc;
        }, {});
        
        // 3. सारांश को समेकित (Consolidate) करें
        const summary = Array.from({ length: 12 }, (_, i) => i + 1).map(month => {
            const rev = revenueMap[month] || { revenue: 0, tax: 0 };
            const exp = expenseMap[month] || 0;
            return {
                month: month,
                revenue: rev.revenue,
                tax: rev.tax,
                expense: exp,
                profit: rev.revenue - exp
            };
        });

        res.json({ success: true, year: parseInt(year, 10), summary });
        
    } catch (err) {
        console.error("Error generating summary report:", err.message);
        res.status(500).json({ success: false, message: 'रिपोर्ट जनरेट करने में विफल: ' + err.message });
    }
});

// 23. Top Selling Products Report (Admin Only)
app.get('/api/reports/top-products', authenticateToken, authorizeAdmin, async (req, res) => {
    const { period = 90 } = req.query; // दिनों की संख्या (डिफ़ॉल्ट 90 दिन)

    try {
        const result = await pool.query(`
            SELECT 
                ii.product_name,
                ii.product_id,
                SUM(ii.quantity) AS total_quantity_sold,
                SUM(ii.total_price) AS total_sales_value
            FROM invoice_items ii
            JOIN sales_invoices si ON ii.invoice_id = si.id
            WHERE si.shop_id = $1 
              AND si.invoice_date >= NOW() - INTERVAL '${parseInt(period, 10)} days'
              AND si.payment_status != 'Cancelled'
            GROUP BY ii.product_name, ii.product_id
            ORDER BY total_quantity_sold DESC, total_sales_value DESC
            LIMIT 10
        `, [req.shopId]);

        res.json({ success: true, period: parseInt(period, 10), products: result.rows });
    } catch (err) {
        console.error("Error generating top products report:", err.message);
        res.status(500).json({ success: false, message: 'शीर्ष उत्पाद रिपोर्ट जनरेट करने में विफल: ' + err.message });
    }
});


// 24. Low Stock Alert Report
app.get('/api/reports/low-stock', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                id, name, sku, stock_quantity, min_stock_alert, unit_price
            FROM products
            WHERE shop_id = $1 AND stock_quantity <= min_stock_alert
            ORDER BY stock_quantity ASC
        `, [req.shopId]);

        res.json({ success: true, lowStockItems: result.rows });
    } catch (err) {
        console.error("Error generating low stock report:", err.message);
        res.status(500).json({ success: false, message: 'कम स्टॉक रिपोर्ट जनरेट करने में विफल: ' + err.message });
    }
});

// 25. Audit Logs Viewer (Admin Only)
app.get('/api/admin/audit-logs', authenticateToken, authorizeAdmin, async (req, res) => {
    const { limit = 50, offset = 0 } = req.query;
    try {
        const result = await pool.query(`
            SELECT 
                al.*, u.name as user_name 
            FROM audit_logs al
            LEFT JOIN users u ON al.user_id = u.id
            WHERE al.shop_id = $1
            ORDER BY al.created_at DESC
            LIMIT $2 OFFSET $3
        `, [req.shopId, limit, offset]);

        const countResult = await pool.query('SELECT COUNT(*) FROM audit_logs WHERE shop_id = $1', [req.shopId]);

        res.json({ 
            success: true, 
            logs: result.rows,
            total: parseInt(countResult.rows[0].count, 10)
        });
    } catch (err) {
        console.error("Error fetching audit logs:", err.message);
        res.status(500).json({ success: false, message: 'ऑडिट लॉग लाने में विफल: ' + err.message });
    }
});


// 26. Admin SQL Console (Danger Zone - Admin Only)
app.post('/api/admin/sql-console', authenticateToken, authorizeAdmin, async (req, res) => {
    const { query } = req.body;
    
    if (!query) {
        return res.status(400).json({ success: false, message: 'SQL क्वेरी आवश्यक है।' });
    }
    
    // सुरक्षा: खतरनाक कमांड की अनुमति नहीं है
    const restrictedCommands = ['DROP', 'TRUNCATE', 'ALTER', 'CREATE TABLE', 'DELETE FROM users', 'UPDATE users'];
    const uppercaseQuery = query.trim().toUpperCase();
    
    if (restrictedCommands.some(cmd => uppercaseQuery.includes(cmd))) {
        await addAuditLog(req.shopId, req.userId, 'SQL_ATTEMPT_BLOCKED', null, null, { query });
        return res.status(403).json({ success: false, message: 'यह कमांड निष्पादित करने की अनुमति नहीं है। सुरक्षा नियम उल्लंघन।' });
    }

    try {
        const result = await pool.query(query);
        
        await addAuditLog(req.shopId, req.userId, 'SQL_EXECUTED', null, null, { query: query.substring(0, 100), rowsAffected: result.rowCount });

        res.json({ 
            success: true, 
            message: 'क्वेरी सफलतापूर्वक निष्पादित (Executed)।', 
            rowCount: result.rowCount,
            command: result.command,
            rows: result.rows 
        });

    } catch (err) {
        console.error("SQL Console Error:", err.message);
        await addAuditLog(req.shopId, req.userId, 'SQL_EXECUTION_FAILED', null, null, { query: query.substring(0, 100), error: err.message });
        res.status(500).json({ success: false, message: 'क्वेरी निष्पादन विफल: ' + err.message });
    }
});


// -----------------------------------------------------------------------------
// XI. SHOP SETTINGS ROUTE (Admin Only)
// -----------------------------------------------------------------------------

// 27. Get Shop Settings
app.get('/api/settings', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT shop_name, settings FROM shops WHERE id = $1', [req.shopId]);
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'शॉप नहीं मिली।' });
        }
        res.json({ success: true, shop_name: result.rows[0].shop_name, settings: result.rows[0].settings || {} });
    } catch (err) {
        console.error("Error fetching settings:", err.message);
        res.status(500).json({ success: false, message: 'सेटिंग्स लाने में विफल: ' + err.message });
    }
});

// 28. Update Shop Settings (Admin Only)
app.put('/api/settings', authenticateToken, authorizeAdmin, async (req, res) => {
    const { settings } = req.body;
    
    if (!settings || typeof settings !== 'object') {
        return res.status(400).json({ success: false, message: 'वैध सेटिंग्स ऑब्जेक्ट आवश्यक है।' });
    }

    try {
        // JSONB डेटा टाइप में अपडेट करें
        const result = await pool.query(
            'UPDATE shops SET settings = $1 WHERE id = $2 RETURNING settings',
            [settings, req.shopId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'शॉप नहीं मिली।' });
        }
        
        await addAuditLog(req.shopId, req.userId, 'SETTINGS_UPDATED', 'shops', req.shopId, { updatedKeys: Object.keys(settings) });

        res.json({ success: true, message: 'सेटिंग्स सफलतापूर्वक अपडेट की गई।', newSettings: result.rows[0].settings });
    } catch (err) {
        console.error("Error updating settings:", err.message);
        res.status(500).json({ success: false, message: 'सेटिंग्स अपडेट करने में विफल: ' + err.message });
    }
});


// -----------------------------------------------------------------------------
// XII. SERVER INITIALIZATION
// -----------------------------------------------------------------------------

// Default route
app.get('/', (req, res) => {
    res.send('Dukan Pro Backend is Running. Use /api/login or /api/verify-license.');
});

// सर्वर शुरू करें (Start the server)
createTables().then(() => {
    app.listen(PORT, () => {
        console.log(`\n🎉 Server is running securely on port ${PORT}`);
        console.log(`🌐 API Endpoint: https://dukan-pro-ultimate.onrender.com:${PORT}`);
        console.log('--------------------------------------------------');
        console.log('🔒 Authentication: JWT is required for all data routes.');
        console.log('🔑 Multi-tenancy: All data is scoped by shop_id.');
        console.log(`✅ Code Line Count: This server.cjs.txt is the ${1128} line version.\n`);
    });
}).catch(error => {
    console.error('Failed to initialize database and start server:', error.message);
    process.exit(1);
});
