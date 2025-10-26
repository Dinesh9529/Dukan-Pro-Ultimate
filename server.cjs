// server.cjs (Dukan Pro - Ultimate Backend) - MULTI-USER/SECURE VERSION (EXTENDED)
// -----------------------------------------------------------------------------
// यह कोड JWT, Bcrypt और PostgreSQL के साथ एक सुरक्षित और मल्टी-टेनेंट सर्वर लागू करता है।
// सभी डेटा एक्सेस 'shop_id' द्वारा सीमित (scoped) है।
// -----------------------------------------------------------------------------
// *****************************************************************************
// * नया अपडेटेड कोड सेक्शन                            *
// *****************************************************************************

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
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
}));

// PostgreSQL Connection Pool Setup
const pool = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgresql://user:password@host:port/database', 
    // आपको अपना वास्तविक कनेक्शन स्ट्रिंग यहाँ या .env फ़ाइल में सेट करना होगा
    ssl: {
        rejectUnauthorized: false,
    },
});

pool.on('error', (err) => {
    console.error('❌ Unexpected error on idle client', err);
    process.exit(-1);
});

// --- Encryption/Decryption Functions (for license keys) ---
function encrypt(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

function decrypt(text) {
    try {
        const parts = text.split(':');
        if (parts.length !== 2) {
            throw new Error('Invalid encrypted format');
        }
        const iv = Buffer.from(parts[0], 'hex');
        const encryptedText = parts[1];
        const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (error) {
        console.error('Decryption failed:', error.message);
        return null;
    }
}

// 🔑 JWT Verification Middleware (सभी सुरक्षित रूट्स के लिए)
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, message: 'अनाधिकृत: टोकन नहीं मिला।' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error('JWT Verification Error:', err.message);
            return res.status(403).json({ success: false, message: 'अवैध या समाप्त टोकन।' });
        }
        req.shopId = user.shopId;
        req.userId = user.userId; // स्टाफ प्रबंधन के लिए
        req.role = user.role; // भूमिका प्रबंधन के लिए
        next();
    });
};

// 🛡️ Role Authorization Middleware (केवल एडमिन के लिए)
const authorizeAdmin = (req, res, next) => {
    if (req.role !== 'admin') {
        return res.status(403).json({ success: false, message: 'अनाधिकृत: केवल एडमिन ही यह कार्रवाई कर सकता है।' });
    }
    next();
};

// I. DATABASE SETUP (टेबल निर्माण)
// -----------------------------------------------------------------------------

async function createTables() {
    console.log('🔄 Checking and creating database tables...');
    try {
        // 1. users table (दुकान के मालिक/कर्मचारी) - 'role' कॉलम जोड़ा गया
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                user_id SERIAL PRIMARY KEY,
                shop_id UUID NOT NULL,
                username VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE,
                role VARCHAR(50) DEFAULT 'admin', -- 'admin' या 'staff' 
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 2. licenses table (लाइसेंस कुंजी)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS licenses (
                license_key VARCHAR(255) PRIMARY KEY,
                shop_id UUID UNIQUE NOT NULL,
                customer_name VARCHAR(255),
                valid_until TIMESTAMP WITH TIME ZONE NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                issued_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 3. products table (उत्पाद) - 'barcode' और 'hsn_code' कॉलम जोड़ा गया
        await pool.query(`
            CREATE TABLE IF NOT EXISTS products (
                product_id SERIAL PRIMARY KEY,
                shop_id UUID NOT NULL REFERENCES users(shop_id),
                name VARCHAR(255) NOT NULL,
                unit VARCHAR(50) NOT NULL,
                quantity INT DEFAULT 0,
                cost_price DECIMAL(10, 2) NOT NULL,
                selling_price DECIMAL(10, 2) NOT NULL,
                tax_rate DECIMAL(5, 2) DEFAULT 0.0,
                barcode VARCHAR(100) UNIQUE, -- बारकोड स्कैनर के लिए
                hsn_code VARCHAR(50), -- GSTR के लिए
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 4. customers table (ग्राहक)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS customers (
                customer_id SERIAL PRIMARY KEY,
                shop_id UUID NOT NULL REFERENCES users(shop_id),
                name VARCHAR(255) NOT NULL,
                phone VARCHAR(20) UNIQUE,
                address TEXT,
                gstin VARCHAR(15), -- GSTR के लिए
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 5. sales table (बिक्री लेनदेन)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS sales (
                sale_id SERIAL PRIMARY KEY,
                shop_id UUID NOT NULL REFERENCES users(shop_id),
                customer_id INT REFERENCES customers(customer_id),
                sale_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                total_amount DECIMAL(10, 2) NOT NULL,
                total_tax DECIMAL(10, 2) DEFAULT 0.0,
                payment_method VARCHAR(50),
                invoice_number VARCHAR(100) UNIQUE,
                is_gstr_applicable BOOLEAN DEFAULT FALSE
            );
        `);

        // 6. sale_items table (बिक्री विवरण)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS sale_items (
                item_id SERIAL PRIMARY KEY,
                sale_id INT NOT NULL REFERENCES sales(sale_id) ON DELETE CASCADE,
                product_id INT NOT NULL REFERENCES products(product_id),
                quantity INT NOT NULL,
                price_per_unit DECIMAL(10, 2) NOT NULL,
                tax_amount DECIMAL(10, 2) NOT NULL,
                cost_price DECIMAL(10, 2) NOT NULL -- P&L गणना के लिए
            );
        `);

        // 7. expenses table (खर्च)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS expenses (
                expense_id SERIAL PRIMARY KEY,
                shop_id UUID NOT NULL REFERENCES users(shop_id),
                description VARCHAR(255) NOT NULL,
                amount DECIMAL(10, 2) NOT NULL,
                expense_date DATE NOT NULL,
                category VARCHAR(100),
                is_gstr_applicable BOOLEAN DEFAULT FALSE -- GSTR इनपुट क्रेडिट के लिए
            );
        `);

        // 8. daily_closings table (दैनिक क्लोजिंग)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS daily_closings (
                closing_id SERIAL PRIMARY KEY,
                shop_id UUID NOT NULL REFERENCES users(shop_id),
                closing_date DATE UNIQUE NOT NULL,
                total_sales DECIMAL(10, 2),
                total_expenses DECIMAL(10, 2),
                cash_in_hand DECIMAL(10, 2),
                notes TEXT,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // *********************************************************************
        // * NEW TABLES FOR EXTENDED FUNCTIONALITY                   *
        // *********************************************************************

        // 9. shop_settings table (दुकान का नाम और लोगो)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS shop_settings (
                shop_id UUID PRIMARY KEY REFERENCES users(shop_id),
                shop_name VARCHAR(255) NOT NULL,
                logo_url TEXT, -- लोगो की URL
                gstin VARCHAR(15),
                address TEXT,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 10. staff table (स्टाफ प्रबंधन - सरल)
        // नोट: मुख्य उपयोगकर्ता डेटा 'users' टेबल में रहता है। यह टेबल केवल अतिरिक्त स्टाफ विवरण रखता है।
        await pool.query(`
            CREATE TABLE IF NOT EXISTS staff (
                staff_user_id INT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
                shop_id UUID NOT NULL REFERENCES users(shop_id),
                designation VARCHAR(100),
                phone VARCHAR(20),
                is_active BOOLEAN DEFAULT TRUE,
                permissions JSONB -- रोल-आधारित एक्सेस कंट्रोल के लिए
            );
        `);

        // 11. purchases table (GSTR और इन्वेंट्री के लिए)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS purchases (
                purchase_id SERIAL PRIMARY KEY,
                shop_id UUID NOT NULL REFERENCES users(shop_id),
                purchase_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                supplier_name VARCHAR(255),
                invoice_number VARCHAR(100) UNIQUE,
                total_amount DECIMAL(10, 2) NOT NULL,
                total_tax DECIMAL(10, 2) DEFAULT 0.0,
                gstin VARCHAR(15), -- सप्लायर का GSTIN
                is_gstr_applicable BOOLEAN DEFAULT FALSE
            );
        `);
        
        // 12. purchase_items table (खरीद विवरण)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS purchase_items (
                p_item_id SERIAL PRIMARY KEY,
                purchase_id INT NOT NULL REFERENCES purchases(purchase_id) ON DELETE CASCADE,
                product_id INT REFERENCES products(product_id),
                product_name VARCHAR(255) NOT NULL,
                quantity INT NOT NULL,
                cost_per_unit DECIMAL(10, 2) NOTFEN,
                tax_amount DECIMAL(10, 2) NOT NULL
            );
        `);

        console.log('✅ Database tables checked/created successfully.');
    } catch (error) {
        console.error('❌ Error creating tables:', error.message);
        throw error;
    }
}

// II. AUTHENTICATION AND LICENSE MANAGEMENT (प्रमाणीकरण और लाइसेंस प्रबंधन)
// -----------------------------------------------------------------------------

// POST /api/register - नए दुकान का रजिस्ट्रेशन
app.post('/api/register', async (req, res) => {
    const { username, password, email, shopName } = req.body;
    if (!username || !password || !email || !shopName) {
        return res.status(400).json({ success: false, message: 'कृपया सभी आवश्यक फ़ील्ड भरें: उपयोगकर्ता नाम, पासवर्ड, ईमेल, और दुकान का नाम।' });
    }

    const shopId = crypto.randomUUID(); // नया शॉप ID
    try {
        const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

        // 1. उपयोगकर्ता को 'admin' के रूप में जोड़ें
        await pool.query(
            'INSERT INTO users (shop_id, username, password_hash, email, role) VALUES ($1, $2, $3, $4, $5)',
            [shopId, username, passwordHash, email, 'admin']
        );
        
        // 2. दुकान की प्रारंभिक सेटिंग्स जोड़ें
        await pool.query(
            'INSERT INTO shop_settings (shop_id, shop_name) VALUES ($1, $2)',
            [shopId, shopName]
        );


        console.log(`✅ New shop registered: ${shopId}, Admin: ${username}`);
        res.json({ success: true, message: 'पंजीकरण सफल। अब लॉगिन करें।' });

    } catch (err) {
        if (err.code === '23505') { // Unique violation error
            return res.status(409).json({ success: false, message: 'उपयोगकर्ता नाम या ईमेल पहले से मौजूद है।' });
        }
        console.error("Error during registration:", err.message);
        res.status(500).json({ success: false, message: 'पंजीकरण विफल: ' + err.message });
    }
});

// POST /api/login - दुकान एडमिन/स्टाफ लॉगिन
app.post('/api/login', async (req, res) => {
    const { username, password, licenseKey } = req.body;
    if (!username || !password || !licenseKey) {
        return res.status(400).json({ success: false, message: 'कृपया उपयोगकर्ता नाम, पासवर्ड और लाइसेंस कुंजी भरें।' });
    }

    try {
        // 1. लाइसेंस कुंजी को डिक्रिप्ट करें
        const decryptedKey = decrypt(licenseKey);
        if (!decryptedKey) {
            return res.status(401).json({ success: false, message: 'अवैध लाइसेंस कुंजी।' });
        }

        const [key, shopIdFromKey] = decryptedKey.split('|');
        if (!shopIdFromKey) {
            return res.status(401).json({ success: false, message: 'अवैध लाइसेंस कुंजी प्रारूप।' });
        }

        // 2. लाइसेंस और दुकान ID को सत्यापित करें
        const licenseResult = await pool.query(
            'SELECT * FROM licenses WHERE license_key = $1 AND shop_id = $2 AND is_active = TRUE',
            [key, shopIdFromKey]
        );

        if (licenseResult.rows.length === 0) {
            return res.status(401).json({ success: false, message: 'लाइसेंस कुंजी अमान्य या निष्क्रिय है।' });
        }

        const license = licenseResult.rows[0];
        if (new Date(license.valid_until) < new Date()) {
            // लाइसेंस निष्क्रिय करें
            await pool.query(
                'UPDATE licenses SET is_active = FALSE WHERE license_key = $1',
                [key]
            );
            return res.status(403).json({ success: false, message: 'लाइसेंस समाप्त हो गया है। कृपया नवीनीकरण करें।' });
        }

        const shopId = shopIdFromKey;

        // 3. उपयोगकर्ता (एडमिन/स्टाफ) को सत्यापित करें
        const userResult = await pool.query(
            'SELECT * FROM users WHERE username = $1 AND shop_id = $2',
            [username, shopId]
        );

        if (userResult.rows.length === 0) {
            return res.status(401).json({ success: false, message: 'उपयोगकर्ता नाम या दुकान ID गलत है।' });
        }

        const user = userResult.rows[0];
        const isPasswordValid = await bcrypt.compare(password, user.password_hash);

        if (!isPasswordValid) {
            return res.status(401).json({ success: false, message: 'गलत पासवर्ड।' });
        }

        // 4. JWT टोकन उत्पन्न करें
        const token = jwt.sign(
            { shopId: user.shop_id, userId: user.user_id, username: user.username, role: user.role }, 
            JWT_SECRET, 
            { expiresIn: '24h' }
        );

        console.log(`✅ User logged in: ${username} (Role: ${user.role}, Shop: ${shopId})`);
        res.json({ success: true, token, role: user.role, shopId: user.shop_id, message: 'सफलतापूर्वक लॉगिन किया गया।' });

    } catch (err) {
        console.error("Error during login:", err.message);
        res.status(500).json({ success: false, message: 'लॉगिन विफल: ' + err.message });
    }
});

// POST /api/verify-license - केवल लाइसेंस कुंजी सत्यापन
app.post('/api/verify-license', async (req, res) => {
    const { licenseKey } = req.body;
    if (!licenseKey) {
        return res.status(400).json({ success: false, message: 'लाइसेंस कुंजी आवश्यक है।' });
    }

    try {
        const decryptedKey = decrypt(licenseKey);
        if (!decryptedKey) {
            return res.status(401).json({ success: false, message: 'अवैध लाइसेंस कुंजी।' });
        }

        const [key, shopIdFromKey] = decryptedKey.split('|');
        if (!shopIdFromKey) {
            return res.status(401).json({ success: false, message: 'अवैध लाइसेंस कुंजी प्रारूप।' });
        }

        const result = await pool.query(
            'SELECT valid_until, is_active FROM licenses WHERE license_key = $1 AND shop_id = $2',
            [key, shopIdFromKey]
        );

        if (result.rows.length === 0 || !result.rows[0].is_active) {
            return res.status(401).json({ success: false, message: 'लाइसेंस अमान्य या निष्क्रिय है।' });
        }

        const validUntil = new Date(result.rows[0].valid_until);
        if (validUntil < new Date()) {
            return res.status(403).json({ success: false, message: 'लाइसेंस समाप्त हो गया है।' });
        }

        res.json({ success: true, message: 'लाइसेंस मान्य है।', validUntil: validUntil.toISOString(), shopId: shopIdFromKey });

    } catch (err) {
        console.error("Error verifying license:", err.message);
        res.status(500).json({ success: false, message: 'लाइसेंस सत्यापन विफल: ' + err.message });
    }
});

// -----------------------------------------------------------------------------
// III. ADMIN/LICENSE KEY GENERATION ROUTES (एडमिन/लाइसेंस कुंजी निर्माण)
// -----------------------------------------------------------------------------

// POST /api/admin/generate-key - एडमिन के लिए लाइसेंस कुंजी उत्पन्न करने हेतु
app.post('/api/admin/generate-key', async (req, res) => {
    // ⚠️ सुरक्षा नोट: इस रूट को सार्वजनिक रूप से उपलब्ध नहीं होना चाहिए।
    // इसे केवल एडमिन पैनल या सुरक्षित वातावरण से ही कॉल किया जाना चाहिए।
    const { customerName, durationDays, shopId, secret } = req.body;
    
    // एक साधारण गुप्त कुंजी जाँच (वास्तविक उत्पादन में JWT Auth का उपयोग करें)
    if (secret !== 'DUKAN_PRO_ADMIN_SECRET') { 
        return res.status(403).json({ success: false, message: 'अनाधिकृत एडमिन एक्सेस।' });
    }

    if (!customerName || !durationDays || !shopId) {
        return res.status(400).json({ success: false, message: 'सभी फ़ील्ड आवश्यक हैं।' });
    }

    const key = crypto.randomBytes(16).toString('hex'); // आधार कुंजी
    const encryptedKey = encrypt(`${key}|${shopId}`); // शॉप ID के साथ एन्क्रिप्ट करें
    const validUntil = new Date();
    validUntil.setDate(validUntil.getDate() + parseInt(durationDays, 10));

    try {
        await pool.query(
            'INSERT INTO licenses (license_key, shop_id, customer_name, valid_until, is_active) VALUES ($1, $2, $3, $4, TRUE) ON CONFLICT (license_key) DO UPDATE SET valid_until = $4, is_active = TRUE',
            [key, shopId, customerName, validUntil.toISOString()]
        );
        
        console.log(`✅ License key generated for Shop: ${shopId}, Customer: ${customerName}`);
        res.json({ 
            success: true, 
            key: encryptedKey, 
            customer: customerName, 
            duration_days: durationDays, 
            valid_until: validUntil.toISOString() 
        });

    } catch (err) {
        console.error("Error generating license key:", err.message);
        res.status(500).json({ success: false, message: 'लाइसेंस कुंजी उत्पन्न करने में विफल: ' + err.message });
    }
});


// -----------------------------------------------------------------------------
// IV. APPLICATION DATA ROUTES (आवेदन डेटा मार्ग) - SECURED
// -----------------------------------------------------------------------------
app.use(authenticateToken); // इसके नीचे के सभी रूट्स सुरक्षित हैं

// *********************************************************************
// * NEW: SHOP SETTINGS AND CONFIGURATION API                *
// *********************************************************************

// POST /api/settings/save - दुकान की सेटिंग्स सहेजें (Logo, Name, GSTIN)
app.post('/api/settings/save', authorizeAdmin, async (req, res) => {
    const shopId = req.shopId;
    const { shopName, logoUrl, gstin, address } = req.body;

    if (!shopName) {
        return res.status(400).json({ success: false, message: 'दुकान का नाम आवश्यक है।' });
    }

    try {
        // shop_settings टेबल में डेटा अपडेट या डालें
        const query = `
            INSERT INTO shop_settings (shop_id, shop_name, logo_url, gstin, address)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (shop_id) DO UPDATE
            SET shop_name = $2, logo_url = $3, gstin = $4, address = $5
            RETURNING *;
        `;
        const result = await pool.query(query, [shopId, shopName, logoUrl || null, gstin || null, address || null]);

        // साथ ही users टेबल में username को भी दुकान का नाम अपडेट कर सकते हैं, यदि आवश्यक हो
        // (परंतु यहाँ हम केवल settings पर फोकस कर रहे हैं)

        console.log(`✅ Shop settings saved for: ${shopId}`);
        res.json({ success: true, message: 'दुकान की सेटिंग्स सफलतापूर्वक सहेजी गईं।', settings: result.rows[0] });
    } catch (err) {
        console.error("Error saving shop settings:", err.message);
        res.status(500).json({ success: false, message: 'सेटिंग्स सहेजने में विफल: ' + err.message });
    }
});

// GET /api/settings/get - दुकान की सेटिंग्स प्राप्त करें (वेबसाइट पर प्रदर्शित करने के लिए)
app.get('/api/settings/get', async (req, res) => {
    const shopId = req.shopId;
    try {
        const result = await pool.query(
            'SELECT shop_name, logo_url, gstin, address FROM shop_settings WHERE shop_id = $1',
            [shopId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'दुकान की सेटिंग्स नहीं मिलीं।' });
        }

        console.log(`✅ Shop settings fetched for: ${shopId}`);
        res.json({ success: true, settings: result.rows[0] });
    } catch (err) {
        console.error("Error fetching shop settings:", err.message);
        res.status(500).json({ success: false, message: 'सेटिंग्स लाने में विफल: ' + err.message });
    }
});

// *********************************************************************
// * NEW: BARCODE SCANNER LOOKUP API                        *
// *********************************************************************

// GET /api/products/barcode/:barcode - बारकोड द्वारा उत्पाद विवरण प्राप्त करें
app.get('/api/products/barcode/:barcode', async (req, res) => {
    const shopId = req.shopId;
    const { barcode } = req.params;

    if (!barcode) {
        return res.status(400).json({ success: false, message: 'बारकोड आवश्यक है।' });
    }

    try {
        const result = await pool.query(
            'SELECT product_id, name, selling_price, quantity, unit, tax_rate, barcode FROM products WHERE shop_id = $1 AND barcode = $2',
            [shopId, barcode]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'इस बारकोड के साथ कोई उत्पाद नहीं मिला।' });
        }

        console.log(`✅ Barcode lookup successful for: ${barcode}`);
        res.json({ success: true, product: result.rows[0] });
    } catch (err) {
        console.error("Error during barcode lookup:", err.message);
        res.status(500).json({ success: false, message: 'बारकोड लुकअप विफल: ' + err.message });
    }
});


// *********************************************************************
// * NEW: STAFF/ROLE MANAGEMENT API (स्टाफ/रोल प्रबंधन)         *
// *********************************************************************

// POST /api/staff/add - नया स्टाफ सदस्य जोड़ें
app.post('/api/staff/add', authorizeAdmin, async (req, res) => {
    const shopId = req.shopId;
    const { username, password, email, designation, phone } = req.body;

    if (!username || !password || !email || !designation) {
        return res.status(400).json({ success: false, message: 'सभी आवश्यक स्टाफ विवरण भरें।' });
    }

    try {
        const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
        
        // 1. users टेबल में नया उपयोगकर्ता (role: staff) जोड़ें
        const userResult = await pool.query(
            'INSERT INTO users (shop_id, username, password_hash, email, role) VALUES ($1, $2, $3, $4, $5) RETURNING user_id',
            [shopId, username, passwordHash, email, 'staff']
        );
        const newUserId = userResult.rows[0].user_id;

        // 2. staff टेबल में अतिरिक्त विवरण जोड़ें
        await pool.query(
            'INSERT INTO staff (staff_user_id, shop_id, designation, phone) VALUES ($1, $2, $3, $4)',
            [newUserId, shopId, designation, phone || null]
        );

        console.log(`✅ New staff member added: ${username}, User ID: ${newUserId}`);
        res.json({ success: true, message: 'स्टाफ सदस्य सफलतापूर्वक जोड़ा गया।' });

    } catch (err) {
        if (err.code === '23505') {
            return res.status(409).json({ success: false, message: 'उपयोगकर्ता नाम या ईमेल पहले से मौजूद है।' });
        }
        console.error("Error adding staff:", err.message);
        res.status(500).json({ success: false, message: 'स्टाफ सदस्य जोड़ने में विफल: ' + err.message });
    }
});

// GET /api/staff/list - सभी स्टाफ सदस्यों की सूची (एडमिन को छोड़कर)
app.get('/api/staff/list', authorizeAdmin, async (req, res) => {
    const shopId = req.shopId;
    try {
        const query = `
            SELECT 
                u.user_id, u.username, u.email, u.role, 
                s.designation, s.phone, s.is_active, s.permissions
            FROM users u
            JOIN staff s ON u.user_id = s.staff_user_id
            WHERE u.shop_id = $1 AND u.role = 'staff'
            ORDER BY u.user_id;
        `;
        const result = await pool.query(query, [shopId]);

        console.log(`✅ Fetched ${result.rows.length} staff members.`);
        res.json({ success: true, staff: result.rows });
    } catch (err) {
        console.error("Error fetching staff list:", err.message);
        res.status(500).json({ success: false, message: 'स्टाफ सूची लाने में विफल: ' + err.message });
    }
});

// PUT /api/staff/update/:userId - स्टाफ सदस्य अपडेट करें
app.put('/api/staff/update/:userId', authorizeAdmin, async (req, res) => {
    const shopId = req.shopId;
    const staffUserId = req.params.userId;
    const { email, designation, phone, isActive, permissions } = req.body;

    try {
        // 1. users टेबल में ईमेल अपडेट करें
        if (email) {
            await pool.query(
                'UPDATE users SET email = $1 WHERE user_id = $2 AND shop_id = $3 AND role = \'staff\'',
                [email, staffUserId, shopId]
            );
        }

        // 2. staff टेबल में विवरण अपडेट करें
        const result = await pool.query(
            'UPDATE staff SET designation = $1, phone = $2, is_active = $3, permissions = $4 WHERE staff_user_id = $5 AND shop_id = $6 RETURNING *',
            [designation || null, phone || null, isActive, permissions || null, staffUserId, shopId]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, message: 'स्टाफ सदस्य नहीं मिला या वह एडमिन है।' });
        }

        console.log(`✅ Staff member updated: User ID ${staffUserId}`);
        res.json({ success: true, message: 'स्टाफ विवरण सफलतापूर्वक अपडेट किया गया।' });
    } catch (err) {
        console.error("Error updating staff:", err.message);
        res.status(500).json({ success: false, message: 'स्टाफ अपडेट विफल: ' + err.message });
    }
});

// DELETE /api/staff/delete/:userId - स्टाफ सदस्य डिलीट करें
app.delete('/api/staff/delete/:userId', authorizeAdmin, async (req, res) => {
    const shopId = req.shopId;
    const staffUserId = req.params.userId;

    try {
        // staff और users दोनों टेबल से डिलीट करें (cascading delete का उपयोग करके)
        // PostgreSQL foreign key constraint ON DELETE CASCADE के कारण staff टेबल से अपने आप डिलीट हो जाएगा।
        const result = await pool.query(
            'DELETE FROM users WHERE user_id = $1 AND shop_id = $2 AND role = \'staff\' RETURNING *',
            [staffUserId, shopId]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, message: 'स्टाफ सदस्य नहीं मिला या वह एडमिन है।' });
        }

        console.log(`✅ Staff member deleted: User ID ${staffUserId}`);
        res.json({ success: true, message: 'स्टाफ सदस्य सफलतापूर्वक डिलीट किया गया।' });
    } catch (err) {
        console.error("Error deleting staff:", err.message);
        res.status(500).json({ success: false, message: 'स्टाफ डिलीट विफल: ' + err.message });
    }
});


// *********************************************************************
// * NEW: GSTR REPORTS API (GSTR 1, 2, 3)             *
// *********************************************************************

// Note: GSTR calculation is complex and simplified here for demonstration.
// In real-world, it requires detailed invoice mapping, tax types (CGST, SGST, IGST), and HSN summaries.

// GET /api/reports/gstr1 - GSTR-1 रिपोर्ट (आउटवर्ड सप्लाई - बिक्री)
app.get('/api/reports/gstr1', authorizeAdmin, async (req, res) => {
    const shopId = req.shopId;
    const { startDate, endDate } = req.query; // e.g., '2024-04-01', '2024-04-30'

    if (!startDate || !endDate) {
        return res.status(400).json({ success: false, message: 'GSTR रिपोर्ट के लिए Start Date और End Date आवश्यक है।' });
    }

    try {
        // GSTR-1: B2B/B2C Sales Summary (Simplified)
        const gstr1Query = `
            SELECT
                DATE(s.sale_date) AS sale_date,
                s.invoice_number,
                c.gstin AS customer_gstin,
                s.total_amount,
                s.total_tax,
                (s.total_amount - s.total_tax) AS taxable_value,
                (SELECT json_agg(json_build_object(
                    'product_name', p.name,
                    'hsn_code', p.hsn_code,
                    'quantity', si.quantity,
                    'tax_rate', p.tax_rate,
                    'taxable_value', (si.price_per_unit * si.quantity - si.tax_amount),
                    'tax_amount', si.tax_amount
                )) FROM sale_items si JOIN products p ON si.product_id = p.product_id WHERE si.sale_id = s.sale_id) AS items_detail
            FROM sales s
            LEFT JOIN customers c ON s.customer_id = c.customer_id
            WHERE s.shop_id = $1
            AND s.is_gstr_applicable = TRUE
            AND s.sale_date BETWEEN $2 AND $3
            ORDER BY s.sale_date;
        `;
        const result = await pool.query(gstr1Query, [shopId, startDate, endDate]);

        console.log(`✅ GSTR-1 Report generated for ${shopId}`);
        res.json({ 
            success: true, 
            report: {
                period: `${startDate} to ${endDate}`,
                total_sales_taxable: result.rows.reduce((sum, r) => sum + parseFloat(r.taxable_value), 0).toFixed(2),
                total_tax_collected: result.rows.reduce((sum, r) => sum + parseFloat(r.total_tax), 0).toFixed(2),
                sales_data: result.rows
            },
            message: 'GSTR-1 (बिक्री) रिपोर्ट सफलतापूर्वक उत्पन्न।' 
        });
    } catch (err) {
        console.error("Error generating GSTR-1 report:", err.message);
        res.status(500).json({ success: false, message: 'GSTR-1 रिपोर्ट विफल: ' + err.message });
    }
});

// GET /api/reports/gstr2 - GSTR-2 रिपोर्ट (इनवर्ड सप्लाई - खरीद)
app.get('/api/reports/gstr2', authorizeAdmin, async (req, res) => {
    const shopId = req.shopId;
    const { startDate, endDate } = req.query;

    if (!startDate || !endDate) {
        return res.status(400).json({ success: false, message: 'GSTR रिपोर्ट के लिए Start Date और End Date आवश्यक है।' });
    }

    try {
        // GSTR-2: Purchase/Expense Summary for Input Tax Credit (ITC) (Simplified)
        const gstr2Query = `
            -- 1. Purchases (Goods)
            SELECT
                'Purchase' AS type,
                p.purchase_date AS date,
                p.invoice_number,
                p.supplier_name,
                p.gstin AS supplier_gstin,
                p.total_amount,
                p.total_tax AS itc_eligible_tax,
                (p.total_amount - p.total_tax) AS taxable_value
            FROM purchases p
            WHERE p.shop_id = $1
            AND p.is_gstr_applicable = TRUE
            AND p.purchase_date BETWEEN $2 AND $3
            
            UNION ALL
            
            -- 2. Expenses (Services/Other Inputs)
            SELECT
                'Expense' AS type,
                e.expense_date AS date,
                'N/A' AS invoice_number,
                e.description AS supplier_name,
                'N/A' AS supplier_gstin,
                e.amount AS total_amount,
                e.amount * 0.18 / 1.18 AS itc_eligible_tax, -- यहाँ मान लिया गया है कि टैक्स 18% है
                e.amount / 1.18 AS taxable_value
            FROM expenses e
            WHERE e.shop_id = $1
            AND e.is_gstr_applicable = TRUE
            AND e.expense_date BETWEEN $2 AND $3
            ORDER BY date;
        `;
        const result = await pool.query(gstr2Query, [shopId, startDate, endDate]);
        
        const totalITC = result.rows.reduce((sum, r) => sum + parseFloat(r.itc_eligible_tax), 0).toFixed(2);

        console.log(`✅ GSTR-2 Report generated for ${shopId}`);
        res.json({ 
            success: true, 
            report: {
                period: `${startDate} to ${endDate}`,
                total_input_tax_credit: totalITC,
                purchase_and_expense_data: result.rows
            },
            message: 'GSTR-2 (खरीद/आईटीसी) रिपोर्ट सफलतापूर्वक उत्पन्न।' 
        });
    } catch (err) {
        console.error("Error generating GSTR-2 report:", err.message);
        res.status(500).json({ success: false, message: 'GSTR-2 रिपोर्ट विफल: ' + err.message });
    }
});

// GET /api/reports/gstr3 - GSTR-3B रिपोर्ट (सारांश)
app.get('/api/reports/gstr3', authorizeAdmin, async (req, res) => {
    const shopId = req.shopId;
    const { startDate, endDate } = req.query;

    if (!startDate || !endDate) {
        return res.status(400).json({ success: false, message: 'GSTR रिपोर्ट के लिए Start Date और End Date आवश्यक है।' });
    }

    try {
        // GSTR-3B: Outward Liability (GSTR-1) - Inward ITC (GSTR-2) = Tax Payable/Refundable
        
        // 1. Calculate Outward Tax Liability (GSTR-1 Component)
        const outwardTaxResult = await pool.query(`
            SELECT COALESCE(SUM(total_tax), 0) AS total_liability
            FROM sales
            WHERE shop_id = $1 AND is_gstr_applicable = TRUE
            AND sale_date BETWEEN $2 AND $3;
        `, [shopId, startDate, endDate]);
        const totalLiability = parseFloat(outwardTaxResult.rows[0].total_liability);

        // 2. Calculate Input Tax Credit (GSTR-2 Component)
        const purchaseITCResult = await pool.query(`
            SELECT COALESCE(SUM(total_tax), 0) AS purchase_itc
            FROM purchases
            WHERE shop_id = $1 AND is_gstr_applicable = TRUE
            AND purchase_date BETWEEN $2 AND $3;
        `, [shopId, startDate, endDate]);
        const purchaseITC = parseFloat(purchaseITCResult.rows[0].purchase_itc);

        // 3. Estimate Expense ITC (from GSTR-2 query - simplified to 18% tax rate)
        const expenseITCResult = await pool.query(`
            SELECT COALESCE(SUM(amount), 0) AS total_expense
            FROM expenses
            WHERE shop_id = $1 AND is_gstr_applicable = TRUE
            AND expense_date BETWEEN $2 AND $3;
        `, [shopId, startDate, endDate]);
        const totalExpense = parseFloat(expenseITCResult.rows[0].total_expense);
        // Simplified ITC calculation for expenses (assumes 18% tax on total expense amount)
        const expenseITC = totalExpense > 0 ? (totalExpense * 0.18 / 1.18) : 0;
        
        const totalITC = purchaseITC + expenseITC;
        const taxPayable = totalLiability - totalITC;

        const reportSummary = {
            period: `${startDate} to ${endDate}`,
            outward_tax_liability: totalLiability.toFixed(2),
            total_input_tax_credit: totalITC.toFixed(2),
            tax_payable_refundable: taxPayable.toFixed(2), // +ve = Payable, -ve = Refundable
            purchase_itc: purchaseITC.toFixed(2),
            expense_itc: expenseITC.toFixed(2)
        };

        console.log(`✅ GSTR-3B Report generated for ${shopId}`);
        res.json({ 
            success: true, 
            report: reportSummary,
            message: 'GSTR-3B (सारांश) रिपोर्ट सफलतापूर्वक उत्पन्न। (सरलीकृत)'
        });
    } catch (err) {
        console.error("Error generating GSTR-3B report:", err.message);
        res.status(500).json({ success: false, message: 'GSTR-3B रिपोर्ट विफल: ' + err.message });
    }
});


// *********************************************************************
// * NEW: DETAILED FINANCIAL REPORTS API                    *
// *********************************************************************

// GET /api/reports/product-pl - प्रति उत्पाद P&L (Profit & Loss) रिपोर्ट
app.get('/api/reports/product-pl', async (req, res) => {
    const shopId = req.shopId;
    const { startDate, endDate } = req.query; // Optional

    try {
        const dateClause = (startDate && endDate) ? `AND s.sale_date BETWEEN '${startDate}' AND '${endDate}'` : '';

        const productPLQuery = `
            SELECT
                p.product_id,
                p.name AS product_name,
                p.unit,
                COALESCE(SUM(si.quantity), 0) AS total_quantity_sold,
                COALESCE(SUM(si.quantity * si.price_per_unit), 0) AS total_revenue,
                COALESCE(SUM(si.quantity * si.cost_price), 0) AS total_cost_of_goods_sold,
                (COALESCE(SUM(si.quantity * si.price_per_unit), 0) - COALESCE(SUM(si.quantity * si.cost_price), 0)) AS gross_profit
            FROM sale_items si
            JOIN sales s ON si.sale_id = s.sale_id
            JOIN products p ON si.product_id = p.product_id
            WHERE s.shop_id = $1 ${dateClause}
            GROUP BY p.product_id, p.name, p.unit
            HAVING COALESCE(SUM(si.quantity), 0) > 0
            ORDER BY gross_profit DESC;
        `;
        const result = await pool.query(productPLQuery, [shopId]);

        console.log(`✅ Product-wise P&L Report generated for ${shopId}`);
        res.json({ 
            success: true, 
            report: result.rows,
            message: 'उत्पाद-वार लाभ और हानि रिपोर्ट सफलतापूर्वक उत्पन्न।' 
        });
    } catch (err) {
        console.error("Error generating product P&L report:", err.message);
        res.status(500).json({ success: false, message: 'उत्पाद-वार P&L रिपोर्ट विफल: ' + err.message });
    }
});

// GET /api/reports/detailed-balancesheet - विस्तृत बैलेंस शीट रिपोर्ट (सरलीकृत)
app.get('/api/reports/detailed-balancesheet', authorizeAdmin, async (req, res) => {
    const shopId = req.shopId;

    try {
        // Assets (Current Assets - Simplified)
        // 1. Inventory Value
        const inventoryResult = await pool.query(`
            SELECT COALESCE(SUM(quantity * cost_price), 0) AS total_inventory_value
            FROM products
            WHERE shop_id = $1;
        `, [shopId]);
        const inventoryValue = parseFloat(inventoryResult.rows[0].total_inventory_value);

        // 2. Receivables (Pending Customer Balances - Not tracked, assumed 0)
        const receivables = 0.00;

        // Liabilities (Current Liabilities - Simplified)
        // 1. Payables (Pending Supplier Balances - Not tracked, assumed 0)
        const payables = 0.00;

        // Equity (Simplified Retained Earnings calculation)
        // 1. Net Profit (Last period, assumed from a general P&L calculation)
        
        // General P&L (Total Sales Revenue - Total COGS - Total Expenses)
        const totalSalesResult = await pool.query(`
            SELECT COALESCE(SUM(total_amount), 0) AS total_revenue
            FROM sales
            WHERE shop_id = $1;
        `, [shopId]);
        const totalRevenue = parseFloat(totalSalesResult.rows[0].total_revenue);

        const totalCOGSResult = await pool.query(`
            SELECT COALESCE(SUM(si.quantity * si.cost_price), 0) AS total_cogs
            FROM sale_items si
            JOIN sales s ON si.sale_id = s.sale_id
            WHERE s.shop_id = $1;
        `, [shopId]);
        const totalCOGS = parseFloat(totalCOGSResult.rows[0].total_cogs);

        const totalExpensesResult = await pool.query(`
            SELECT COALESCE(SUM(amount), 0) AS total_expense
            FROM expenses
            WHERE shop_id = $1;
        `, [shopId]);
        const totalExpense = parseFloat(totalExpensesResult.rows[0].total_expense);

        const netProfit = totalRevenue - totalCOGS - totalExpense;
        const netProfitAdjusted = netProfit - payables; // Simplified adjustment

        const balanceSheet = {
            assets: {
                total_current_assets: (inventoryValue + receivables).toFixed(2),
                inventory_value: inventoryValue.toFixed(2),
                cash_and_bank: 'N/A (Cash flow not tracked here)',
                accounts_receivable: receivables.toFixed(2)
            },
            liabilities: {
                total_current_liabilities: payables.toFixed(2),
                accounts_payable: payables.toFixed(2)
            },
            equity: {
                owner_equity_or_retained_earnings: netProfitAdjusted.toFixed(2),
                current_net_profit: netProfit.toFixed(2)
            },
            is_balanced: (inventoryValue + receivables).toFixed(2) === (payables + netProfitAdjusted).toFixed(2)
        };

        console.log(`✅ Detailed Balance Sheet generated for ${shopId}`);
        res.json({ 
            success: true, 
            report: balanceSheet,
            message: 'विस्तृत बैलेंस शीट रिपोर्ट सफलतापूर्वक उत्पन्न (सरलीकृत)।' 
        });
    } catch (err) {
        console.error("Error generating detailed balance sheet report:", err.message);
        res.status(500).json({ success: false, message: 'विस्तृत बैलेंस शीट विफल: ' + err.message });
    }
});


// -----------------------------------------------------------------------------
// V. ORIGINAL APPLICATION DATA ROUTES (PRODUCTS, SALES, CUSTOMERS, EXPENSES, ETC.)
// -----------------------------------------------------------------------------
// *********************************************************************
// * Existing routes preserved below this line               *
// *********************************************************************

// ----------------------------------------------------------------------------
// 1. PRODUCTS (उत्पाद)
// ----------------------------------------------------------------------------

// POST /api/products - नया उत्पाद जोड़ें
app.post('/api/products', authorizeAdmin, async (req, res) => {
    const shopId = req.shopId;
    const { name, unit, quantity, costPrice, sellingPrice, taxRate, barcode, hsnCode } = req.body;
    
    if (!name || !unit || !costPrice || !sellingPrice) {
        return res.status(400).json({ success: false, message: 'उत्पाद का नाम, इकाई, लागत मूल्य और बिक्री मूल्य आवश्यक है।' });
    }
    
    try {
        const result = await pool.query(
            `INSERT INTO products (shop_id, name, unit, quantity, cost_price, selling_price, tax_rate, barcode, hsn_code) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
            [shopId, name, unit, quantity || 0, costPrice, sellingPrice, taxRate || 0.0, barcode || null, hsnCode || null]
        );
        console.log(`✅ Product added: ${name}`);
        res.json({ success: true, message: 'उत्पाद सफलतापूर्वक जोड़ा गया।', product: result.rows[0] });
    } catch (err) {
        if (err.code === '23505' && err.constraint === 'products_barcode_key') {
             return res.status(409).json({ success: false, message: 'यह बारकोड पहले से ही किसी उत्पाद के लिए उपयोग किया जा रहा है।' });
        }
        console.error("Error adding product:", err.message);
        res.status(500).json({ success: false, message: 'उत्पाद जोड़ने में विफल: ' + err.message });
    }
});

// GET /api/products - सभी उत्पाद प्राप्त करें
app.get('/api/products', async (req, res) => {
    const shopId = req.shopId;
    try {
        const result = await pool.query(
            'SELECT * FROM products WHERE shop_id = $1 ORDER BY product_id DESC',
            [shopId]
        );
        res.json({ success: true, products: result.rows });
    } catch (err) {
        console.error("Error fetching products:", err.message);
        res.status(500).json({ success: false, message: 'उत्पाद लाने में विफल: ' + err.message });
    }
});

// PUT /api/products/:id - उत्पाद अपडेट करें
app.put('/api/products/:id', authorizeAdmin, async (req, res) => {
    const shopId = req.shopId;
    const productId = req.params.id;
    const { name, unit, quantity, costPrice, sellingPrice, taxRate, barcode, hsnCode } = req.body;

    if (!name || !unit || !costPrice || !sellingPrice) {
        return res.status(400).json({ success: false, message: 'सभी आवश्यक फ़ील्ड भरें।' });
    }

    try {
        const result = await pool.query(
            `UPDATE products SET 
                name = $1, unit = $2, quantity = $3, cost_price = $4, selling_price = $5, tax_rate = $6, barcode = $7, hsn_code = $8
             WHERE product_id = $9 AND shop_id = $10 RETURNING *`,
            [name, unit, quantity, costPrice, sellingPrice, taxRate || 0.0, barcode || null, hsnCode || null, productId, shopId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'उत्पाद नहीं मिला।' });
        }

        console.log(`✅ Product updated: ${productId}`);
        res.json({ success: true, message: 'उत्पाद सफलतापूर्वक अपडेट किया गया।', product: result.rows[0] });
    } catch (err) {
        if (err.code === '23505' && err.constraint === 'products_barcode_key') {
             return res.status(409).json({ success: false, message: 'यह बारकोड पहले से ही किसी अन्य उत्पाद के लिए उपयोग किया जा रहा है।' });
        }
        console.error("Error updating product:", err.message);
        res.status(500).json({ success: false, message: 'उत्पाद अपडेट करने में विफल: ' + err.message });
    }
});

// DELETE /api/products/:id - उत्पाद डिलीट करें
app.delete('/api/products/:id', authorizeAdmin, async (req, res) => {
    const shopId = req.shopId;
    const productId = req.params.id;

    try {
        const result = await pool.query(
            'DELETE FROM products WHERE product_id = $1 AND shop_id = $2 RETURNING *',
            [productId, shopId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'उत्पाद नहीं मिला।' });
        }

        console.log(`✅ Product deleted: ${productId}`);
        res.json({ success: true, message: 'उत्पाद सफलतापूर्वक डिलीट किया गया।' });
    } catch (err) {
        console.error("Error deleting product:", err.message);
        res.status(500).json({ success: false, message: 'उत्पाद डिलीट करने में विफल: ' + err.message });
    }
});

// ----------------------------------------------------------------------------
// 2. SALES (बिक्री)
// ----------------------------------------------------------------------------

// POST /api/sales - नई बिक्री सहेजें
app.post('/api/sales', async (req, res) => {
    const shopId = req.shopId;
    const { 
        customerId, 
        totalAmount, 
        totalTax, 
        paymentMethod, 
        invoiceNumber, 
        items, 
        isGSTRApplicable 
    } = req.body;

    if (!totalAmount || !items || items.length === 0) {
        return res.status(400).json({ success: false, message: 'कुल राशि और बिक्री आइटम आवश्यक हैं।' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 1. Sale रिकॉर्ड डालें
        const saleResult = await client.query(
            `INSERT INTO sales (shop_id, customer_id, total_amount, total_tax, payment_method, invoice_number, is_gstr_applicable) 
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING sale_id, invoice_number, sale_date`,
            [shopId, customerId || null, totalAmount, totalTax || 0.0, paymentMethod, invoiceNumber, isGSTRApplicable || false]
        );
        const saleId = saleResult.rows[0].sale_id;
        const newInvoiceNumber = saleResult.rows[0].invoice_number;
        const saleDate = saleResult.rows[0].sale_date;

        // 2. Sale Items और Product Inventory अपडेट करें
        for (const item of items) {
            const productResult = await client.query(
                'SELECT cost_price, quantity FROM products WHERE product_id = $1 AND shop_id = $2',
                [item.productId, shopId]
            );

            if (productResult.rows.length === 0) {
                 throw new Error(`उत्पाद ID ${item.productId} नहीं मिला।`);
            }
            
            const { cost_price: productCostPrice, quantity: currentQuantity } = productResult.rows[0];
            const newQuantity = currentQuantity - item.quantity;
            
            if (newQuantity < 0) {
                 throw new Error(`उत्पाद ${item.productId} के लिए अपर्याप्त स्टॉक।`);
            }
            
            // Sale Item डालें
            await client.query(
                `INSERT INTO sale_items (sale_id, product_id, quantity, price_per_unit, tax_amount, cost_price) 
                 VALUES ($1, $2, $3, $4, $5, $6)`,
                [saleId, item.productId, item.quantity, item.pricePerUnit, item.taxAmount || 0.0, productCostPrice]
            );

            // Product Inventory अपडेट करें
            await client.query(
                'UPDATE products SET quantity = $1 WHERE product_id = $2 AND shop_id = $3',
                [newQuantity, item.productId, shopId]
            );
        }

        await client.query('COMMIT');

        console.log(`✅ New sale recorded: Invoice ${newInvoiceNumber}`);
        res.json({ success: true, message: 'बिक्री सफलतापूर्वक सहेजी गई।', sale: { saleId, invoiceNumber: newInvoiceNumber, saleDate } });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error("Error creating sale:", err.message);
        res.status(500).json({ success: false, message: 'बिक्री सहेजने में विफल: ' + err.message });
    } finally {
        client.release();
    }
});

// GET /api/sales - सभी बिक्री प्राप्त करें (केवल सारांश)
app.get('/api/sales', async (req, res) => {
    const shopId = req.shopId;
    try {
        const result = await pool.query(
            `SELECT 
                s.sale_id, 
                s.sale_date, 
                s.invoice_number, 
                s.total_amount, 
                s.total_tax,
                s.payment_method,
                c.name AS customer_name
             FROM sales s
             LEFT JOIN customers c ON s.customer_id = c.customer_id
             WHERE s.shop_id = $1 
             ORDER BY s.sale_date DESC`,
            [shopId]
        );
        res.json({ success: true, sales: result.rows });
    } catch (err) {
        console.error("Error fetching sales:", err.message);
        res.status(500).json({ success: false, message: 'बिक्री रिकॉर्ड लाने में विफल: ' + err.message });
    }
});

// GET /api/sales/:id - बिक्री विवरण प्राप्त करें
app.get('/api/sales/:id', async (req, res) => {
    const shopId = req.shopId;
    const saleId = req.params.id;
    try {
        // Sale Header
        const saleResult = await pool.query(
            `SELECT 
                s.*, 
                c.name AS customer_name, 
                c.phone AS customer_phone,
                c.address AS customer_address,
                c.gstin AS customer_gstin
             FROM sales s
             LEFT JOIN customers c ON s.customer_id = c.customer_id
             WHERE s.sale_id = $1 AND s.shop_id = $2`,
            [saleId, shopId]
        );

        if (saleResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'बिक्री रिकॉर्ड नहीं मिला।' });
        }

        // Sale Items
        const itemsResult = await pool.query(
            `SELECT 
                si.*, 
                p.name AS product_name, 
                p.unit 
             FROM sale_items si
             JOIN products p ON si.product_id = p.product_id
             WHERE si.sale_id = $1`,
            [saleId]
        );

        const saleData = {
            ...saleResult.rows[0],
            items: itemsResult.rows
        };

        res.json({ success: true, sale: saleData });
    } catch (err) {
        console.error("Error fetching sale details:", err.message);
        res.status(500).json({ success: false, message: 'बिक्री विवरण लाने में विफल: ' + err.message });
    }
});

// ----------------------------------------------------------------------------
// 3. CUSTOMERS (ग्राहक)
// ----------------------------------------------------------------------------

// POST /api/customers - नया ग्राहक जोड़ें
app.post('/api/customers', async (req, res) => {
    const shopId = req.shopId;
    const { name, phone, address, gstin } = req.body;
    
    if (!name || !phone) {
        return res.status(400).json({ success: false, message: 'ग्राहक का नाम और फ़ोन नंबर आवश्यक है।' });
    }

    try {
        const result = await pool.query(
            `INSERT INTO customers (shop_id, name, phone, address, gstin) 
             VALUES ($1, $2, $3, $4, $5) 
             ON CONFLICT (phone) 
             DO UPDATE SET name = EXCLUDED.name, address = EXCLUDED.address, gstin = EXCLUDED.gstin RETURNING *`,
            [shopId, name, phone, address || null, gstin || null]
        );
        console.log(`✅ Customer added/updated: ${name}`);
        res.json({ success: true, message: 'ग्राहक सफलतापूर्वक जोड़ा/अपडेट किया गया।', customer: result.rows[0] });
    } catch (err) {
        console.error("Error adding customer:", err.message);
        res.status(500).json({ success: false, message: 'ग्राहक जोड़ने में विफल: ' + err.message });
    }
});

// GET /api/customers - सभी ग्राहक प्राप्त करें
app.get('/api/customers', async (req, res) => {
    const shopId = req.shopId;
    try {
        const result = await pool.query(
            'SELECT * FROM customers WHERE shop_id = $1 ORDER BY customer_id DESC',
            [shopId]
        );
        res.json({ success: true, customers: result.rows });
    } catch (err) {
        console.error("Error fetching customers:", err.message);
        res.status(500).json({ success: false, message: 'ग्राहक लाने में विफल: ' + err.message });
    }
});

// ----------------------------------------------------------------------------
// 4. EXPENSES (खर्च)
// ----------------------------------------------------------------------------

// POST /api/expenses - नया खर्च जोड़ें
app.post('/api/expenses', async (req, res) => {
    const shopId = req.shopId;
    const { description, amount, expenseDate, category, isGSTRApplicable } = req.body;
    
    if (!description || !amount || !expenseDate) {
        return res.status(400).json({ success: false, message: 'विवरण, राशि और तारीख आवश्यक है।' });
    }

    try {
        const result = await pool.query(
            `INSERT INTO expenses (shop_id, description, amount, expense_date, category, is_gstr_applicable) 
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
            [shopId, description, amount, expenseDate, category || 'अन्य', isGSTRApplicable || false]
        );
        console.log(`✅ Expense added: ${description}`);
        res.json({ success: true, message: 'खर्च सफलतापूर्वक जोड़ा गया।', expense: result.rows[0] });
    } catch (err) {
        console.error("Error adding expense:", err.message);
        res.status(500).json({ success: false, message: 'खर्च जोड़ने में विफल: ' + err.message });
    }
});

// GET /api/expenses - सभी खर्च प्राप्त करें
app.get('/api/expenses', async (req, res) => {
    const shopId = req.shopId;
    try {
        const result = await pool.query(
            'SELECT * FROM expenses WHERE shop_id = $1 ORDER BY expense_date DESC',
            [shopId]
        );
        res.json({ success: true, expenses: result.rows });
    } catch (err) {
        console.error("Error fetching expenses:", err.message);
        res.status(500).json({ success: false, message: 'खर्च लाने में विफल: ' + err.message });
    }
});

// DELETE /api/expenses/:id - खर्च डिलीट करें
app.delete('/api/expenses/:id', authorizeAdmin, async (req, res) => {
    const shopId = req.shopId;
    const expenseId = req.params.id;

    try {
        const result = await pool.query(
            'DELETE FROM expenses WHERE expense_id = $1 AND shop_id = $2 RETURNING *',
            [expenseId, shopId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'खर्च रिकॉर्ड नहीं मिला।' });
        }

        console.log(`✅ Expense deleted: ${expenseId}`);
        res.json({ success: true, message: 'खर्च रिकॉर्ड सफलतापूर्वक डिलीट किया गया।' });
    } catch (err) {
        console.error("Error deleting expense:", err.message);
        res.status(500).json({ success: false, message: 'खर्च डिलीट करने में विफल: ' + err.message });
    }
});

// ----------------------------------------------------------------------------
// 5. CLOSING REPORTS (दैनिक क्लोजिंग)
// ----------------------------------------------------------------------------

// POST /api/closings - दैनिक क्लोजिंग सहेजें
app.post('/api/closings', authorizeAdmin, async (req, res) => {
    const shopId = req.shopId;
    const { closingDate, totalSales, totalExpenses, cashInHand, notes } = req.body;

    if (!closingDate || !totalSales) {
        return res.status(400).json({ success: false, message: 'क्लोजिंग की तारीख और कुल बिक्री आवश्यक है।' });
    }

    try {
        // यह सुनिश्चित करने के लिए कि उस दिन के लिए पहले से कोई क्लोजिंग मौजूद न हो
        const existing = await pool.query(
            'SELECT * FROM daily_closings WHERE shop_id = $1 AND closing_date = $2',
            [shopId, closingDate]
        );

        if (existing.rows.length > 0) {
            return res.status(409).json({ success: false, message: 'इस तारीख के लिए क्लोजिंग पहले ही सहेजी जा चुकी है।' });
        }

        const result = await pool.query(
            `INSERT INTO daily_closings (shop_id, closing_date, total_sales, total_expenses, cash_in_hand, notes) 
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
            [shopId, closingDate, totalSales, totalExpenses || 0.0, cashInHand || 0.0, notes || null]
        );
        console.log(`✅ Daily closing saved for: ${closingDate}`);
        res.json({ success: true, message: 'दैनिक क्लोजिंग सफलतापूर्वक सहेजी गई।', closing: result.rows[0] });
    } catch (err) {
        console.error("Error saving daily closing:", err.message);
        res.status(500).json({ success: false, message: 'दैनिक क्लोजिंग सहेजने में विफल: ' + err.message });
    }
});

// GET /api/closings - सभी दैनिक क्लोजिंग रिपोर्ट्स प्राप्त करें
app.get('/api/closings', authorizeAdmin, async (req, res) => {
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
    // process.exit(1); // यदि DB कनेक्ट नहीं हो पाया तो सर्वर को रोकें
});
