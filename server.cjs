// server.cjs (Dukan Pro - Ultimate Backend) - MULTI-USER/SECURE VERSION (CORRECTED)
// -----------------------------------------------------------------------------
// यह कोड JWT, Bcrypt और PostgreSQL के साथ एक सुरक्षित और मल्टी-टेनेंट सर्वर लागू करता है।
// सभी डेटा एक्सेस 'shop_id' द्वारा सीमित (scoped) है।
// -----------------------------------------------------------------------------

const express = require('express');
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');
const crypto = require('crypto');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require('dotenv').config();
// [ यह नया कोड यहाँ जोड़ें ]
// --- 🚀 WEBSOCKET सेटअप START ---
const http = require('http'); // 1. HTTP सर्वर की आवश्यकता
const { WebSocketServer } = require('ws'); // 2. WebSocket सर्वर की आवश्यकता
// --- 🚀 WEBSOCKET सेटअप END ---
const app = express();
// JSON payload limit ko 10MB tak badhayein (logo ke liye)
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));
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
// --- server.cjs में इस पूरे फ़ंक्शन को बदलें ---
// [ server.cjs फ़ाइल में इस पूरे फ़ंक्शन को बदलें ]


async function createTables() {
    const client = await pool.connect();
    try {
        console.log('Attempting to ensure all tables and columns exist...');

        await client.query(`
            CREATE TABLE IF NOT EXISTS shops (
                id SERIAL PRIMARY KEY,
                shop_name TEXT NOT NULL,
                license_expiry_date TIMESTAMP WITH TIME ZONE DEFAULT NULL,
                shop_logo TEXT,
                plan_type TEXT DEFAULT 'TRIAL',
                add_ons JSONB DEFAULT '{}'::jsonb,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        
        // 0. Shops / Tenant Table & License Expiry
        await client.query(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = (SELECT oid FROM pg_class WHERE relname = 'shops') AND attname = 'license_expiry_date') THEN ALTER TABLE shops ADD COLUMN license_expiry_date TIMESTAMP WITH TIME ZONE DEFAULT NULL; END IF; END $$;`);
        await client.query(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = (SELECT oid FROM pg_class WHERE relname = 'shops') AND attname = 'shop_logo') THEN ALTER TABLE shops ADD COLUMN shop_logo TEXT; END IF; END $$;`);        
        await client.query(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid=(SELECT oid FROM pg_class WHERE relname='shops') AND attname='plan_type') THEN ALTER TABLE shops ADD COLUMN plan_type TEXT DEFAULT 'TRIAL'; END IF; END $$;`);
        await client.query(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid=(SELECT oid FROM pg_class WHERE relname='shops') AND attname='add_ons') THEN ALTER TABLE shops ADD COLUMN add_ons JSONB DEFAULT '{}'::jsonb; END IF; END $$;`);
        // 0.5. Users Table
        await client.query('CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, name TEXT NOT NULL, role TEXT DEFAULT \'CASHIER\' CHECK (role IN (\'ADMIN\', \'MANAGER\', \'CASHIER\')), created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);');
        
        // ===================================================================
        // [ ✅ NAYA CODE FIX YAHAN SE SHURU HOTA HAI ]
        // Yah 6 tables dataTables loop se pehle banai ja rahi hain
        
        // 1. Stock Table (CREATE)
        await client.query(`
            CREATE TABLE IF NOT EXISTS stock (
                id SERIAL PRIMARY KEY,
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
                sku TEXT NOT NULL,
                name TEXT NOT NULL,
                quantity NUMERIC NOT NULL DEFAULT 0,
                unit TEXT,
                purchase_price NUMERIC NOT NULL DEFAULT 0,
                sale_price NUMERIC NOT NULL DEFAULT 0,
                cost_price NUMERIC DEFAULT 0,
                gst NUMERIC DEFAULT 0,
                category TEXT,
                hsn_code TEXT,
                product_attributes JSONB,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (shop_id, sku)
            );
        `);

        // 2. Customers Table (CREATE)
        await client.query(`
            CREATE TABLE IF NOT EXISTS customers (
                id SERIAL PRIMARY KEY, 
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE, 
                name TEXT NOT NULL, 
                phone TEXT, 
                email TEXT, 
                address TEXT, 
                gstin TEXT, 
                balance NUMERIC DEFAULT 0, 
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 3. Invoices Table (CREATE)
        await client.query(`
            CREATE TABLE IF NOT EXISTS invoices (
                id SERIAL PRIMARY KEY, 
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE, 
                customer_id INTEGER REFERENCES customers(id) ON DELETE SET NULL, 
                total_amount NUMERIC NOT NULL, 
                total_cost NUMERIC DEFAULT 0, 
                customer_gstin TEXT,
                place_of_supply TEXT,
                is_reconciled BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 4. Invoice Items Table (CREATE)
        await client.query(`
            CREATE TABLE IF NOT EXISTS invoice_items (
                id SERIAL PRIMARY KEY, 
                invoice_id INTEGER REFERENCES invoices(id) ON DELETE CASCADE, 
                item_name TEXT NOT NULL, 
                item_sku TEXT NOT NULL, 
                quantity NUMERIC NOT NULL, 
                sale_price NUMERIC NOT NULL, 
                purchase_price NUMERIC, 
                gst_rate NUMERIC DEFAULT 0, 
                gst_amount NUMERIC DEFAULT 0,
                cgst_amount NUMERIC DEFAULT 0,
                sgst_amount NUMERIC DEFAULT 0,
                igst_amount NUMERIC DEFAULT 0,
                product_attributes JSONB
            );
        `);

        // 5. Purchases Table (CREATE)
        await client.query(`
            CREATE TABLE IF NOT EXISTS purchases (
                id SERIAL PRIMARY KEY, 
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE, 
                supplier_name TEXT NOT NULL, 
                item_details TEXT, 
                total_cost NUMERIC NOT NULL, 
                gst_details JSONB, 
                is_reconciled BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 6. Expenses Table (CREATE)
        await client.query(`
            CREATE TABLE IF NOT EXISTS expenses (
                id SERIAL PRIMARY KEY, 
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE, 
                description TEXT NOT NULL, 
                category TEXT, 
                amount NUMERIC NOT NULL, 
                is_reconciled BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        
        // [ ✅ NAYA CODE FIX YAHAN KHATM HOTA HAI ]
        // ===================================================================

        await client.query(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = (SELECT oid FROM pg_class WHERE relname = 'users') AND attname = 'status') THEN ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'pending' CHECK (status IN ('active', 'pending', 'disabled')); END IF; IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = (SELECT oid FROM pg_class WHERE relname = 'users') AND attname = 'mobile') THEN ALTER TABLE users ADD COLUMN mobile TEXT; END IF; END $$;`);

        // 1. Licenses Table (All necessary updates for shop_id, etc.)
        await client.query('CREATE TABLE IF NOT EXISTS licenses (key_hash TEXT PRIMARY KEY, user_id INTEGER REFERENCES users(id) ON DELETE SET NULL, shop_id INTEGER REFERENCES shops(id) ON DELETE SET NULL, customer_details JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, expiry_date TIMESTAMP WITH TIME ZONE, is_trial BOOLEAN DEFAULT FALSE);');
        await client.query(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = (SELECT oid FROM pg_class WHERE relname = 'licenses') AND attname = 'user_id') THEN ALTER TABLE licenses ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE SET NULL; CREATE INDEX IF NOT EXISTS idx_licenses_user_id ON licenses (user_id); END IF; IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = (SELECT oid FROM pg_class WHERE relname = 'licenses') AND attname = 'customer_details') THEN ALTER TABLE licenses ADD COLUMN customer_details JSONB; END IF; IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = (SELECT oid FROM pg_class WHERE relname = 'licenses') AND attname = 'shop_id') THEN ALTER TABLE licenses ADD COLUMN shop_id INTEGER REFERENCES shops(id) ON DELETE SET NULL; CREATE INDEX IF NOT EXISTS idx_licenses_shop_id ON licenses (shop_id); END IF; END $$;`);
        await client.query(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid=(SELECT oid FROM pg_class WHERE relname='licenses') AND attname='plan_type') THEN ALTER TABLE licenses ADD COLUMN plan_type TEXT DEFAULT 'TRIAL'; END IF; END $$;`);
        
        // --- Multi-tenant modification: Add shop_id to all data tables ---
        // (Ab yah safe hai kyunki tables pehle hi ban chuki hain)
        const dataTables = ['stock', 'customers', 'invoices', 'invoice_items', 'purchases', 'expenses'];
        for (const table of dataTables) {
            await client.query(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = (SELECT oid FROM pg_class WHERE relname = '${table}') AND attname = 'shop_id') THEN ALTER TABLE ${table} ADD COLUMN shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE; CREATE INDEX IF NOT EXISTS idx_${table}_shop_id ON ${table} (shop_id); END IF; END $$;`);
        }

        // 2. Stock Table (Fixing the UNIQUE constraint and missing columns for ON CONFLICT)
       // 🚀🚀🚀 यह रहा परमानेंट फिक्स 🚀🚀🚀
        // यह पुराने, गलत 'sku' नियम को हटाता है और सही 'shop_id + sku' नियम को लागू करता है
        await client.query(`
            DO $$ BEGIN
                -- 1. पहले, किसी भी पुराने और गलत "सिर्फ-sku" वाले नियम को हटा दें (अगर वह मौजूद है)
                IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'stock_sku_key' AND conrelid = (SELECT oid FROM pg_class WHERE relname = 'stock')) THEN
                    ALTER TABLE stock DROP CONSTRAINT stock_sku_key;
                END IF;
                
                -- 2. अब, सही "shop_id + sku" वाले नियम को जोड़ें (अगर वह पहले से मौजूद नहीं है)
                IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'stock_shop_id_sku_key' AND conrelid = (SELECT oid FROM pg_class WHERE relname = 'stock')) THEN
                    ALTER TABLE stock ADD CONSTRAINT stock_shop_id_sku_key UNIQUE (shop_id, sku);
                END IF;
            END $$;
        `);
        
        // [ ✅ Is Nayi Line ko Line 32 ke baad Paste Karein ]

        await client.query(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid=(SELECT oid FROM pg_class WHERE relname='stock') AND attname='product_attributes') THEN ALTER TABLE stock ADD COLUMN product_attributes JSONB; END IF; END $$;`);
        
        // 🚀🚀🚀 फिक्स समाप्त 🚀🚀🚀
        // 3. Customers Table (Fixing the missing balance column for Balance Sheet Error)
        await client.query('CREATE TABLE IF NOT EXISTS customers (id SERIAL PRIMARY KEY, shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE, name TEXT NOT NULL, phone TEXT, email TEXT, address TEXT, gstin TEXT, balance NUMERIC DEFAULT 0, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);');
        // FIX: Add the missing balance column safely (Fixes Balance Sheet Error)
        await client.query(`
            DO $$ BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = (SELECT oid FROM pg_class WHERE relname = 'customers') AND attname = 'balance') THEN
                    ALTER TABLE customers ADD COLUMN balance NUMERIC DEFAULT 0;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid=(SELECT oid FROM pg_class WHERE relname='customers') AND attname='gstin') THEN ALTER TABLE customers ADD COLUMN gstin TEXT; END IF;
            END $$;
        `);

        // 4. Invoices/Sales Table
        await client.query('CREATE TABLE IF NOT EXISTS invoices (id SERIAL PRIMARY KEY, shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE, customer_id INTEGER REFERENCES customers(id) ON DELETE SET NULL, total_amount NUMERIC NOT NULL, total_cost NUMERIC DEFAULT 0, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);');
        
        // === TALLY UPGRADE START: Add customer_gstin and place_of_supply to INVOICES ===
        await client.query(`
            DO $$ BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = (SELECT oid FROM pg_class WHERE relname = 'invoices') AND attname = 'customer_gstin') THEN
                    ALTER TABLE invoices ADD COLUMN customer_gstin TEXT;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = (SELECT oid FROM pg_class WHERE relname = 'invoices') AND attname = 'place_of_supply') THEN
                    ALTER TABLE invoices ADD COLUMN place_of_supply TEXT;
                END IF;
            END $$;
        `);
        // === TALLY UPGRADE END ===

        // 5. Invoice Items
        await client.query('CREATE TABLE IF NOT EXISTS invoice_items (id SERIAL PRIMARY KEY, invoice_id INTEGER REFERENCES invoices(id) ON DELETE CASCADE, item_name TEXT NOT NULL, item_sku TEXT NOT NULL, quantity NUMERIC NOT NULL, sale_price NUMERIC NOT NULL, purchase_price NUMERIC, gst_rate NUMERIC DEFAULT 0, gst_amount NUMERIC DEFAULT 0);');
        await client.query(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid=(SELECT oid FROM pg_class WHERE relname='invoice_items') AND attname='product_attributes') THEN ALTER TABLE invoice_items ADD COLUMN product_attributes JSONB; END IF; END $$;`);    
        // === TALLY UPGRADE START: Add detailed GST columns to INVOICE_ITEMS ===
        // (Note: This combines your existing check[span_0](end_span) with the new Tally columns)
        await client.query(`
            DO $$ BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = (SELECT oid FROM pg_class WHERE relname = 'invoice_items') AND attname = 'gst_rate') THEN
                    ALTER TABLE invoice_items ADD COLUMN gst_rate NUMERIC DEFAULT 0;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = (SELECT oid FROM pg_class WHERE relname = 'invoice_items') AND attname = 'gst_amount') THEN
                    ALTER TABLE invoice_items ADD COLUMN gst_amount NUMERIC DEFAULT 0;
                END IF;
                
                -- New Tally Columns Added Safely --
                IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = (SELECT oid FROM pg_class WHERE relname = 'invoice_items') AND attname = 'cgst_amount') THEN
                    ALTER TABLE invoice_items ADD COLUMN cgst_amount NUMERIC DEFAULT 0;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = (SELECT oid FROM pg_class WHERE relname = 'invoice_items') AND attname = 'sgst_amount') THEN
                    ALTER TABLE invoice_items ADD COLUMN sgst_amount NUMERIC DEFAULT 0;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = (SELECT oid FROM pg_class WHERE relname = 'invoice_items') AND attname = 'igst_amount') THEN
                    ALTER TABLE invoice_items ADD COLUMN igst_amount NUMERIC DEFAULT 0;
                END IF;
            END $$;
        `);
        // === TALLY UPGRADE END ===

        // 6. Purchases Table
        await client.query('CREATE TABLE IF NOT EXISTS purchases (id SERIAL PRIMARY KEY, shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE, supplier_name TEXT NOT NULL, item_details TEXT, total_cost NUMERIC NOT NULL, gst_details JSONB, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);');
        await client.query(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid=(SELECT oid FROM pg_class WHERE relname='purchases') AND attname='gst_details') THEN ALTER TABLE purchases ADD COLUMN gst_details JSONB; END IF; END $$;`);

        // 7. Expenses Table
        await client.query('CREATE TABLE IF NOT EXISTS expenses (id SERIAL PRIMARY KEY, shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE, description TEXT NOT NULL, category TEXT, amount NUMERIC NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);');

        // 8. Daily Closings Table
        await client.query('CREATE TABLE IF NOT EXISTS daily_closings (id SERIAL PRIMARY KEY, shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE, closing_date DATE NOT NULL, total_sales NUMERIC DEFAULT 0, total_cogs NUMERIC DEFAULT 0, total_expenses NUMERIC DEFAULT 0, net_profit NUMERIC DEFAULT 0, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, UNIQUE (shop_id, closing_date));');

        // 9. Categories Table
        await client.query('CREATE TABLE IF NOT EXISTS categories (id SERIAL PRIMARY KEY, shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE, name TEXT NOT NULL, created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, UNIQUE (shop_id, name));');

        // 10. Company Profile Table
        await client.query(`
    CREATE TABLE IF NOT EXISTS company_profile (
        shop_id INTEGER PRIMARY KEY REFERENCES shops(id) ON DELETE CASCADE,
        legal_name TEXT,
        gstin TEXT,
        address TEXT,
        opening_capital NUMERIC DEFAULT 0,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );
`);

        //11. createTables() फ़ंक्शन के अंदर, company_profile टेबल बनाने के बाद इसे जोड़ें:
        await client.query(`
        DO $$ BEGIN 
        IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid=(SELECT oid FROM pg_class WHERE relname='company_profile') AND attname='opening_capital') 
        THEN ALTER TABLE company_profile ADD COLUMN opening_capital NUMERIC DEFAULT 0; 
    END IF; 
    END $$;
`);

        // 12. Renewal Requests Table
        await client.query(`CREATE TABLE IF NOT EXISTS renewal_requests (id SERIAL PRIMARY KEY, shop_id INTEGER REFERENCES shops(id), user_email TEXT, message TEXT, requested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP);`);

        // ... (renewal_requests टेबल के बाद)

        // 13. Bank Statement Items Table
        await client.query(`
            CREATE TABLE IF NOT EXISTS bank_statement_items (
                id SERIAL PRIMARY KEY,
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
                transaction_date DATE NOT NULL,
                description TEXT,
                debit NUMERIC DEFAULT 0,
                credit NUMERIC DEFAULT 0,
                balance NUMERIC,
                is_reconciled BOOLEAN DEFAULT FALSE,
                reconciliation_id INTEGER DEFAULT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // 14. Reconciliation Reports Table (The "Static Report")
        await client.query(`
            CREATE TABLE IF NOT EXISTS reconciliation_reports (
                id SERIAL PRIMARY KEY,
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
                statement_end_date DATE NOT NULL,
                statement_end_balance NUMERIC NOT NULL,
                book_balance_start NUMERIC NOT NULL,
                cleared_payments NUMERIC DEFAULT 0,
                cleared_deposits NUMERIC DEFAULT 0,
                uncleared_items_count INTEGER DEFAULT 0,
                uncleared_items_total NUMERIC DEFAULT 0,
                reconciled_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        
        // 15. Add 'is_reconciled' status to existing tables
        await client.query(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid=(SELECT oid FROM pg_class WHERE relname='invoices') AND attname='is_reconciled') THEN ALTER TABLE invoices ADD COLUMN is_reconciled BOOLEAN DEFAULT FALSE; END IF; END $$;`);
        await client.query(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid=(SELECT oid FROM pg_class WHERE relname='purchases') AND attname='is_reconciled') THEN ALTER TABLE purchases ADD COLUMN is_reconciled BOOLEAN DEFAULT FALSE; END IF; END $$;`);
        await client.query(`DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid=(SELECT oid FROM pg_class WHERE relname='expenses') AND attname='is_reconciled') THEN ALTER TABLE expenses ADD COLUMN is_reconciled BOOLEAN DEFAULT FALSE; END IF; END $$;`);

// ... (console.log('✅ All tables...') से पहले)
        // --- MOVED SECTION (Kept as per your request) ---
        // (Note: These are redundant but kept to avoid deleting code)

        // 1. GSTR और बेहतर रिपोर्टिंग के लिए स्टॉक में HSN कोड जोड़ना
        await client.query(`
            DO $$ BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = (SELECT oid FROM pg_class WHERE relname = 'stock') AND attname = 'hsn_code') THEN
                    ALTER TABLE stock ADD COLUMN hsn_code TEXT;
                END IF;
            END $$;
        `);

        // 2. GSTR (B2B) के लिए ग्राहकों में GSTIN जोड़ना
        await client.query(`
            DO $$ BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = (SELECT oid FROM pg_class WHERE relname = 'customers') AND attname = 'gstin') THEN
                    ALTER TABLE customers ADD COLUMN gstin TEXT;
                END IF;
            END $$;
        `);

        // 3. GSTR-1 रिपोर्टिंग के लिए Invoice Items में GST दरें जोड़ना
        // (Note: Redundant, already handled in the Tally Upgrade section above)
        await client.query(`
            DO $$ BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = (SELECT oid FROM pg_class WHERE relname = 'invoice_items') AND attname = 'gst_rate') THEN
                    ALTER TABLE invoice_items ADD COLUMN gst_rate NUMERIC DEFAULT 0;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = (SELECT oid FROM pg_class WHERE relname = 'invoice_items') AND attname = 'gst_amount') THEN
                    ALTER TABLE invoice_items ADD COLUMN gst_amount NUMERIC DEFAULT 0;
                END IF;
            END $$;
        `);

        // 4. GSTR-2 (Purchases) के लिए Purchases में GST विवरण जोड़ना
        await client.query(`
            DO $$ BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = (SELECT oid FROM pg_class WHERE relname = 'purchases') AND attname = 'gst_details') THEN
                    ALTER TABLE purchases ADD COLUMN gst_details JSONB;
                END IF;
            END $$;
        `);

        
        // 6. लाइसेंस रिन्यूअल अनुरोधों को ट्रैक करने के लिए नई टेबल
        await client.query(`
            CREATE TABLE IF NOT EXISTS renewal_requests (
                id SERIAL PRIMARY KEY,
                shop_id INTEGER REFERENCES shops(id),
                user_email TEXT,
                message TEXT,
                requested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        // --- END MOVED SECTION ---

        console.log('✅ All tables and columns (including Tally GST columns) checked/created successfully.');
        
    } catch (err) {
        console.error('❌ Error ensuring database schema:', err.message, err.stack);
        process.exit(1); // Exit if schema setup fails
    } finally {
        if (client) { // Ensure client exists before releasing
           client.release();
        }
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
/* [Line 86] - यह आपका मौजूदा checkRole फ़ंक्शन है */
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
/* [Line 94] - checkRole फ़ंक्शन यहाँ समाप्त होता है */


/* ============================================== */
/* === 🚀 🚀 🚀 नया checkPlan मिडलवेयर यहाँ पेस्ट करें 🚀 🚀 🚀 === */
/* ============================================== */
/**
 * मिडलवेयर: प्लान-आधारित फीचर कंट्रोल के लिए।
 * पदानुक्रम (Hierarchy): PREMIUM (4) > MEDIUM (3) > BASIC (2) > TRIAL (1)
 * AMC: 'ONE_TIME' प्लान की AMC एक्सपायर होने पर उसे 'BASIC' माना जाएगा।
 */
/* ============================================== */
/* === 🚀 🚀 🚀 NAYA 'checkPlan' (ADD-ON KE SAATH) 🚀 🚀 🚀 === */
/* ============================================== */
/**
 * मिडलवेयर: प्लान-आधारित और ऐड-ऑन आधारित फीचर कंट्रोल के लिए।
 * पदानुक्रम (Hierarchy): PREMIUM (4) > MEDIUM (3) > BASIC (2) > TRIAL (1)
 * requiredPlans: ['MEDIUM', 'PREMIUM'] (यानि Medium ya Premium hona zaroori hai)
 * requiredAddOn: 'has_closing' (ya fir 'has_backup')
 */
/* ============================================== */
/* === 🚀 🚀 🚀 NAYA 'checkPlan' (ADD-ON KE SAATH) 🚀 🚀 🚀 === */
/* ============================================== */
/**
 * मिडलवेयर: प्लान-आधारित और ऐड-ऑन आधारित फीचर कंट्रोल के लिए।
 * पदानुक्रम (Hierarchy): PREMIUM (4) > MEDIUM (3) > BASIC (2) > TRIAL (1)
 * requiredPlans: ['MEDIUM', 'PREMIUM'] (यानि Medium ya Premium hona zaroori hai)
 * requiredAddOn: 'has_closing' (ya fir 'has_backup')
 */
const checkPlan = (requiredPlans, requiredAddOn = null) => (req, res, next) => {
    const plans = { 'PREMIUM': 4, 'ONE_TIME': 4, 'MEDIUM': 3, 'BASIC': 2, 'TRIAL': 1 };
    
    // JWT टोकन से यूज़र का प्लान और ऐड-ऑन लें (jo humne Login/Activate mein daala tha)
    const userPlan = req.user.plan_type || 'TRIAL';
    const userPlanLevel = plans[userPlan.toUpperCase()] || 0;
    const userAddOns = req.user.add_ons || {}; // Jaise { "has_backup": true }
    const expiryDate = req.user.licenseExpiryDate ? new Date(req.user.licenseExpiryDate) : null;
    const now = new Date();

    // 1. जाँच करें कि लाइसेंस/AMC एक्सपायर तो नहीं हो गया
    if (!expiryDate || expiryDate < now) {
        // लाइसेंस/AMC एक्सपायर हो गया है।
        return res.status(403).json({ 
            success: false, 
            message: `आपका '${userPlan}' प्लान/AMC समाप्त हो गया है। सॉफ्टवेयर लॉक है। कृपया 7303410987 पर संपर्क करें।`
        });
    }

    // 2. 'TRIAL' प्लान के लिए जाँच करें (sab access milna chahiye)
    if (userPlan === 'TRIAL') {
        next(); // ट्रायल एक्टिव है, अनुमति दें
        return;
    }

    // 3. 'ONE_TIME' प्लान 'PREMIUM' ke barabar hai
    // (Yeh logic neeche handle ho jaayega)
    
    // 4. मुख्य प्लान लेवल की जाँच करें (Kya user MEDIUM ya PREMIUM hai?)
    const isPlanAuthorized = requiredPlans.some(plan => {
        const requiredLevel = plans[plan.toUpperCase()] || 0;
        return userPlanLevel >= requiredLevel; // Kya user ka level zaroori level se zyada hai?
    });

    if (isPlanAuthorized) {
        // Haan, user MEDIUM ya PREMIUM par hai.
        next(); // Anumati hai
        return;
    }

    // 5. 🚀 ADD-ON CHECK 🚀
    // Agar user 'BASIC' par hai, to add-on check karen
    if (requiredAddOn && userPlan === 'BASIC' && userAddOns[requiredAddOn] === true) {
        // User 'BASIC' par hai, lekin usne yeh add-on (jaise 'has_closing') khareeda hai
        console.log(`User ${req.user.id} accessed ${requiredAddOn} via Add-on.`);
        next(); // Anumati hai
        return;
    }
    
    // 6. अनुमति नहीं है (Na toh plan hai, na hi add-on)
    const featureName = requiredAddOn ? `'${requiredAddOn}' ऐड-ऑन` : `'${requiredPlans.join('/')}' प्लान`;
    res.status(403).json({ 
        success: false, 
        message: `यह फीचर (${featureName}) आपके '${userPlan}' प्लान में शामिल नहीं है। अपग्रेड करने या ऐड-ऑन खरीदने के लिए 7303410987 पर संपर्क करें।`
    });
};
/* ============================================== */
/* === 🚀 Naya checkPlan yahaan samapt hota hai === */
/* ============================================== *//* ============================================== */
/* === 🚀 Naya checkPlan yahaan samapt hota hai === */
/* ============================================== *//* ============================================== */
/* === 🚀 नया मिडलवेयर समाप्त === */
/* ============================================== */
/* ============================================== */
/* === 🚀 🚀 🚀 Naya Add-on Grant API 🚀 🚀 🚀 === */
/* ============================================== */
app.post('/api/admin/grant-addon', async (req, res) => {
    const { adminPassword, shop_id, add_ons } = req.body; // add_ons = { "has_backup": true, "has_closing": false }

    // 1. एडमिन पासवर्ड चेक करें
    if (!process.env.GLOBAL_ADMIN_PASSWORD) {
        return res.status(500).json({ success: false, message: 'सर्वर पर GLOBAL_ADMIN_PASSWORD सेट नहीं है।' });
    }
    if (adminPassword !== process.env.GLOBAL_ADMIN_PASSWORD) {
         return res.status(401).json({ success: false, message: 'अमान्य एडमिन पासवर्ड।' });
    }
    
    // 2. इनपुट चेक करें
    if (!shop_id || !add_ons) {
        return res.status(400).json({ success: false, message: 'Shop ID और add_ons ऑब्जेक्ट आवश्यक हैं।' });
    }

    try {
        // 3. डेटाबेस अपडेट करें
        const result = await pool.query(
            "UPDATE shops SET add_ons = $1 WHERE id = $2 RETURNING id, shop_name, add_ons",
            [add_ons, shop_id]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, message: `Shop ID ${shop_id} नहीं मिली।` });
        }

        res.json({ success: true, message: `Shop ID ${result.rows[0].id} (${result.rows[0].shop_name}) के लिए ऐड-ऑन सफलतापूर्वक अपडेट किए गए।`, data: result.rows[0] });

    } catch (err) {
        console.error("Error granting add-on:", err.message);
        res.status(500).json({ success: false, message: 'ऐड-ऑन देने में विफल: ' + err.message });
    }
});
/* ============================================== */
/* === 🚀 Naya API yahaan samapt hota hai === */
/* ============================================== */
// -----------------------------------------------------------------------------
// III. AUTHENTICATION AND LICENSE ROUTES (PUBLIC/SETUP)
// -----------------------------------------------------------------------------

// 🌟 FIX: This route is now /api/admin/generate-key and uses GLOBAL_ADMIN_PASSWORD
// [ server.cjs में इस पूरे फ़ंक्शन को बदलें ]

// 1. License Key Generation (UPDATED FOR 'plan_type')
app.post('/api/admin/generate-key', async (req, res) => {
    
    // 🚀 FIX: 'plan_type' को req.body से जोड़ा गया
    const { adminPassword, days, plan_type = 'TRIAL', customerName, customerMobile, customerAddress } = req.body;

    if (!process.env.GLOBAL_ADMIN_PASSWORD) {
        return res.status(500).json({ success: false, message: 'सर्वर पर GLOBAL_ADMIN_PASSWORD सेट नहीं है।' });
    }
    if (adminPassword !== process.env.GLOBAL_ADMIN_PASSWORD) {
         return res.status(401).json({ success: false, message: 'अमान्य एडमिन पासवर्ड।' });
    }

    if (typeof days !== 'number' || days < 1) {
        return res.status(400).json({ success: false, message: 'दिनों की संख्या मान्य होनी चाहिए।' });
    }

    // ग्राहक विवरण को एक JSON ऑब्जेक्ट में सहेजें (यह सही है)
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
        // 🚀 FIX: 'plan_type' को INSERT क्वेरी में जोड़ा गया
        await pool.query(
            'INSERT INTO licenses (key_hash, expiry_date, is_trial, customer_details, plan_type) VALUES ($1, $2, $3, $4, $5)',
            [keyHash, expiryDate, (plan_type === 'TRIAL'), customer_details, plan_type]
        );
        
        res.json({
            success: true,
            key: rawKey,
            message: `लाइसेंस कुंजी (${plan_type}) सफलतापूर्वक बनाई गई।`,
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
    const { shopName, name, email, mobile, password } = req.body;

   if (!shopName || !name || !email || !mobile || !password) { // <<< '!mobile' जोड़ा
    return res.status(400).json({ success: false, message: 'सभी फ़ील्ड (शॉप का नाम, आपका नाम, ईमेल, मोबाइल, पासवर्ड) आवश्यक हैं.' }); // <<< मैसेज अपडेट किया
}
// (Optional) Add mobile format validation after this if needed
if (!/^\d{10}$/.test(mobile)) {
     return res.status(400).json({ success: false, message: 'कृपया मान्य 10 अंकों का मोबाइल नंबर डालें.' });
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
    INSERT INTO users (shop_id, email, password_hash, name, mobile, role, status) -- <<< 'mobile' जोड़ा
    VALUES ($1, $2, $3, $4, $5, $6, 'active')  -- <<< '$5' (mobile) और '$6' (role) किया
    RETURNING id, shop_id, email, name, mobile, role, status -- <<< 'mobile' जोड़ा
`;
        const userResult = await client.query(userInsertQuery, [shopId, email, hashedPassword, name, mobile, 'ADMIN']); // <<< 'mobile' यहाँ जोड़ा
        const user = userResult.rows[0];
        // 5. JWT टोकन जनरेट करें
const tokenUser = {
    id: user.id,
    email: user.email,
    mobile: user.mobile,
    shopId: user.shop_id,
    name: user.name,
    role: user.role,
    shopName: shopName, // ShopName जोड़ना
    status: user.status,
    plan_type: 'TRIAL', // 🚀 NAYA: Register par default 'TRIAL'
    add_ons: {}, // 🚀 NAYA: Register par default 'khaali add-on'
    licenseExpiryDate: null // 🚀 NAYA: Register par koi date nahi
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
// [ server.cjs फ़ाइल में यह कोड बदलें ]

// [ server.cjs में इस पूरे फ़ंक्शन को बदलें ]

// 4. User Login (UPDATED FOR 'plan_type' AND 'add_ons')
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'ईमेल और पासवर्ड आवश्यक हैं.' });
    }

    try {
        // --- 🚀 FIX: Step 1: 'plan_type' और 'add_ons' को एक साथ लाएँ ---
        const result = await pool.query(
            'SELECT u.*, s.shop_name, s.license_expiry_date, s.plan_type, s.add_ons FROM users u JOIN shops s ON u.shop_id = s.id WHERE u.email = $1',
            [email]
        );

        if (result.rows.length === 0) {
            console.log(`DEBUG LOGIN: User not found for email: ${email}`);
            return res.status(401).json({ success: false, message: 'अमान्य ईमेल या पासवर्ड.' });
        }

        let user = result.rows[0]; // इसमें अब 'add_ons' भी शामिल है

        // --- Step 2: Check Password (यह सही है) ---
        const isMatch = await bcrypt.compare(password, user.password_hash);
        console.log(`DEBUG LOGIN: Password Match? ${isMatch}`);

        if (!isMatch) {
            return res.status(401).json({ success: false, message: 'अमान्य ईमेल या पासवर्ड.' });
        }

        // --- Step 3: Check/Update User Status (यह सही है) ---
        if (user.status !== 'active') {
             await pool.query('UPDATE users SET status = $1 WHERE id = $2', ['active', user.id]);
             user.status = 'active'; // Update local variable too
             console.log('DEBUG LOGIN: User status set to active (Auto-Activate).');
        }

        // --- Step 4: (डेटा पहले ही Step 1 में मिल गया है) ---
        const shopExpiryDate = user.license_expiry_date; 
        const shopPlanType = user.plan_type || 'TRIAL'; 
        const shopAddOns = user.add_ons || {}; // 🚀🚀🚀 नया: ऐड-ऑन को यहाँ जोड़ा गया

        console.log(`DEBUG LOGIN: Shop ID ${user.shop_id} Expiry Date: ${shopExpiryDate} | Plan: ${shopPlanType}`);


        // --- 🚀 FIX: Step 5: टोकन पेलोड में 'add_ons' जोड़ें ---
        const tokenUser = {
            id: user.id,
            email: user.email,
            shopId: user.shop_id,
            name: user.name,
            mobile: user.mobile, // Include mobile if you added it
            role: user.role,
            shopName: user.shop_name,
            licenseExpiryDate: shopExpiryDate, // <<< Use SHOP's expiry date
            status: user.status,
            plan_type: shopPlanType,
            add_ons: shopAddOns // 🚀🚀🚀 नया ऐड-ऑन यहाँ जोड़ा गया
        };
        const token = jwt.sign(tokenUser, JWT_SECRET, { expiresIn: '30d' });

        // --- Step 6: Check SHOP's License Expiry (यह सही है) ---
        const expiryDate = shopExpiryDate ? new Date(shopExpiryDate) : null;
        const currentDate = new Date();
        currentDate.setHours(0, 0, 0, 0); // Compare dates only, ignore time

        if (!expiryDate || expiryDate < currentDate) {
            console.log(`DEBUG LOGIN: Shop ID ${user.shop_id} license is missing or expired. Requires key.`);
            // License expired/missing for the SHOP, send requiresLicense: true
            return res.json({
                success: true, // Login itself is successful (user exists, password matches)
                message: 'आपकी दुकान का लाइसेंस समाप्त हो गया है या सक्रिय नहीं है। कृपया दुकान के एडमिन द्वारा लाइसेंस सक्रिय करें।', // Updated message
                requiresLicense: true, // Tell client to show modal (only admin should activate)
                token: token, // Send token so admin can activate if needed
                user: tokenUser
            });
        }

        // --- Step 7: Successful Login (Shop License is valid) ---
        console.log(`DEBUG LOGIN: Shop ID ${user.shop_id} license is valid. Login successful for ${user.email}.`);
        res.json({
            success: true,
            message: 'लॉगिन सफल।',
            requiresLicense: false, // License is okay, no modal needed
            token: token,
            user: tokenUser
       });

    } catch (err) {
        console.error("Error logging in:", err.message, err.stack); // Log stack trace for better debugging
        res.status(500).json({ success: false, message: 'लॉगिन प्रक्रिया में सर्वर त्रुटि हुई: ' + err.message });
    }
});
// [ server.cjs में इस पूरे फ़ंक्शन को बदलें ]

// 5. License Activation Route (UPDATED FOR 'plan_type' AND 'add_ons')
app.post('/api/activate-license', authenticateJWT, async (req, res) => {
    const { licenseKey } = req.body;
    // --- ROLE CHECK ADDED: Only Admin should activate ---
    if (!req.user || req.user.role !== 'ADMIN') {
        return res.status(403).json({ success: false, message: 'केवल दुकान का एडमिन ही लाइसेंस सक्रिय कर सकता है।' });
    }
    // --- END ROLE CHECK ---
    const userId = req.user.id; // Keep user ID to mark who activated
    const shopId = req.user.shopId; // Get shop ID from the authenticated user

    if (!licenseKey) {
        return res.status(400).json({ success: false, message: 'लाइसेंस कुंजी आवश्यक है.' });
    }

    const keyHash = hashKey(licenseKey); // Hash the input key
    const client = await pool.connect();

    try {
        await client.query('BEGIN'); // Start transaction

        // 1. 🚀 FIX: 'plan_type' को भी 'licenses' टेबल से SELECT करें
        const licenseResult = await client.query(
            'SELECT expiry_date, user_id, shop_id, plan_type FROM licenses WHERE key_hash = $1 FOR UPDATE', // Lock the row
            [keyHash]
        );

        if (licenseResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({ success: false, message: 'अमान्य लाइसेंस कुंजी.' });
        }

        const license = licenseResult.rows[0];
        const newExpiryDate = new Date(license.expiry_date);
        const now = new Date();

        // 2. Check if the key itself is expired
        if (newExpiryDate < now) {
            await client.query('ROLLBACK');
            return res.status(400).json({ success: false, message: 'यह लाइसेंस कुंजी पहले ही समाप्त हो चुकी है.' });
        }

        // 3. Check if the key is already used by ANOTHER shop
        if (license.shop_id && license.shop_id !== shopId) {
            await client.query('ROLLBACK');
            return res.status(400).json({ success: false, message: 'यह लाइसेंस कुंजी पहले ही किसी अन्य दुकान द्वारा उपयोग की जा चुकी है.' });
        }
        
        // 4. 🚀 FIX: 'shops' टेबल में 'plan_type' और 'expiry_date' दोनों को अपडेट करें
        const newPlanType = license.plan_type || 'TRIAL'; // लाइसेंस से प्लान लें
        
        console.log(`DEBUG ACTIVATE: Updating shop ID ${shopId} expiry to ${newExpiryDate.toISOString()} and Plan to ${newPlanType}`);
        const updateShopResult = await client.query(
            'UPDATE shops SET license_expiry_date = $1, plan_type = $2 WHERE id = $3',
            [newExpiryDate, newPlanType, shopId]
        );
        if (updateShopResult.rowCount === 0) {
             await client.query('ROLLBACK'); // Rollback if shop wasn't found
             console.error(`License Activation Error: Shop ID ${shopId} not found.`);
             return res.status(404).json({ success: false, message: 'सक्रियण विफल: संबंधित दुकान नहीं मिली.' });
        }


        // 5. Mark the key as used by this user AND this shop in 'licenses' table
        console.log(`DEBUG ACTIVATE: Linking key ${keyHash} to user ID ${userId} and shop ID ${shopId}`);
        await client.query(
            'UPDATE licenses SET user_id = $1, shop_id = $2 WHERE key_hash = $3', // Add shop_id assignment
            [userId, shopId, keyHash] // Pass shopId as parameter
        );

        // --- Fetch updated data for the new token ---
        
        // 6. 🚀 FIX: 'shops' टेबल से 'plan_type', 'expiry_date' और 'add_ons' को फिर से SELECT करें
        const updatedShopLicenseResult = await pool.query(
           'SELECT license_expiry_date, plan_type, add_ons FROM shops WHERE id = $1',
           [shopId]
        );
        const updatedShopExpiryDate = updatedShopLicenseResult.rows[0].license_expiry_date;
        const updatedPlanType = updatedShopLicenseResult.rows[0].plan_type;
        const updatedAddOns = updatedShopLicenseResult.rows[0].add_ons || {}; // 🚀🚀🚀 नया
        
        console.log(`DEBUG ACTIVATE: Verified updated shop expiry: ${updatedShopExpiryDate} | Verified Plan: ${updatedPlanType}`);

        // 7. Fetch user data again (shop_name needed for payload)
       // [ ✅ Sahi Query (Ise Upar Wale Ki Jagah Paste Karein) ]
const updatedUserResult = await pool.query(
    'SELECT u.*, s.shop_name, s.shop_logo, s.license_expiry_date, s.plan_type, s.add_ons FROM users u JOIN shops s ON u.shop_id = s.id WHERE u.id = $1',
    [userId]
);
        const updatedUser = updatedUserResult.rows[0];

        // 8. 🚀 FIX: नए टोकन में 'plan_type' और 'add_ons' जोड़ें
        const tokenUser = {
            id: updatedUser.id,
            email: updatedUser.email,
            shopId: updatedUser.shop_id,
            name: updatedUser.name,
            mobile: updatedUser.mobile, // Include if added
            role: updatedUser.role,
            shopName: updatedUser.shop_name,
            licenseExpiryDate: updatedShopExpiryDate, // <<< Use UPDATED shop expiry date
            status: updatedUser.status,
            plan_type: updatedPlanType,
            add_ons: updatedAddOns // 🚀🚀🚀 नया ऐड-ऑन यहाँ जोड़ा गया
        };
        const token = jwt.sign(tokenUser, JWT_SECRET, { expiresIn: '30d' });

        await client.query('COMMIT'); // Commit transaction
        console.log(`DEBUG ACTIVATE: Shop ID ${shopId} successfully activated/renewed to ${updatedPlanType}.`);
        res.json({
            success: true,
            message: `दुकान का '${updatedPlanType}' लाइसेंस सफलतापूर्वक सक्रिय हो गया है। नई समाप्ति तिथि: ${newExpiryDate.toLocaleDateString()}`, // Updated message
            token: token, // Send back new token with updated expiry
            user: tokenUser // Send back potentially updated user info with new expiry
        });

    } catch (err) {
        await client.query('ROLLBACK'); // Rollback on any error
        console.error("License Activation Error:", err.message, err.stack); // Log stack trace
        res.status(500).json({ success: false, message: 'लाइसेंस सक्रियण विफल: ' + err.message });
    } finally {
        if (client) {
           client.release(); // Release client connection
        }
    }
});


// --- 6. User Management (Shop Admin Only) ---

// 6.1 Add New User to the Current Shop (PLAN LOCKED)
app.post('/api/users', authenticateJWT, checkRole('ADMIN'), checkPlan(['MEDIUM', 'PREMIUM']), async (req, res) => {
    // 🚀 NAYA: Plan check yahaan lagaya gaya hai ^^^^^^^^^^^^^^^^^^^^^^^^^^^
    
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
        res.json({ success: true, user: result.rows[0], message: 'यूजर सफलतापूर्वक जोड़ा गया.' });
    } catch (err) {
        if (err.constraint === 'users_email_key') {
            return res.status(409).json({ success: false, message: 'यह ईमेल आपकी शॉप में पहले से उपयोग में है।' });
        }
        console.error("Error adding user:", err.message);
        res.status(500).json({ success: false, message: 'यूजर जोड़ने में विफल: ' + err.message });
    }
});

// 6.2 Get All Users for the Current Shop (PLAN LOCKED)
app.get('/api/users', authenticateJWT, checkRole('MANAGER'), checkPlan(['MEDIUM', 'PREMIUM']), async (req, res) => { // Manager can view staff
    // 🚀 NAYA: Plan check yahaan lagaya gaya hai ^^^^^^^^^^^^^^^^^^^^^^^^^^^
    
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

// 6.3 Update User Role/Name/Status (PLAN LOCKED)
app.put('/api/users/:userId', authenticateJWT, checkRole('ADMIN'), checkPlan(['MEDIUM', 'PREMIUM']), async (req, res) => {
    // 🚀 NAYA: Plan check yahaan lagaya gaya hai ^^^^^^^^^^^^^^^^^^^^^^^^^^^
    
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

// 6.4 Delete User from the Current Shop (PLAN LOCKED)
app.delete('/api/users/:userId', authenticateJWT, checkRole('ADMIN'), checkPlan(['MEDIUM', 'PREMIUM']), async (req, res) => {
    // 🚀 NAYA: Plan check yahaan lagaya gaya hai ^^^^^^^^^^^^^^^^^^^^^^^^^^^
    
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
            return res.status(404).json({ success: false, message: 'यूजर नहीं मिला या आपकी शॉप से संबंधित नहीं है.' });
        }

        res.json({ success: true, message: 'यूजर सफलतापूर्वक डिलीट किया गया.' });
    } catch (err) {
        console.error("Error deleting user:", err.message);
        res.status(500).json({ success: false, message: 'यूजर डिलीट करने में विफल: ' + err.message });
    }
});

// --- 7. Stock Management ---

// 7.1 Stock Management - Add/Update (SCOPED & Transactional)
app.post('/api/stock', authenticateJWT, checkRole('CASHIER'), async (req, res) => {
    const { sku, name, quantity, unit, purchase_price, sale_price, gst, cost_price, category, product_attributes } = req.body;
    const shopId = req.shopId;

    if (!sku || !name || typeof quantity === 'undefined' || typeof purchase_price === 'undefined' || typeof sale_price === 'undefined') {
        return res.status(400).json({ success: false, message: 'SKU, नाम, मात्रा, खरीद मूल्य और बिक्री मूल्य आवश्यक हैं.' });
    }

    const safeQuantity = parseFloat(quantity);
    const safePurchasePrice = parseFloat(purchase_price);
    const safeSalePrice = parseFloat(sale_price);
    const safeGst = parseFloat(gst || 0);
    const safeCostPrice = parseFloat(cost_price || safePurchasePrice);

    if (isNaN(safeQuantity) || isNaN(safePurchasePrice) || isNaN(safeSalePrice)) {
        return res.status(400).json({ success: false, message: 'मात्रा, खरीद मूल्य और बिक्री मूल्य मान्य संख्याएँ होनी चाहिए.' });
    }

    try {
        // 🔑 Query now includes shop_id in INSERT and WHERE clause for ON CONFLICT
        const result = await pool.query(
            `INSERT INTO stock (shop_id, sku, name, quantity, unit, purchase_price, sale_price, gst, cost_price, category, product_attributes)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,$11)
             ON CONFLICT (shop_id, sku) DO UPDATE
             SET quantity = stock.quantity + EXCLUDED.quantity,
                 name = EXCLUDED.name,
                 purchase_price = EXCLUDED.purchase_price,
                 sale_price = EXCLUDED.sale_price,
                 gst = EXCLUDED.gst,
                 cost_price = EXCLUDED.cost_price,
                 category = EXCLUDED.category,
				 product_attributes = EXCLUDED.product_attributes,
                 updated_at = CURRENT_TIMESTAMP
             WHERE stock.shop_id = EXCLUDED.shop_id RETURNING *;`,
            [shopId, sku, name, safeQuantity, unit,
         safePurchasePrice, safeSalePrice, safeGst, safeCostPrice, category, product_attributes || null]
        );
		broadcastToShop(shopId, JSON.stringify({ type: 'DASHBOARD_UPDATE', view: 'stock' }));
        res.json({ success: true, stock: result.rows[0], message: 'स्टॉक सफलतापूर्वक जोड़ा/अपडेट किया गया.' });
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
        res.status(500).json({ success: false, message: 'स्टॉक सूची प्राप्त करने में विफल.' });
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
    } // <-- CORRECTED: Added missing brace here
});

// ------------------------------------------------------------------
// --- 🚀 START: NEW COMMENT (आपकी आवश्यकता के अनुसार) ---
// ------------------------------------------------------------------
//
// 5. बारकोड स्कैनिंग (Barcode Scanning)
// नीचे दिया गया एंडपॉइंट (/api/get-stock-item/:sku) बारकोड स्कैनिंग के लिए उपयोग किया जाता है।
// जब आप बारकोड स्कैनर से किसी उत्पाद को स्कैन करते हैं, तो वह स्कैनर
// उस उत्पाद के SKU (जैसे "89012345") को कीबोर्ड की तरह टाइप करता है।
// आपका फ्रंटएंड (वेबसाइट) उस SKU को पकड़ता है और इस API को कॉल करता है:
// GET /api/get-stock-item/89012345
// यह API उस आइटम का विवरण (नाम, मूल्य, आदि) वापस भेजता है,
// जिसे आपका POS सिस्टम कार्ट में जोड़ देता है।
//
// ------------------------------------------------------------------
// --- 🚀 END: NEW COMMENT ---
// ------------------------------------------------------------------

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
            res.status(404).json({ success: false, message: 'SKU स्टॉक में नहीं मिला या आपकी शॉप से संबंधित नहीं है.' });
        }
    } catch (error) {
        console.error("Error fetching single stock item:", error.message);
        res.status(500).json({ success: false, message: 'स्टॉक आइटम प्राप्त करने में विफल.' });
    }
});

// [ ✅ Is Naye Code ko Line 245 ke baad Paste Karein ]

// 7.4.1 (NEW) Get Next Available Numeric SKU (Point 3)
// Yeh API 'stock' table mein sabse bada numeric SKU dhoondhta hai aur +1 return karta hai
app.get('/api/stock/next-sku', authenticateJWT, checkRole('CASHIER'), async (req, res) => {
    const shopId = req.shopId;

    try {
        // Yeh query sirf un SKUs ko dekhegi jo poori tarah se numbers hain
        const result = await pool.query(
            `SELECT sku FROM stock 
             WHERE shop_id = $1 AND sku ~ '^[0-9]+$' 
             ORDER BY LENGTH(sku) DESC, sku DESC 
             LIMIT 1`,
            [shopId]
        );

        let nextSku = "1001"; // Default, agar koi numeric SKU nahi hai

        if (result.rows.length > 0) {
            const lastSku = result.rows[0].sku;
            const lastSkuNumber = parseInt(lastSku, 10);
            if (!isNaN(lastSkuNumber)) {
                nextSku = (lastSkuNumber + 1).toString();
            }
        }

        res.json({ success: true, nextSku: nextSku });

    } catch (error) {
        console.error("Error fetching next SKU:", error.message);
        res.status(500).json({ success: false, message: 'अगला SKU प्राप्त करने में विफल: ' + error.message });
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
           return res.status(404).json({ success: false, message: 'स्टॉक आइटम नहीं मिला या आपकी शॉप से संबंधित नहीं है.' });
        }
        res.json({ success: true, message: `SKU ${sku} सफलतापूर्वक स्टॉक से डिलीट किया गया.` });
    } catch (err) {
        console.error("Error deleting stock:", err.message);
        res.status(500).json({ success: false, message: 'स्टॉक आइटम डिलीट करने में विफल: ' + err.message });
    }
});
// --- 8. Invoice/Sales Management ---

//... (बाकी server.cjs कोड)

// 8.1 Process New Sale / Create Invoice (UPDATED FOR TALLY-GST REPORTING)
app.post('/api/invoices', authenticateJWT, async (req, res) => {
    // FIX 1: req.body से customerMobile वेरिएबल निकालें (आपका मौजूदा कोड)
    // TALLY UPDATE: हम 'place_of_supply' को भी req.body से लेंगे (यह फ्रंटएंड से आना चाहिए)
    const { customerName, customerMobile, total_amount, sale_items, place_of_supply } = req.body;
    const shopId = req.shopId;

    if (!total_amount || !Array.isArray(sale_items) || sale_items.length === 0) {
        return res.status(400).json({ success: false, message: 'कुल राशि और बिक्री आइटम आवश्यक हैं.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN'); // Transaction Start

        let customerId = null;
        // === TALLY UPDATE START: ग्राहक का GSTIN भी प्राप्त करें ===
        let customerGstin = null; 
        // === TALLY UPDATE END ===

        if (customerName && customerName.trim() !== 'अनाम ग्राहक') {
            
            // FIX 2: ग्राहक को नाम OR फोन से खोजें (आपका मौजूदा कोड)
            // TALLY UPDATE: SELECT में 'gstin' जोड़ा गया
            let customerResult = await client.query('SELECT id, gstin FROM customers WHERE shop_id = $1 AND name = $2', [shopId, customerName.trim()]);
            
            if (customerResult.rows.length === 0 && customerMobile) {
                // TALLY UPDATE: SELECT में 'gstin' जोड़ा गया
                 customerResult = await client.query('SELECT id, gstin FROM customers WHERE shop_id = $1 AND phone = $2', [shopId, customerMobile]);
            }

            if (customerResult.rows.length > 0) {
                customerId = customerResult.rows[0].id;
                customerGstin = customerResult.rows[0].gstin; // <<< TALLY UPDATE: GSTIN सहेजें
            } else {
                // FIX 3: नया ग्राहक बनाते समय phone कॉलम शामिल करें (आपका मौजूदा कोड)
                // TALLY UPDATE: RETURNING में 'gstin' जोड़ा गया
                const newCustomerResult = await client.query('INSERT INTO customers (shop_id, name, phone) VALUES ($1, $2, $3) RETURNING id, gstin', [shopId, customerName.trim(), customerMobile]);
                customerId = newCustomerResult.rows[0].id;
                customerGstin = newCustomerResult.rows[0].gstin; // <<< TALLY UPDATE: (यह NULL होगा, जो सही है)
            }
        }

        const safeTotalAmount = parseFloat(total_amount);
        let calculatedTotalCost = 0;

        // TALLY UPDATE: अपनी दुकान का GSTIN प्राप्त करें (यह जानने के लिए कि बिक्री Intra-State है या Inter-State)
        const profileRes = await client.query('SELECT gstin FROM company_profile WHERE shop_id = $1', [shopId]);
        const shopGstin = (profileRes.rows[0]?.gstin || '').substring(0, 2); // जैसे "27" (Maharashtra)
        const supplyPlace = (place_of_supply || shopGstin); // यदि 'place_of_supply' नहीं है, तो मानें कि यह Intra-State है

        // 🔑 Insert invoice with shop_id
        // TALLY UPDATE: 'customer_gstin' और 'place_of_supply' कॉलम जोड़े गए
        const invoiceResult = await client.query(
            `INSERT INTO invoices (shop_id, customer_id, total_amount, customer_gstin, place_of_supply) VALUES ($1, $2, $3, $4, $5) RETURNING id`,
            [shopId, customerId, safeTotalAmount, customerGstin, supplyPlace]
        );
        const invoiceId = invoiceResult.rows[0].id;

        for (const item of sale_items) {
            const safeQuantity = parseFloat(item.quantity);
            const safePurchasePrice = parseFloat(item.purchase_price || 0);
            const salePrice = parseFloat(item.sale_price);
            
            // === TALLY UPDATE START: CGST/SGST/IGST की गणना करें ===
            const gstRate = parseFloat(item.gst || 0);
            const taxableValue = (salePrice * safeQuantity); // मानते हैं कि sale_price टैक्स-रहित (tax-exclusive) है
            const totalGstAmount = taxableValue * (gstRate / 100);

            let cgst_amount = 0;
            let sgst_amount = 0;
            let igst_amount = 0;

            if (supplyPlace === shopGstin) {
                // Intra-State (राज्य के अंदर)
                cgst_amount = totalGstAmount / 2;
                sgst_amount = totalGstAmount / 2;
            } else {
                // Inter-State (राज्य के बाहर)
                igst_amount = totalGstAmount;
            }
            // === TALLY UPDATE END ===

            calculatedTotalCost += safeQuantity * safePurchasePrice;
            
            // TALLY UPDATE: 'invoice_items' INSERT क्वेरी में नए GST कॉलम जोड़े गए
            await client.query(
                `INSERT INTO invoice_items (
                    invoice_id, item_name, item_sku, quantity, sale_price, purchase_price, 
                   gst_rate, gst_amount, cgst_amount, sgst_amount, igst_amount, product_attributes
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
[
    invoiceId, item.name, item.sku, safeQuantity, salePrice, safePurchasePrice,
    gstRate, totalGstAmount, cgst_amount, sgst_amount, igst_amount, item.product_attributes || null
]
            );
            
            // 🔑 Update stock quantity (आपका मौजूदा कोड)
            await client.query(
                `UPDATE stock SET quantity = quantity - $1 WHERE sku = $2 AND shop_id = $3`,
                [safeQuantity, item.sku, shopId]
            );
        }

        // Update the invoice with the calculated total cost of goods sold (COGS) (आपका मौजूदा कोड)
        await client.query(
            `UPDATE invoices SET total_cost = $1 WHERE id = $2`,
            [calculatedTotalCost, invoiceId]
        );
		
        // ... (POST /api/invoices का कोड)
        await client.query('COMMIT'); // Transaction End

        // 🚀 NAYA: Dashboard को अपडेट करने के लिए ब्रॉडकास्ट करें
        broadcastToShop(shopId, JSON.stringify({ type: 'DASHBOARD_UPDATE', view: 'sales' }));

        res.json({ success: true, invoiceId: invoiceId, message: 'बिक्री सफलतापूर्वक दर्ज की गई और स्टॉक अपडेट किया गया.' });
    
    } catch (err) {
// ...

        res.json({ success: true, invoiceId: invoiceId, message: 'बिक्री सफलतापूर्वक दर्ज की गई और स्टॉक अपडेट किया गया.' });
    
    } catch (err) {
        await client.query('ROLLBACK');
        // Rollback on any error
        console.error("Error processing invoice:", err.message, err.stack); // Added stack trace
        res.status(500).json({ success: false, message: 'बिक्री विफल: ' + err.message });
    } finally {
        if (client) client.release();
    }
});


//... (बाकी server.cjs कोड)

// 8.2 Get Invoices/Sales List (SCOPED)
app.get('/api/invoices', authenticateJWT, async (req, res) => {
    const shopId = req.shopId;
    try {
        
        // --- पुराना लॉजिक (इसे डिस्टर्ब नहीं किया गया है, बस कमेंट किया गया है) ---
        // const result = await pool.query("SELECT i.id, i.total_amount, i.created_at, COALESCE(c.name, 'अज्ञात ग्राहक') AS customer_name, i.total_cost FROM invoices i LEFT JOIN customers c ON i.customer_id = c.id WHERE i.shop_id = $1 ORDER BY i.created_at DESC LIMIT 100", [shopId]);
        // --- पुराना लॉजिक समाप्त ---

        // --- नया लॉजिक (GST जोड़ने के लिए) ---
        // 🚀 फिक्स: invoice_items को JOIN किया और कुल gst_amount को SUM किया 
        const result = await pool.query(`
            SELECT 
                i.id, 
                i.total_amount, 
                i.created_at, 
               COALESCE(c.name, 'अज्ञात ग्राहक') AS customer_name,
			   c.phone AS customer_phone, 
			   i.total_cost,
                COALESCE(SUM(ii.gst_amount), 0) AS total_gst
            FROM invoices i 
            LEFT JOIN customers c ON i.customer_id = c.id
            LEFT JOIN invoice_items ii ON i.id = ii.invoice_id
            WHERE i.shop_id = $1 
            GROUP BY i.id, c.name, c.phone
            ORDER BY i.created_at DESC 
            LIMIT 100
        `, [shopId]);
        // --- नया लॉजिक समाप्त ---

        res.json({ success: true, sales: result.rows, message: "चालान सफलतापूर्वक लोड किए गए।" }); // Corrected: Single line
    } catch (error) {
        console.error("Error fetching invoices list:", error.message);
        res.status(500).json({ success: false, message: 'चालान सूची प्राप्त करने में विफल.' });
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
            return res.status(404).json({ success: false, message: 'चालान नहीं मिला या आपकी शॉप से संबंधित नहीं है.' });
        }

        // फिक्स: SELECT में gst_rate और gst_amount को जोड़ा गया
        const itemsResult = await pool.query(
           `SELECT 
    item_name, item_sku, quantity, sale_price, purchase_price, 
    gst_rate, gst_amount, product_attributes
 FROM invoice_items 
 WHERE invoice_id = $1`,
            [invoiceId]
        );

        const invoice = invoiceResult.rows[0];
        invoice.items = itemsResult.rows;

        res.json({ success: true, invoice: invoice });
    } catch (error) {
        console.error("Error fetching invoice details:", error.message);
        res.status(500).json({ success: false, message: 'चालान विवरण प्राप्त करने में विफल.' });
    }
});

// --- 9. Customer Management ---

/// 9.1 Add/Update Customer (PLAN LOCKED)
app.post('/api/customers', authenticateJWT, checkPlan(['MEDIUM', 'PREMIUM']), async (req, res) => {
// 🚀 NAYA: Plan check yahaan lagaya gaya hai ^^^^^^^^^^^^^^^^^^^^^^^^^^^

    // सुनिश्चित करें कि 'phone' req.body से डीकंस्ट्रक्ट हो रहा है
    const { id, name, phone, email, address, gstin, balance } = req.body; 
    const shopId = req.shopId;

    if (!name || !phone) {
        return res.status(400).json({ success: false, message: 'नाम और फ़ोन आवश्यक हैं।' });
    }

    try {
        let result;

        if (id) {
            // CASE 1: ग्राहक को ID के आधार पर अपडेट करना (UPDATE)
            result = await pool.query(
                // FIX: सुनिश्चित करें कि 'phone' को UPDATE स्टेटमेंट में शामिल किया गया है
                'UPDATE customers SET name = $1, phone = $2, email = $3, address = $4, gstin = $5, balance = $6 WHERE id = $7 AND shop_id = $8 RETURNING *',
                [name, phone, email || null, address || null, gstin || null, balance || 0, id, shopId]
            );
            
            // यदि अपडेट सफल होता है
            if (result.rows.length === 0) {
                return res.status(404).json({ success: false, message: 'ग्राहक नहीं मिला या आपको इसे अपडेट करने की अनुमति नहीं है।' });
            }
            res.json({ success: true, customer: result.rows[0], message: 'ग्राहक सफलतापूर्वक अपडेट किया गया।' });
            
        } else {
            // CASE 2: नया ग्राहक बनाना (INSERT)
            // डुप्लिकेट जाँच लॉजिक यहाँ रहेगा...

            // यदि ग्राहक मौजूद नहीं है, तो नया INSERT करें
            // FIX: सुनिश्चित करें कि 'phone' को INSERT स्टेटमेंट में शामिल किया गया है
            result = await pool.query(
                'INSERT INTO customers (shop_id, name, phone, email, address, gstin, balance) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
                [shopId, name, phone, email || null, address || null, gstin || null, balance || 0]
            );

            res.status(201).json({ success: true, customer: result.rows[0], message: 'नया ग्राहक सफलतापूर्वक बनाया गया।' });
        }

    } catch (err) {
        console.error("Error adding/updating customer:", err.message);
        res.status(500).json({ success: false, message: 'ग्राहक जोड़ने/अपडेट करने में विफल.' });
    }
});

// ... (अन्य कोड)

// 9.2 Get All Customers (PLAN LOCKED)
app.get('/api/customers', authenticateJWT, checkPlan(['MEDIUM', 'PREMIUM']), async (req, res) => {
// 🚀 NAYA: Plan check yahaan lagaya gaya hai ^^^^^^^^^^^^^^^^^^^^^^^^^^^

    const shopId = req.shopId;
    try {
        const result = await pool.query('SELECT * FROM customers WHERE shop_id = $1 ORDER BY name ASC', [shopId]);
        res.json({ success: true, customers: result.rows });
    } catch (err) {
        console.error("Error fetching customers:", err.message);
        res.status(500).json({ success: false, message: 'ग्राहक सूची प्राप्त करने में विफल.' });
    }
});

// 9.3 Get Customer by ID (PLAN LOCKED)
app.get('/api/customers/:customerId', authenticateJWT, checkPlan(['MEDIUM', 'PREMIUM']), async (req, res) => {
// 🚀 NAYA: Plan check yahaan lagaya gaya hai ^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    const { customerId } = req.params;
    const shopId = req.shopId;
    try {
        const result = await pool.query('SELECT * FROM customers WHERE id = $1 AND shop_id = $2', [customerId, shopId]);
        if (result.rows.length > 0) {
            res.json({ success: true, customer: result.rows[0] });
        } else {
           res.status(404).json({ success: false, message: 'ग्राहक नहीं मिला या आपकी शॉप से संबंधित नहीं है.' });
        }
    } catch (err) {
        console.error("Error fetching customer:", err.message);
        res.status(500).json({ success: false, message: 'ग्राहक विवरण प्राप्त करने में विफल.' });
    }
});
// --- 10. Expense Management ---

// 10.1 Add New Expense (SCOPED)
app.post('/api/expenses', authenticateJWT, checkRole('MANAGER'), async (req, res) => { // Manager and above
    const { description, category, amount, date } = req.body;
    const shopId = req.shopId;

    if (!description || !amount) {
        return res.status(400).json({ success: false, message: 'विवरण और राशि आवश्यक हैं.' });
    }

    const safeAmount = parseFloat(amount);
    if (isNaN(safeAmount) || safeAmount <= 0) {
        return res.status(400).json({ success: false, message: 'राशि एक मान्य धनात्मक संख्या होनी चाहिए.' });
    }

    // Use CURRENT_TIMESTAMP if date is not provided/invalid
    const created_at = date && !isNaN(new Date(date)) ? new Date(date) : new Date();

    try {
        const result = await pool.query(
            'INSERT INTO expenses (shop_id, description, category, amount, created_at) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [shopId, description, category, safeAmount, created_at]
        );
		broadcastToShop(shopId, JSON.stringify({ type: 'DASHBOARD_UPDATE', view: 'expenses' }));
        res.json({ success: true, expense: result.rows[0], message: 'खर्च सफलतापूर्वक जोड़ा गया.' });
    } catch (err) {
        console.error("Error adding expense:", err.message);
        res.status(500).json({ success: false, message: 'खर्च जोड़ने में विफल: ' + err.message });
    }
});
// [ server.cjs फ़ाइल में यह कोड जोड़ें ]

// -----------------------------------------------------------------------------
// 10.5.
//PURCHASE MANAGEMENT (NEW)
// -----------------------------------------------------------------------------
// (यह एक सरल कार्यान्वयन है। यह स्टॉक को स्वचालित रूप से अपडेट नहीं करता है।)

// 10.5.1 Add New Purchase Record (SCOPED)
app.post('/api/purchases', authenticateJWT, checkRole('MANAGER'), async (req, res) => {
    // 'created_at' को 'date' के रूप में स्वीकार करें, जैसा कि expenses करता है
    const { supplier_name, item_details, total_cost, date } = req.body;
    const shopId = req.shopId;

    if (!supplier_name || !total_cost) {
        return res.status(400).json({ success: false, message: 'आपूर्तिकर्ता (Supplier) का नाम और कुल लागत आवश्यक हैं.' });
    }

    const safeTotalCost = parseFloat(total_cost);
    if (isNaN(safeTotalCost) || safeTotalCost <= 0) {
        return res.status(400).json({ success: false, message: 'लागत एक मान्य धनात्मक संख्या होनी चाहिए.' });
    }

    const purchase_date = date && !isNaN(new Date(date)) ? new Date(date) : new Date();
    try {
        const result = await pool.query(
            'INSERT INTO purchases (shop_id, supplier_name, item_details, total_cost, created_at) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [shopId, supplier_name, item_details || 'N/A', safeTotalCost, purchase_date]
        );
        res.json({ success: true, purchase: result.rows[0], message: 'खरीद सफलतापूर्वक जोड़ी गई.' });
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
        res.status(500).json({ success: false, message: 'खरीद सूची प्राप्त करने में विफल.' });
    }
});
// 10.5.3 Delete Purchase (SCOPED)
app.delete('/api/purchases/:purchaseId', authenticateJWT, checkRole('ADMIN'), async (req, res) => {
    const { purchaseId } = req.params;
    const shopId = req.shopId;
    try {
        const result = await pool.query('DELETE FROM purchases WHERE id = $1 AND shop_id = $2', [purchaseId, shopId]);
        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, message: 'खरीद रिकॉर्ड नहीं मिला या आपकी शॉप से संबंधित नहीं है.' });
        }
        res.json({ success: true, message: 'खरीद रिकॉर्ड सफलतापूर्वक डिलीट किया गया.' });
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
        res.status(500).json({ success: false, message: 'खर्च सूची प्राप्त करने में विफल.' });
    }
});
// 10.3 Delete Expense (SCOPED)
app.delete('/api/expenses/:expenseId', authenticateJWT, checkRole('ADMIN'), async (req, res) => { // Admin only
    const { expenseId } = req.params;
    const shopId = req.shopId;
    try {
        const result = await pool.query('DELETE FROM expenses WHERE id = $1 AND shop_id = $2', [expenseId, shopId]);
        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, message: 'खर्च नहीं मिला या आपकी शॉप से संबंधित नहीं है.' });
        }
        res.json({ success: true, message: 'खर्च सफलतापूर्वक डिलीट किया गया.' });
    } catch (err) {
        console.error("Error deleting expense:", err.message);
        res.status(500).json({ success: false, message: 'खर्च डिलीट करने में विफल: ' + err.message });
    }
});
// --- 11. Reporting and Dashboard (Admin/Manager) ---

// 11.1 Get Dashboard Summary (Sales, Costs, Profit, Stock Value)
app.get('/api/dashboard/summary', authenticateJWT, checkRole('CASHIER'), async (req, res) => {
    const shopId = req.shopId;
    const { days = 30 } = req.query; // Default to last 30 days
    const daysInt = parseInt(days);
    if (isNaN(daysInt) || daysInt <= 0) {
        return res.status(400).json({ success: false, message: 'दिनों की संख्या मान्य होनी चाहिए.' });
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
        // यह अंतिम और सही Response है
        res.json({
            success: true,
            days: daysInt,
            summary: {
                totalSales: parseFloat(totalSales.toFixed(2)),
                totalCogs: parseFloat(totalCogs.toFixed(2)),
                grossProfit: parseFloat(grossProfit.toFixed(2)),
                totalExpenses: parseFloat(totalExpenses.toFixed(2)),
                netProfit: parseFloat(netProfit.toFixed(2)),
                // FIX: .toFixed() को parseFloat() के बाहर ले जाया गया
                currentStockValue: parseFloat(stockData.stock_value).toFixed(2)
            },
            message: `पिछले ${daysInt} दिनों का सारांश सफलतापूर्वक प्राप्त हुआ.`
        });
    } catch (err) {
        console.error("Error fetching dashboard summary:", err.message);
        // सुनिश्चित करें कि error होने पर भी response एक ही बार जाए
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
        return res.status(400).json({ success: false, message: 'शॉप का नाम खाली नहीं हो सकता.' });
    }

    try {
        // शॉप का नाम और लोगो (Base64) अपडेट करें
        await pool.query(
            'UPDATE shops SET shop_name = $1, shop_logo = $2 WHERE id = $3',
            [shop_name, shop_logo, shopId]
        );

        // यूज़र का डेटा पुनः प्राप्त करें (क्योंकि 'shopName' बदल गया होगा)
       // [ ✅ Sahi Query (Ise Line 346 par Paste Karein) ]
        const updatedUserResult = await pool.query(
            'SELECT u.*, s.shop_name, s.shop_logo, s.license_expiry_date, s.plan_type, s.add_ons FROM users u JOIN shops s ON u.shop_id = s.id WHERE u.id = $1',
            [userId]
        );
      // [ ✅ Sahi Token Object (Ise Upar Wale Ki Jagah Paste Karein) ]
const updatedUser = updatedUserResult.rows[0];

const tokenUser = {
    id: updatedUser.id,
    email: updatedUser.email,
    shopId: updatedUser.shop_id,
    name: updatedUser.name,
    role: updatedUser.role,
    shopName: updatedUser.shop_name, // (Updated)
    shopLogo: updatedUser.shop_logo, // (Updated)
    status: updatedUser.status,
    
    // --- 🚀 FIX: Yeh 3 lines jodi gayi hain ---
    licenseExpiryDate: updatedUser.license_expiry_date, // Ab yeh 'shops' table se aa raha hai
    plan_type: updatedUser.plan_type || 'TRIAL',        // Ab yeh 'shops' table se aa raha hai
    add_ons: updatedUser.add_ons || {}                // Ab yeh 'shops' table se aa raha hai
};
        const token = jwt.sign(tokenUser, JWT_SECRET, { expiresIn: '30d' });

        res.json({
            success: true,
            message: 'शॉप सेटिंग्स सफलतापूर्वक अपडेट की गईं.',
            token: token,
            user: tokenUser
        });
    } catch (err) {
        console.error("Error updating shop settings:", err.message);
        res.status(500).json({ success: false, message: 'सेटिंग्स अपडेट करने में विफल: ' + err.message });
    }
});
// 11.6 Shop-Specific Backup (PLAN LOCKED)
app.get('/api/backup', authenticateJWT, checkPlan(['MEDIUM', 'PREMIUM'], 'has_backup'), async (req, res) => {
    // 🚀 NAYA: Plan check yahaan lagaya gaya hai ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

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
});// 12.1 Get All Users (Global)
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
        return res.status(403).json({ success: false, message: 'आप खुद को अक्षम (disable) नहीं कर सकते.' });
    }

    try {
        await pool.query(
           'UPDATE users SET name = $1, role = $2, status = $3 WHERE id = $4',
            [name, role, status, userId]
        );
        res.json({ success: true, message: 'यूज़र सफलतापूर्वक अपडेट किया गया.' });
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
app.get('/api/dashboard/sales-by-day', authenticateJWT, checkRole('CASHIER'), async (req, res) => {
    const shopId = req.shopId;
    const { days = 30 } = req.query; // Default to last 30 days
    const daysInt = parseInt(days);
    if (isNaN(daysInt) || daysInt <= 0) {
        return res.status(400).json({ success: false, message: 'दिनों की संख्या मान्य होनी चाहिए.' });
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
        return res.status(400).json({ success: false, message: 'SQL क्वेरी आवश्यक है.' });
    }

    // 🛑 SAFETY CHECK: Prevent dropping critical tables
    const lowerQuery = query.toLowerCase().trim();
    if (lowerQuery.includes('drop table') || lowerQuery.includes('truncate table')) {
      const forbiddenTables = ['users', 'shops', 'licenses'];
        if (forbiddenTables.some(table => lowerQuery.includes(table))) {
            return res.status(403).json({ success: false, message: 'इस टेबल पर DROP/TRUNCATE की अनुमति नहीं है.' });
        }
    }

    try {
        // Execute the user-provided query
        const result = await pool.query(query);
        res.json({
            success: true,
            message: 'क्वेरी सफलतापूर्वक निष्पादित (Executed).',
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


// [ ✅ Yeh Sahi Code Hai - Ise Line 380 par Paste Karein ]

// 13.1 Run Daily Closing (PLAN LOCKED)
app.post('/api/closing/run', authenticateJWT, checkRole('MANAGER'), checkPlan(['MEDIUM', 'PREMIUM'], 'has_closing'), async (req, res) => {
    const shopId = req.shopId;

    // --- 🚀 YEH HAI AAPKA FIX (Timezone galti theek ki gayi) ---
    const today = new Date(); // Maan lijiye abhi 10 baje hain
    // 'startDate' hamesha "aaj subah 00:00" hoga
    const startDate = new Date(today.getFullYear(), today.getMonth(), today.getDate(), 0, 0, 0, 0); 
    // 'endDate' hamesha "aaj raat 23:59" hoga
    const endDate = new Date(today.getFullYear(), today.getMonth(), today.getDate(), 23, 59, 59, 999); 
    // --- FIX END ---

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 1. Check if closing already ran (Using startDate for the check)
        // 🚀 FIX: Yahaan 'today' ki jagah 'startDate' ka istemaal karein
        const checkResult = await client.query(
            'SELECT id FROM daily_closings WHERE shop_id = $1 AND closing_date = $2',
            [shopId, startDate] // 🚀 FIX
        );

        if (checkResult.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({ success: false, message: 'आज की क्लोजिंग पहले ही रन हो चुकी है.' });
        }

        // 2. Calculate Sales (Using the new date range)
        const salesResult = await client.query(
            `SELECT COALESCE(SUM(total_amount), 0) AS sales, COALESCE(SUM(total_cost), 0) AS cogs
             FROM invoices
             WHERE shop_id = $1 AND created_at >= $2 AND created_at <= $3`, // 🚀 FIX
            [shopId, startDate, endDate] // 🚀 FIX
        );
        const { sales, cogs } = salesResult.rows[0];

        // 3. Calculate Expenses (Using the new date range)
        const expensesResult = await client.query(
            `SELECT COALESCE(SUM(amount), 0) AS expenses
             FROM expenses
             WHERE shop_id = $1 AND created_at >= $2 AND created_at <= $3`, // 🚀 FIX
            [shopId, startDate, endDate] // 🚀 FIX
        );
        const { expenses } = expensesResult.rows[0];

        // 4. Calculate Net Profit
        const netProfit = parseFloat(sales) - parseFloat(cogs) - parseFloat(expenses);

        // 5. Save Closing Report (Using startDate as the 'closing_date')
        // 🚀 FIX: Yahaan 'today' ki jagah 'startDate' ka istemaal karein
        await client.query(
            `INSERT INTO daily_closings (shop_id, closing_date, total_sales, total_cogs, total_expenses, net_profit)
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [shopId, startDate, parseFloat(sales), parseFloat(cogs), parseFloat(expenses), netProfit] // 🚀 FIX
        );

        await client.query('COMMIT');
        res.json({
            success: true,
            message: `आज (${startDate.toLocaleDateString()}) की क्लोजिंग सफलतापूर्वक सहेज ली गई.`,
            report: {
                date: startDate.toLocaleDateString(),
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

// 13.2 Get All Closing Reports (PLAN LOCKED)
app.get('/api/closing/reports', authenticateJWT, checkRole('MANAGER'), checkPlan(['MEDIUM', 'PREMIUM'], 'has_closing'), async (req, res) => {
    // 🚀 NAYA: Plan check yahaan lagaya gaya hai ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

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
});// -----------------------------------------------------------------------------
// --- 🚀 START: NEW API SECTION (आपकी नई आवश्यकताओं के लिए) ---
// --- 14. ADVANCED REPORTING API (NEW) ---
// -----------------------------------------------------------------------------

// 14.1 Simplified Profit & Loss Report (PLAN LOCKED)
app.get('/api/reports/profit-loss', authenticateJWT, checkRole('MANAGER'), checkPlan(['MEDIUM', 'PREMIUM']), async (req, res) => {
    // 🚀 NAYA: Plan check yahaan lagaya gaya hai ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    const shopId = req.shopId;
    const { startDate, endDate } = req.query;

    if (!startDate || !endDate) {
        return res.status(400).json({ success: false, message: 'StartDate और EndDate आवश्यक हैं.' });
    }
	const endDateObj = new Date(endDate);
    endDateObj.setDate(endDateObj.getDate() + 1);

    const client = await pool.connect();
    try {
        // 1. आय (Revenue) और COGS (Cost of Goods Sold)
        const salesResult = await client.query(
            `SELECT
                COALESCE(SUM(total_amount), 0) AS total_sales,
                COALESCE(SUM(total_cost), 0) AS total_cogs
             FROM invoices
            WHERE shop_id = $1 AND created_at >= $2 AND created_at < $3`,
		    [shopId, startDate, endDateObj] 
        );

        // 2. खर्च (Expenses) - श्रेणी के अनुसार (By Category)
        const expenseResult = await client.query(
            `SELECT category, COALESCE(SUM(amount), 0) AS total_amount
             FROM expenses
             WHERE shop_id = $1 AND created_at >= $2 AND created_at < $3
             GROUP BY category`,
            [shopId, startDate, endDateObj]
        );
        
        const { total_sales, total_cogs } = salesResult.rows[0];
        const sales = parseFloat(total_sales);
        const cogs = parseFloat(total_cogs);

        let total_expenses = 0;
        const detailedExpenses = expenseResult.rows.map(exp => {
            const amount = parseFloat(exp.total_amount);
            total_expenses += amount;
            return { description: exp.category || 'अन्य खर्च', amount: amount.toFixed(2) };
        });

        // 3. गणना (Calculations)
        const grossProfit = sales - cogs;
        const netProfit = grossProfit - total_expenses;

        // 4. रिपोर्ट को T-Account जैसा संतुलित (Balance) करें
        let debitEntries = [
            { description: 'बेचे गए माल की लागत (COGS)', amount: cogs.toFixed(2) },
            ...detailedExpenses // सभी खर्चों को अलग-अलग दिखाएं
        ];
        let creditEntries = [
            { description: 'कुल बिक्री (Revenue)', amount: sales.toFixed(2) }
        ];

        let totalDebit = cogs + total_expenses;
        let totalCredit = sales;

        if (netProfit >= 0) {
            // शुद्ध लाभ (Net Profit)
            debitEntries.push({ description: 'शुद्ध लाभ (Net Profit)', amount: netProfit.toFixed(2) });
            totalDebit += netProfit;
        } else {
            // शुद्ध हानि (Net Loss)
            creditEntries.push({ description: 'शुद्ध हानि (Net Loss)', amount: Math.abs(netProfit).toFixed(2) });
            totalCredit += Math.abs(netProfit);
        }

        const plReport = {
            debit: debitEntries,
            credit: creditEntries,
            totalDebit: totalDebit.toFixed(2),
            totalCredit: totalCredit.toFixed(2),
            netProfit: netProfit.toFixed(2) // Balance Sheet के लिए
        };

        res.json({ success: true, report: plReport });

    } catch (err) {
        console.error("Error generating P&L report:", err.message, err.stack);
        res.status(500).json({ success: false, message: 'P&L रिपोर्ट बनाने में विफल: ' + err.message });
    } finally {
        if (client) client.release();
    }
});

// 14.2 Simplified Balance Sheet Report (PLAN LOCKED)
app.get('/api/reports/balance-sheet', authenticateJWT, checkRole('MANAGER'), checkPlan(['MEDIUM', 'PREMIUM']), async (req, res) => {
    // 🚀 NAYA: Plan check yahaan lagaya gaya hai ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    const shopId = req.shopId;
    const today = new Date().toISOString(); 

    const client = await pool.connect();
    try {
        // --- P&L की गणना करें (Net Profit जानने के लिए) ---
        // ... (P&L calculations - no change) ...
        const salesResult = await client.query(
            `SELECT COALESCE(SUM(total_amount), 0) AS total_sales, COALESCE(SUM(total_cost), 0) AS total_cogs
             FROM invoices WHERE shop_id = $1 AND created_at <= $2`,
            [shopId, today]
        );
        const expenseResult = await client.query(
            `SELECT COALESCE(SUM(amount), 0) AS total_expenses
             FROM expenses WHERE shop_id = $1 AND created_at <= $2`,
            [shopId, today]
        );
        const { total_sales, total_cogs } = salesResult.rows[0];
        const { total_expenses } = expenseResult.rows[0];
        const grossProfit = parseFloat(total_sales) - parseFloat(total_cogs);
        const netProfit = grossProfit - parseFloat(total_expenses);

        // --- Assets (परिसंपत्तियां) ---
        // ... (Inventory and A/R calculations - no change) ...
        const stockValueResult = await client.query(
            `SELECT COALESCE(SUM(quantity * purchase_price), 0) AS inventory_value FROM stock WHERE shop_id = $1`,
            [shopId]
        );
        const inventory_value = parseFloat(stockValueResult.rows[0].inventory_value);

        const accountsReceivableResult = await client.query(
            `SELECT COALESCE(SUM(balance), 0) AS accounts_receivable FROM customers WHERE shop_id = $1 AND balance > 0`,
            [shopId]
        );
        const accounts_receivable = parseFloat(accountsReceivableResult.rows[0].accounts_receivable);

        // --- Liabilities & Equity (देनदारियां और इक्विटी) ---
        
        // 🚀 NEW: Fetch Opening Capital from company_profile
        const capitalResult = await client.query('SELECT opening_capital FROM company_profile WHERE shop_id = $1', [shopId]);
        // 👈 FIX: Capital को fetch करें
        const savedOpeningCapital = parseFloat(capitalResult.rows[0]?.opening_capital || 0);

        // ... (GST Payable calculation - no change) ...
        const salesGstRes = await client.query(`SELECT COALESCE(SUM(ii.gst_amount), 0) AS total_sales_gst FROM invoice_items ii JOIN invoices i ON ii.invoice_id = i.id WHERE i.shop_id = $1 AND i.created_at <= $2`, [shopId, today]);
        const totalSalesGst = parseFloat(salesGstRes.rows[0].total_sales_gst || 0);

        const purchaseItcRes = await client.query(`SELECT SUM(COALESCE((gst_details->>'igst')::numeric, 0) + COALESCE((gst_details->>'cgst')::numeric, 0) + COALESCE((gst_details->>'sgst')::numeric, 0)) AS total_purchase_itc FROM purchases WHERE shop_id = $1 AND created_at <= $2 AND gst_details IS NOT NULL`, [shopId, today]);
        const totalPurchaseItc = parseFloat(purchaseItcRes.rows[0].total_purchase_itc || 0);

        const netGstPayable = totalSalesGst - totalPurchaseItc;
        
        // 4. Accounts Payable (A/P) और Capital - Hardcodes (Capital now uses fetched value)
        const accounts_payable = 0; // 🚀 FIX: A/P tracking needs major upgrade
        const opening_capital = savedOpeningCapital; // 👈 FIX: Use fetched value instead of 0
        const retained_earnings = netProfit; 

        // 5. Cash Balance (Balancing Figure)
        const totalLiabilitiesAndEquity = accounts_payable + netGstPayable + opening_capital + retained_earnings;
        const cash_balance = totalLiabilitiesAndEquity - inventory_value - accounts_receivable;


        // --- अंतिम रिपोर्ट (Detailed) ---
        const bsReport = {
            assets: [
                { description: 'करेंट एसेट्स: स्टॉक (Inventory)', amount: inventory_value.toFixed(2) },
                { description: 'करेंट एसेट्स: ग्राहक शेष (A/R)', amount: accounts_receivable.toFixed(2) },
                { description: 'करेंट एसेट्स: कैश/बैंक बैलेंस', amount: cash_balance.toFixed(2), note: "Net L&E के आधार पर" }
            ],
            liabilities: [
                { description: 'करेंट लायबिलिटी: वेंडर देय (A/P)', amount: accounts_payable.toFixed(2) },
                { description: 'करेंट लायबिलिटी: GST/टैक्स देय', amount: netGstPayable.toFixed(2) }
            ],
            equity: [
                { description: 'ओपनिंग कैपिटल (पूंजी)', amount: opening_capital.toFixed(2) }, // 👈 FIX: Fetched value
                { description: 'रिटेन्ड अर्निंग्स (Net Profit/Loss)', amount: retained_earnings.toFixed(2) }
            ],
            // Totals
            totalAssets: (inventory_value + accounts_receivable + cash_balance).toFixed(2),
            totalLiabilitiesAndEquity: totalLiabilitiesAndEquity.toFixed(2)
        };
        
        console.log("Balance Sheet Check (Assets - L&E):", (bsReport.totalAssets - totalLiabilitiesAndEquity).toFixed(2));
        res.json({ success: true, report: bsReport });

    } catch (err) {
        console.error("Error generating Balance Sheet:", err.message, err.stack);
        res.status(500).json({ success: false, message: 'बैलेंस शीट बनाने में विफल: ' + err.message });
    } finally {
        if (client) client.release();
    }
});

// 14.3 Product-wise Sales Report
app.get('/api/reports/product-sales', authenticateJWT, checkRole('MANAGER'), async (req, res) => {
    const shopId = req.shopId;
    const { startDate, endDate } = req.query;

    if (!startDate || !endDate) {
        return res.status(400).json({ success: false, message: 'StartDate और EndDate आवश्यक हैं.' });
    }

    try {
        const result = await pool.query(
            `SELECT
                ii.item_name,
                ii.item_sku,
                SUM(ii.quantity) AS total_quantity_sold,
                SUM(ii.quantity * ii.sale_price) AS total_revenue,
                SUM(ii.quantity * ii.purchase_price) AS total_cost,
                SUM(ii.quantity * (ii.sale_price - ii.purchase_price)) AS total_profit
             FROM invoice_items ii
             JOIN invoices i ON ii.invoice_id = i.id
             WHERE i.shop_id = $1 AND i.created_at >= $2 AND i.created_at <= $3
             GROUP BY ii.item_name, ii.item_sku
             ORDER BY total_profit DESC`,
            [shopId, startDate, endDate]
        );

        res.json({ success: true, report: result.rows });
    } catch (err) {
        console.error("Error generating product-wise report:", err.message);
        res.status(500).json({ success: false, message: 'उत्पाद-वार रिपोर्ट बनाने में विफल: ' + err.message });
    }
});

// [ ✅ Is Poore Naye Function ko Line 442 par Paste Karein ]

// 14.4 Download Product-wise Sales Report (CSV)
app.get('/api/reports/product-sales/download', authenticateJWT, checkRole('MANAGER'), async (req, res) => {
    const shopId = req.shopId;
    const { startDate, endDate } = req.query; // Yeh "" (khaali string) ho sakti hai

    // SQL query ko dynamic banayein
    let queryParams = [shopId];
    let dateFilter = ""; // Default: koi filter nahi

    // Agar dono date di gayi hain, tabhi filter lagayein
    if (startDate && endDate) {
        queryParams.push(startDate);
        queryParams.push(endDate);
        // 1 din jod dein taaki 'endDate' shaamil ho
        dateFilter = ` AND i.created_at >= $2 AND i.created_at < (DATE '$3' + INTERVAL '1 day')`;
    }

    try {
        const queryText = `
            SELECT
                ii.item_name,
                ii.item_sku,
                SUM(ii.quantity) AS total_quantity_sold,
                SUM(ii.quantity * ii.sale_price) AS total_revenue,
                SUM(ii.quantity * ii.purchase_price) AS total_cost,
                SUM(ii.quantity * (ii.sale_price - ii.purchase_price)) AS total_profit
             FROM invoice_items ii
             JOIN invoices i ON ii.invoice_id = i.id
             WHERE i.shop_id = $1 ${dateFilter}
             GROUP BY ii.item_name, ii.item_sku
             ORDER BY ii.item_name ASC`;

        const result = await pool.query(queryText, queryParams);

        // CSV data banaayein
        let csv = "SKU,ItemName,QuantitySold,TotalRevenue,TotalCost,TotalProfit\n";
        for (const row of result.rows) {
            csv += `${row.item_sku},"${row.item_name}",${row.total_quantity_sold},${row.total_revenue},${row.total_cost},${row.total_profit}\n`;
        }

        res.header('Content-Type', 'text/csv');
        // File ka naam bhi dynamic rakhein
        const fileName = `product_sales_${startDate || 'all'}_to_${endDate || 'all'}.csv`;
        res.attachment(fileName);
        res.send(csv);

    } catch (err) {
        console.error("Error downloading product-wise report:", err.message);
        res.status(500).json({ success: false, message: 'रिपोर्ट डाउनलोड करने में विफल: ' + err.message });
    }
});
// 14.5 Get Recently Sold Items (For POS SKU List)
app.get('/api/reports/recently-sold-items', authenticateJWT, async (req, res) => {
    const shopId = req.shopId;
    try {
        // पिछले 30 दिनों में बेचे गए 20 सबसे लोकप्रिय आइटम
        const result = await pool.query(
            `SELECT
                ii.item_sku,
                ii.item_name,
                MAX(i.created_at) as last_sold_date
             FROM invoice_items ii
             JOIN invoices i ON ii.invoice_id = i.id
             WHERE i.shop_id = $1 AND i.created_at >= (CURRENT_DATE - INTERVAL '30 days')
             GROUP BY ii.item_sku, ii.item_name
             ORDER BY last_sold_date DESC
             LIMIT 20`,
            [shopId]
        );
        res.json({ success: true, items: result.rows });
    } catch (err) {
        console.error("Error fetching recently sold items:", err.message);
        res.status(500).json({ success: false, message: 'हाल ही में बेचे गए आइटम लाने में विफल: ' + err.message });
    }
});


// -----------------------------------------------------------------------------
// --- 🚀 START: NEW API SECTION (आपकी नई आवश्यकताओं के लिए) ---
// --- 15. GST REPORTING API (NEW - SIMPLIFIED) ---
// -----------------------------------------------------------------------------

// 15.1 Get/Update Company Profile (GSTIN, etc.)
app.post('/api/shop/company-profile', authenticateJWT, checkRole('ADMIN'), async (req, res) => {
    const shopId = req.shopId;
    // सुनिश्चित करें कि यहां कोई ' // ' कमेंट न हो।
    const { legal_name, gstin, address, opening_capital } = req.body; 

    try {
        const result = await pool.query(
            `INSERT INTO company_profile (shop_id, legal_name, gstin, address, opening_capital, updated_at)
             VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
             ON CONFLICT (shop_id) DO UPDATE
             SET legal_name = EXCLUDED.legal_name,
                 gstin = EXCLUDED.gstin,
                 address = EXCLUDED.address,
                 opening_capital = EXCLUDED.opening_capital,
                 updated_at = CURRENT_TIMESTAMP
             RETURNING *`,
            [shopId, legal_name, gstin, address, parseFloat(opening_capital) || 0] 
        );
        res.json({ success: true, profile: result.rows[0], message: 'कंपनी प्रोफ़ाइल सफलतापूर्वक अपडेट की गई।' });
    } catch (err) {
        // यदि अभी भी एरर आता है, तो 'opening_capital' कॉलम missing हो सकता है।
        console.error("Error updating company profile:", err.message);
        res.status(500).json({ success: false, message: 'प्रोफ़ाइल अपडेट करने में विफल: ' + err.message });
    }
});

app.get('/api/shop/company-profile', authenticateJWT, checkRole('CASHIER'), async (req, res) => {
    const shopId = req.shopId;
    try {
        const result = await pool.query('SELECT * FROM company_profile WHERE shop_id = $1', [shopId]);
        res.json({ success: true, profile: result.rows[0] || {} });
    } catch (err) {
        console.error("Error fetching company profile:", err.message);
        res.status(500).json({ success: false, message: 'प्रोफ़ाइल लाने में विफल: ' + err.message });
    }
});

// [ server.cjs फ़ाइल में इस पूरे फ़ंक्शन को बदलें ]
// 15.2 Tally-Style GSTR-1 (Sales) Report
app.get('/api/reports/gstr1', authenticateJWT, checkRole('MANAGER'), async (req, res) => {
    const shopId = req.shopId;
    const { startDate, endDate } = req.query;

    if (!startDate || !endDate) {
        return res.status(400).json({ success: false, message: 'StartDate और EndDate आवश्यक हैं.' });
    }

    const client = await pool.connect();
    try {
        // --- 1. B2B (Business-to-Business) - Invoices grouped by GSTIN ---
        // यह उन सभी बिक्रियों को लाता है जहाँ ग्राहक का GSTIN सेव किया गया था
        const b2b_query = `
            SELECT 
                i.customer_gstin,
                c.name AS customer_name,
                i.id AS invoice_number,
                i.created_at AS invoice_date,
                SUM(ii.sale_price * ii.quantity) AS total_taxable_value,
                SUM(ii.igst_amount) AS total_igst,
                SUM(ii.cgst_amount) AS total_cgst,
                SUM(ii.sgst_amount) AS total_sgst
            FROM invoices i
            JOIN invoice_items ii ON i.id = ii.invoice_id
            LEFT JOIN customers c ON i.customer_id = c.id
            WHERE i.shop_id = $1 AND i.created_at BETWEEN $2 AND $3
              AND i.customer_gstin IS NOT NULL AND i.customer_gstin != ''
            GROUP BY i.customer_gstin, c.name, i.id, i.created_at
            ORDER BY i.customer_gstin, i.created_at;
        `;
        const b2b_result = await client.query(b2b_query, [shopId, startDate, endDate]);

        // --- 2. B2C (Small - Business-to-Consumer) - Sales grouped by Rate and Place of Supply ---
        // यह उन सभी बिक्रियों को लाता है जहाँ ग्राहक का GSTIN नहीं था
        const b2c_query = `
            SELECT 
                i.place_of_supply,
                ii.gst_rate,
                SUM(ii.sale_price * ii.quantity) AS taxable_value,
                SUM(ii.igst_amount) AS total_igst,
                SUM(ii.cgst_amount) AS total_cgst,
                SUM(ii.sgst_amount) AS total_sgst,
                SUM(ii.gst_amount) AS total_tax
            FROM invoices i
            JOIN invoice_items ii ON i.id = ii.invoice_id
            WHERE i.shop_id = $1 AND i.created_at BETWEEN $2 AND $3
              AND (i.customer_gstin IS NULL OR i.customer_gstin = '')
            GROUP BY i.place_of_supply, ii.gst_rate
            ORDER BY i.place_of_supply;
        `;
        const b2c_result = await client.query(b2c_query, [shopId, startDate, endDate]);

        // --- 3. HSN/SAC Summary ---
        // यह सभी बेची गई वस्तुओं को उनके HSN कोड के अनुसार ग्रुप करता है
        const hsn_query = `
            SELECT 
                s.hsn_code,
                ii.item_name,
                s.unit,
                ii.gst_rate,
                SUM(ii.quantity) AS total_quantity,
                SUM(ii.sale_price * ii.quantity) AS total_taxable_value,
                SUM(ii.gst_amount) AS total_tax,
                SUM(ii.igst_amount) AS total_igst,
                SUM(ii.cgst_amount) AS total_cgst,
                SUM(ii.sgst_amount) AS total_sgst
            FROM invoice_items ii
            JOIN invoices i ON ii.invoice_id = i.id
            LEFT JOIN stock s ON ii.item_sku = s.sku AND s.shop_id = i.shop_id
            WHERE i.shop_id = $1 AND i.created_at BETWEEN $2 AND $3
            GROUP BY s.hsn_code, ii.item_name, s.unit, ii.gst_rate
            ORDER BY s.hsn_code;
        `;
        const hsn_result = await client.query(hsn_query, [shopId, startDate, endDate]);

        res.json({
            success: true,
            report: {
                period: { start: startDate, end: endDate },
                b2b: b2b_result.rows, // B2B इनवॉइस लिस्ट
                b2c: b2c_result.rows, // B2C समरी (राज्य और रेट के अनुसार)
                hsn_summary: hsn_result.rows // HSN समरी
            }
        });

    } catch (err) {
        console.error("Error generating GSTR-1 Tally report:", err.message, err.stack);
        res.status(500).json({ success: false, message: 'GSTR-1 Tally रिपोर्ट बनाने में विफल: ' + err.message });
    } finally {
        if (client) client.release();
    }
});


// [ server.cjs फ़ाइल में इस पूरे फ़ंक्शन को बदलें ]
// 15.3 Tally-Style GSTR-2 (Purchases) Report
app.get('/api/reports/gstr2', authenticateJWT, checkRole('MANAGER'), async (req, res) => {
    const shopId = req.shopId;
    const { startDate, endDate } = req.query;

    if (!startDate || !endDate) {
        return res.status(400).json({ success: false, message: 'StartDate और EndDate आवश्यक हैं.' });
    }

    const client = await pool.connect();
    try {
        // --- 1. B2B (Purchases from Registered Suppliers) ---
        // यह 'gst_details' वाले सभी परचेस को B2B मानता है
        const b2b_query = `
            SELECT 
                id,
                supplier_name,
                total_cost,
                created_at,
                gst_details -- यह JSONB कॉलम है
            FROM purchases 
            WHERE shop_id = $1 AND created_at BETWEEN $2 AND $3
              AND gst_details IS NOT NULL AND gst_details::text != '{}'
            ORDER BY created_at;
        `;
        const b2b_result = await client.query(b2b_query, [shopId, startDate, endDate]);

        // --- 2. ITC (Input Tax Credit) Summary ---
        // यह JSONB कॉलम से टैक्स की गणना करता है
        // (नोट: यह तभी काम करेगा जब gst_details में 'taxable_value', 'igst', 'cgst', 'sgst' हो)
        const itc_query = `
            SELECT 
                SUM(COALESCE((gst_details->>'taxable_value')::numeric, 0)) AS total_taxable_value,
                SUM(COALESCE((gst_details->>'igst')::numeric, 0)) AS total_igst,
                SUM(COALESCE((gst_details->>'cgst')::numeric, 0)) AS total_cgst,
                SUM(COALESCE((gst_details->>'sgst')::numeric, 0)) AS total_sgst
            FROM purchases
            WHERE shop_id = $1 AND created_at BETWEEN $2 AND $3
              AND gst_details IS NOT NULL AND gst_details::text != '{}';
        `;
        const itc_result = await client.query(itc_query, [shopId, startDate, endDate]);

        res.json({
            success: true,
            report: {
                period: { start: startDate, end: endDate },
                b2b_purchases: b2b_result.rows, // B2B परचेस की लिस्ट
                itc_summary: itc_result.rows[0] // कुल ITC समरी
            }
        });

    } catch (err) {
        console.error("Error generating GSTR-2 Tally report:", err.message, err.stack);
        res.status(500).json({ success: false, message: 'GSTR-2 Tally रिपोर्ट बनाने में विफल: ' + err.message });
    } finally {
        if (client) client.release();
    }
});


// 15.4 Tally-Style GSTR-3B Summary (PLAN LOCKED)
app.get('/api/reports/gstr3b', authenticateJWT, checkRole('MANAGER'), checkPlan(['MEDIUM', 'PREMIUM']), async (req, res) => {
    // 🚀 NAYA: Plan check yahaan lagaya gaya hai ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    
    const shopId = req.shopId;
    const { startDate, endDate } = req.query;

    if (!startDate || !endDate) {
        return res.status(400).json({ success: false, message: 'StartDate और EndDate आवश्यक हैं.' });
    }

    const client = await pool.connect();
    try {
        // --- 1. Outward Supplies (GSTR-1 का सारांश) ---
        const outward_query = `
            SELECT 
                SUM(ii.sale_price * ii.quantity) AS total_taxable_value,
                SUM(ii.igst_amount) AS total_igst,
                SUM(ii.cgst_amount) AS total_cgst,
                SUM(ii.sgst_amount) AS total_sgst
            FROM invoice_items ii
            JOIN invoices i ON ii.invoice_id = i.id
            WHERE i.shop_id = $1 AND i.created_at BETWEEN $2 AND $3;
        `;
        const outward_result = await client.query(outward_query, [shopId, startDate, endDate]);

        // --- 2. Inward Supplies / ITC (GSTR-2 का सारांश) ---
        const inward_query = `
            SELECT 
                SUM(COALESCE((gst_details->>'taxable_value')::numeric, 0)) AS total_taxable_value,
                SUM(COALESCE((gst_details->>'igst')::numeric, 0)) AS total_igst,
                SUM(COALESCE((gst_details->>'cgst')::numeric, 0)) AS total_cgst,
                SUM(COALESCE((gst_details->>'sgst')::numeric, 0)) AS total_sgst
            FROM purchases
            WHERE shop_id = $1 AND created_at BETWEEN $2 AND $3
              AND gst_details IS NOT NULL AND gst_details::text != '{}';
        `;
        const inward_result = await client.query(inward_query, [shopId, startDate, endDate]);

        // --- 3. Non-GST Expenses (ITC का हिस्सा नहीं) ---
        const expense_query = `
            SELECT COALESCE(SUM(amount), 0) AS non_gst_expenses
            FROM expenses 
            WHERE shop_id = $1 AND created_at BETWEEN $2 AND $3;
        `;
        const expense_result = await client.query(expense_query, [shopId, startDate, endDate]);
        
        const sales = outward_result.rows[0] || {};
        const itc = inward_result.rows[0] || {};
        const expenses = expense_result.rows[0] || {};

        // --- 4. Net Tax Calculation ---
        const net_igst = (parseFloat(sales.total_igst) || 0) - (parseFloat(itc.total_igst) || 0);
        const net_cgst = (parseFloat(sales.total_cgst) || 0) - (parseFloat(itc.total_cgst) || 0);
        const net_sgst = (parseFloat(sales.total_sgst) || 0) - (parseFloat(itc.total_sgst) || 0);

        res.json({
            success: true,
            report: {
                period: { start: startDate, end: endDate },
                outward_supplies: { // (Table 3.1)
                    taxable_value: parseFloat(sales.total_taxable_value || 0).toFixed(2),
                    igst: parseFloat(sales.total_igst || 0).toFixed(2),
                    cgst: parseFloat(sales.total_cgst || 0).toFixed(2),
                    sgst: parseFloat(sales.total_sgst || 0).toFixed(2)
                },
                inward_supplies_itc: { // (Table 4)
                    taxable_value: parseFloat(itc.total_taxable_value || 0).toFixed(2),
                    igst: parseFloat(itc.total_igst || 0).toFixed(2),
                    cgst: parseFloat(itc.total_cgst || 0).toFixed(2),
                    sgst: parseFloat(itc.total_sgst || 0).toFixed(2)
                },
                non_gst_expenses: parseFloat(expenses.non_gst_expenses || 0).toFixed(2),
                net_tax_payable: {
                    igst: net_igst.toFixed(2),
                    cgst: net_cgst.toFixed(2),
                    sgst: net_sgst.toFixed(2),
                    total: (net_igst + net_cgst + net_sgst).toFixed(2)
                }
            }
        });

    } catch (err) {
        console.error("Error generating GSTR-3B Tally report:", err.message, err.stack);
        res.status(500).json({ success: false, message: 'GSTR-3B Tally रिपोर्ट बनाने में विफल: ' + err.message });
    } finally {
        if (client) client.release();
    }
});



// -----------------------------------------------------------------------------
// --- 🚀 START: NEW API SECTION (आपकी नई आवश्यकताओं के लिए) ---
// --- 16. LICENSE RENEWAL API (NEW) ---
// -----------------------------------------------------------------------------

// 16.1 Request License Renewal
// (फ्रंटएंड इस एंडपॉइंट को तब कॉल करेगा जब लाइसेंस समाप्त हो गया हो
// और यूज़र 'Renew' बटन पर क्लिक करे)
app.post('/api/request-renewal', authenticateJWT, async (req, res) => {
    const shopId = req.shopId;
    const userEmail = req.user.email;
    const { duration } = req.body; // e.g., "1 month", "6 months", "12 months"

    if (!duration) {
        return res.status(400).json({ success: false, message: 'रिन्यूअल अवधि (duration) आवश्यक है.' });
    }

    const message = `लाइसेंस रिन्यूअल अनुरोध: ${duration}.`;

    try {
        // 1. अनुरोध को डेटाबेस में सहेजें
        await pool.query(
            'INSERT INTO renewal_requests (shop_id, user_email, message) VALUES ($1, $2, $3)',
            [shopId, userEmail, message]
        );

        // 2. व्यवस्थापक (Admin) को सूचित करने के लिए सर्वर कंसोल पर लॉग करें
        // (नोट: यहां WhatsApp/SMS API इंटीग्रेशन जोड़ा जा सकता है)
        console.log('--- 🔔 LICENSE RENEWAL REQUEST ---');
        console.log(`Shop ID: ${shopId}`);
        console.log(`User: ${userEmail}`);
        console.log(`Request: ${message}`);
        console.log(`Admin Contact: 7303410987`);
        console.log('-------------------------------------');

        res.json({
            success: true,
            message: 'आपका रिन्यूअल अनुरोध भेज दिया गया है। एडमिन (7303410987) जल्द ही आपसे संपर्क करेगा.'
        });

    } catch (err) {
        console.error("Error saving renewal request:", err.message);
        res.status(500).json({ success: false, message: 'अनुरोध सहेजने में विफल: ' + err.message });
    }
});



// ==========================================================
// --- 🚀 17. बैंक रिकॉन्सिलेशन API (NEW) ---
// ==========================================================

// 17.1 CSV स्टेटमेंट अपलोड करें और बुक/बैंक आइटम्स लाएँ (PLAN LOCKED)
app.post('/api/reconciliation/upload-statement', authenticateJWT, checkRole('MANAGER'), checkPlan(['MEDIUM', 'PREMIUM']), async (req, res) => {
    // 🚀 NAYA: Plan check yahaan lagaya gaya hai ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    
    const shopId = req.shopId;
    // statementItems एक JSON ऐरे है जिसे CSV से पार्स किया गया है
    const { statementDate, statementBalance, statementItems } = req.body;

    if (!statementDate || !statementBalance || !statementItems || !Array.isArray(statementItems)) {
        return res.status(400).json({ success: false, message: 'स्टेटमेंट की तारीख, बैलेंस और CSV डेटा (आइटम्स) आवश्यक हैं।' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 1. पुराने (unreconciled) बैंक आइटम्स को साफ़ करें (यदि कोई हो)
        await client.query('DELETE FROM bank_statement_items WHERE shop_id = $1 AND is_reconciled = FALSE', [shopId]);

        // 2. CSV से आए नए आइटम्स को डालें
        for (const item of statementItems) {
            await client.query(
                `INSERT INTO bank_statement_items (shop_id, transaction_date, description, debit, credit)
                 VALUES ($1, $2, $3, $4, $5)`,
                [shopId, item.date, item.description, item.debit || 0, item.credit || 0]
            );
        }

        // 3. Dukan Pro (बुक) के वे आइटम्स लाएँ जो मैच नहीं हुए हैं
        // (बिक्री और खर्च)
        const bookTransactionsQuery = `
            (SELECT 
                'invoice' AS type, 
                id, 
                created_at AS date, 
                'बिक्री (Sales) - चालान #' || id AS description, 
                total_amount AS amount 
            FROM invoices 
            WHERE shop_id = $1 AND is_reconciled = FALSE AND created_at <= $2)
            
            UNION ALL
            
            (SELECT 
                'expense' AS type, 
                id, 
                created_at AS date, 
                description, 
                amount * -1 AS amount -- खर्च को नेगेटिव दिखाएँ
            FROM expenses 
            WHERE shop_id = $1 AND is_reconciled = FALSE AND created_at <= $2)
            
            ORDER BY date DESC
        `;
        
        // 4. बैंक के वे आइटम्स लाएँ जो मैच नहीं हुए हैं (जो अभी डाले हैं)
        const bankTransactionsQuery = `
            SELECT 
                id, 
                transaction_date AS date, 
                description, 
                (credit - debit) AS amount -- क्रेडिट पॉजिटिव, डेबिट नेगेटिव
            FROM bank_statement_items 
            WHERE shop_id = $1 AND is_reconciled = FALSE 
            ORDER BY date DESC
        `;
        
        const bookRes = await client.query(bookTransactionsQuery, [shopId, statementDate]);
        const bankRes = await client.query(bankTransactionsQuery, [shopId]);

        await client.query('COMMIT');
        
        res.json({
            success: true,
            message: 'स्टेटमेंट सफलतापूर्वक अपलोड हुआ।',
            bookItems: bookRes.rows,
            bankItems: bankRes.rows
        });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error("Error in /upload-statement:", err.message);
        res.status(500).json({ success: false, message: 'स्टेटमेंट अपलोड करने में विफल: ' + err.message });
    } finally {
        client.release();
    }
});


// ... (upload-statement API के '});' के बाद)

// 17.2 स्टैटिक रिपोर्ट सेव करें (PLAN LOCKED)
app.post('/api/reconciliation/save', authenticateJWT, checkRole('MANAGER'), checkPlan(['MEDIUM', 'PREMIUM']), async (req, res) => {
    // 🚀 NAYA: Plan check yahaan lagaya gaya hai ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    
    const shopId = req.shopId;
    const { 
        statementEndDate, 
        statementEndBalance, 
        reportSummary, // यह एक ऑब्जेक्ट होगा
        reconciledBankIds, // IDs का ऐरे [1, 2, 3]
        reconciledBookItems  // ऑब्जेक्ट्स का ऐरे [{type: 'invoice', id: 123}]
    } = req.body;

    if (!statementEndDate || !statementEndBalance || !reportSummary || !reconciledBankIds || !reconciledBookItems) {
        return res.status(400).json({ success: false, message: 'रिपोर्ट सेव करने के लिए पूरा डेटा आवश्यक है।' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 1. स्टैटिक रिपोर्ट (reconciliation_reports) में एक एंट्री बनाएँ
        const reportRes = await client.query(
            `INSERT INTO reconciliation_reports 
             (shop_id, statement_end_date, statement_end_balance, 
              cleared_payments, cleared_deposits, 
              uncleared_items_count, uncleared_items_total)
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
            [
                shopId,
                statementEndDate,
                parseFloat(statementEndBalance),
                parseFloat(reportSummary.clearedPayments) || 0,
                parseFloat(reportSummary.clearedDeposits) || 0,
                parseInt(reportSummary.unclearedCount) || 0,
                parseFloat(reportSummary.unclearedTotal) || 0
            ]
        );
        const reportId = reportRes.rows[0].id;

        // 2. बैंक आइटम्स को 'reconciled' के रूप में चिह्नित करें
        if (reconciledBankIds.length > 0) {
            await client.query(
                `UPDATE bank_statement_items SET is_reconciled = TRUE, reconciliation_id = $1
                 WHERE shop_id = $2 AND id = ANY($3::int[])`,
                [reportId, shopId, reconciledBankIds]
            );
        }

        // 3. बुक आइटम्स (Invoices/Expenses) को 'reconciled' के रूप में चिह्नित करें
        const invoiceIds = reconciledBookItems
            .filter(item => item.type === 'invoice')
            .map(item => item.id);
        const expenseIds = reconciledBookItems
            .filter(item => item.type === 'expense')
            .map(item => item.id);

        if (invoiceIds.length > 0) {
            await client.query(
                `UPDATE invoices SET is_reconciled = TRUE WHERE shop_id = $1 AND id = ANY($2::int[])`,
                [shopId, invoiceIds]
            );
        }
        if (expenseIds.length > 0) {
            await client.query(
                `UPDATE expenses SET is_reconciled = TRUE WHERE shop_id = $1 AND id = ANY($2::int[])`,
                [shopId, expenseIds]
            );
        }

        await client.query('COMMIT');
        res.json({ success: true, message: 'रिकॉन्सिलेशन रिपोर्ट सफलतापूर्वक सेव की गई!', reportId: reportId });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error("Error in /reconciliation/save:", err.message);
        res.status(500).json({ success: false, message: 'रिपोर्ट सेव करने में विफल: ' + err.message });
    } finally {
        client.release();
    }
});


// 17.3 पिछली (पुरानी) रिकॉन्सिलेशन रिपोर्ट्स लाएँ (PLAN LOCKED)
app.get('/api/reconciliation/reports', authenticateJWT, checkRole('MANAGER'), checkPlan(['MEDIUM', 'PREMIUM']), async (req, res) => {
    // 🚀 NAYA: Plan check yahaan lagaya gaya hai ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    
    const shopId = req.shopId;

    try {
        const result = await pool.query(
            `SELECT 
                id, 
                statement_end_date, 
                statement_end_balance,
                uncleared_items_total,
                reconciled_at
             FROM reconciliation_reports 
             WHERE shop_id = $1 
             ORDER BY statement_end_date DESC`,
            [shopId]
        );

        res.json({ success: true, reports: result.rows });

    } catch (err) {
        console.error("Error in /reconciliation/reports:", err.message);
        res.status(500).json({ success: false, message: 'पुरानी रिपोर्ट्स लाने में विफल: ' + err.message });
    }
});

// [ यह नया कोड यहाँ पेस्ट करें ]

// -----------------------------------------------------------------------------
// VI. SERVER INITIALIZATION (WebSocket के साथ)
// -----------------------------------------------------------------------------

// Default route
app.get('/', (req, res) => {
    res.send('Dukan Pro Backend (with WebSocket) is Running.');
});

// --- 🚀 WEBSOCKET सर्वर लॉजिक START ---

// 1. HTTP सर्वर बनाएँ और Express ऐप को उससे जोड़ें
const server = http.createServer(app);

// 🚀 FIX: टाइमआउट को 120 सेकंड (2 मिनट) तक बढ़ाएँ
server.timeout = 120000; 
server.keepAliveTimeout = 125000; // इसे timeout से थोड़ा अधिक रखें

// 2. WebSocket सर्वर को HTTP सर्वर से जोड़ें
const wss = new WebSocketServer({ server });

// [ यह कोड server.cjs में लाइन 1405 के पास जोड़ें ]

// 3. पेयरिंग के लिए कनेक्शन स्टोर करें
const pairingMap = new Map(); // pairCode -> posSocket
const scannerToPosMap = new Map(); // scannerSocket -> posSocket
const posToScannerMap = new Map(); // posSocket -> posSocket

// 🚀 NAYA: Live Dashboard के लिए क्लाइंट स्टोर करें
// Map<shopId, Set<ws>>
const dashboardClients = new Map();

function generatePairCode() {
    // 6 अंकों का रैंडम कोड
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// [ पुराने wss.on('connection', ...) को इस पूरे नए ब्लॉक से बदलें ]

wss.on('connection', (ws) => {
    console.log('WebSocket Client Connected');

    ws.on('message', (message) => {
        let data;
        try {
            data = JSON.parse(message);
        } catch (e) {
            console.error('Invalid WebSocket message:', message);
            return;
        }

        switch (data.type) {
            
           [नीचे दिए गए पूरे कोड को कॉपी करें]

            // --- 🚀 NAYA: Live Dashboard का केस ---
            case 'REGISTER_DASHBOARD':
                try {
                    // टोकन को वेरिफाई करके shopId निकालें
                    const decoded = jwt.verify(data.token, JWT_SECRET);
                    const shopId = decoded.shopId;
                    
                    if (!shopId) {
                        throw new Error('टोकन में ShopID नहीं है');
                    }

                    // ws (क्लाइंट) पर shopId को स्टोर करें (डिस्कनेक्ट होने पर हटाने के लिए)
                    ws.shopId = shopId; 

                    // Map में shopId के लिए Set ढूँढें या बनाएँ
                    if (!dashboardClients.has(shopId)) {
                        dashboardClients.set(shopId, new Set());
                    }
                    
                    // इस क्लाइंट (ws) को उस दुकान के Set में जोड़ें
                    dashboardClients.get(shopId).add(ws);
                    
                    console.log(`Dashboard client registered for ShopID: ${shopId}. Total clients for this shop: ${dashboardClients.get(shopId).size}`);
                    ws.send(JSON.stringify({ type: 'DASHBOARD_REGISTERED', message: 'Live Dashboard कनेक्ट हो गया है।' }));

                } catch (err) { // 🚀 FIX: 'try' ब्लॉक का क्लोजिंग '}' यहाँ (catch से ठीक पहले) जोड़ा गया है
                    console.error('Dashboard registration failed:', err.message);
                    ws.send(JSON.stringify({ type: 'ERROR', message: 'Dashboard ऑथेंटिकेशन विफल: ' + err.message }));
                    ws.close();
                }
                break;

            // --- पुराना मोबाइल स्कैनर लॉजिक (जैसा था वैसा ही) ---
            case 'REGISTER_POS':
                try {
                    const pairCode = generatePairCode();
                    pairingMap.set(pairCode, ws); 
                    posToScannerMap.set(ws, null); 
                    console.log(`POS Registered. Pair Code: ${pairCode}`);
                    ws.send(JSON.stringify({ type: 'PAIR_CODE_GENERATED', pairCode }));
                } catch (e) {
                    ws.send(JSON.stringify({ type: 'ERROR', message: 'Authentication failed' }));
                }
                break;

            case 'REGISTER_SCANNER':
                const posSocket = pairingMap.get(data.pairCode);
                if (posSocket) {
                    console.log('Scanner Paired successfully!');
                    scannerToPosMap.set(ws, posSocket); 
                    posToScannerMap.set(posSocket, ws); 
                    pairingMap.delete(data.pairCode); 

                    posSocket.send(JSON.stringify({ type: 'SCANNER_PAIRED' }));
                    ws.send(JSON.stringify({ type: 'SCANNER_PAIRED' }));
                } else {
                    console.log('Scanner Pair Failed. Invalid code:', data.pairCode);
                    ws.send(JSON.stringify({ type: 'ERROR', message: 'Invalid Pair Code' }));
                }
                break;

            case 'SCAN_SKU':
                const pairedPosSocket = scannerToPosMap.get(ws);
                if (pairedPosSocket) {
                    console.log(`Relaying SKU ${data.sku} to paired POS`);
                    pairedPosSocket.send(JSON.stringify({ type: 'SKU_SCANNED', sku: data.sku }));
                } else {
                    console.log('SKU received from unpaired scanner');
                    ws.send(JSON.stringify({ type: 'ERROR', message: 'Not Paired' }));
                }
                break;
            
            default:
                console.warn(`Unknown WS message type: ${data.type}`);
        }
    });

    ws.on('close', () => {
        console.log('WebSocket Client Disconnected');

        // --- 🚀 NAYA: Dashboard क्लाइंट को Map से हटाएँ ---
        if (ws.shopId) {
            const shopId = ws.shopId;
            if (dashboardClients.has(shopId)) {
                const clients = dashboardClients.get(shopId);
                clients.delete(ws); // Set से इस क्लाइंट को हटाएँ
                console.log(`Dashboard client disconnected for ShopID: ${shopId}. Remaining: ${clients.size}`);
                // अगर यह उस दुकान का आखिरी क्लाइंट था, तो Map से shopId को ही हटा दें
                if (clients.size === 0) {
                    dashboardClients.delete(shopId);
                }
            }
        }

        // --- पुराना मोबाइल स्कैनर लॉजिक (जैसा था वैसा ही) ---
        if (posToScannerMap.has(ws)) {
            const pairedScannerSocket = posToScannerMap.get(ws);
            if (pairedScannerSocket) {
                pairedScannerSocket.send(JSON.stringify({ type: 'POS_DISCONNECTED' }));
                scannerToPosMap.delete(pairedScannerSocket);
            }
            posToScannerMap.delete(ws);
        } else if (scannerToPosMap.has(ws)) {
            const pairedPosSocket = scannerToPosMap.get(ws);
            if (pairedPosSocket) {
                pairedPosSocket.send(JSON.stringify({ type: 'SCANNER_DISCONNECTED' }));
                posToScannerMap.set(pairedPosSocket, null);
            }
            scannerToPosMap.delete(ws);
        }
        pairingMap.forEach((socket, code) => {
            if (socket === ws) {
                pairingMap.delete(code);
            }
        });
    });
});

// --- 🚀 WEBSOCKET सर्वर लॉजिक END ---


function broadcastToShop(shopId, message) {
    if (!dashboardClients.has(shopId)) {
        // इस दुकान का कोई डैशबोर्ड नहीं खुला है
        return;
    }

    const clients = dashboardClients.get(shopId);
    console.log(`Broadcasting to ${clients.size} dashboard clients for shopId: ${shopId}`);

    clients.forEach(wsClient => {
        if (wsClient.readyState === 1) { // 1 मतलब OPEN
            wsClient.send(message);
        }
    });
}


// Start the server after ensuring database tables are ready
createTables().then(() => {
    // 4. app.listen की जगह server.listen का उपयोग करें
    server.listen(PORT, () => {
        console.log(`\n🎉 Server is running securely on port ${PORT}`);
        console.log(`🌐 API Endpoint: https://dukan-pro-ultimate.onrender.com:${PORT}`); 
        console.log('🚀 WebSocket Server is running on the same port.');
        console.log('--------------------------------------------------');
        console.log('🔒 Authentication: JWT is required for all data routes.');
        console.log('🔑 Multi-tenancy: All data is scoped by shop_id.\n');
    });
}).catch(error => {
    console.error('Failed to initialize database and start server:', error.message);
    process.exit(1);
});