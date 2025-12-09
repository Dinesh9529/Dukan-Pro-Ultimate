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

// --- DATABASE AUTO-SETUP (Status Column) ---
const initDB = async () => {
    try {
        // यह कमांड चेक करेगा और सिर्फ तभी कॉलम जोड़ेगा जब वो मौजूद नहीं होगा
        await pool.query(`
            ALTER TABLE shops 
            ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'active';
        `);
        console.log("✅ Database Setup Checked: 'status' column ready.");
    } catch (err) {
        console.log("⚠️ Database Setup Notice:", err.message);
    }
};

// सर्वर स्टार्ट होते ही इसे चलाएं
initDB();

// 👆👆 कोड यहाँ खत्म 👆👆
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
        // 🚀 FIX: 'ACCOUNTANT' रोल को CHECK constraint में जोड़ा गया
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY, 
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE, 
                email TEXT UNIQUE NOT NULL, 
                password_hash TEXT NOT NULL, 
                name TEXT NOT NULL, 
                role TEXT DEFAULT 'CASHIER' CHECK (role IN ('ADMIN', 'MANAGER', 'CASHIER', 'ACCOUNTANT')), 
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        
        // (यह सुनिश्चित करता है कि पुराने यूज़र्स के लिए भी यह काम करे)
        await client.query(`
            DO $$ BEGIN
                ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
                ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('ADMIN', 'MANAGER', 'CASHIER', 'ACCOUNTANT'));
            EXCEPTION WHEN duplicate_object THEN
                -- कंस्ट्रेंट पहले से ही मौजूद है या दूसरी टेबल द्वारा उपयोग में है, कोई बात नहीं
            END $$;
        `);
        
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
		
		//2.1 Mobile Table (CREATE)
		await client.query(`
        DO $$
        BEGIN
        IF NOT EXISTS (
        SELECT 1 FROM pg_attribute
        WHERE attrelid = (SELECT oid FROM pg_class WHERE relname = 'customers')
        AND attname = 'mobile'
        ) THEN
        ALTER TABLE customers ADD COLUMN mobile TEXT;
        END IF;
        END $$;
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




// ====================================================================
        // 🏗️ FINAL MISSING TABLES: GYM, TAILOR, RESTAURANT, REPAIR
        // ====================================================================

        // 15. 🧵 TAILOR / BOUTIQUE (Measurements)
        // दर्जी के लिए नाप (Measurements) सेव करने की टेबल
        await client.query(`
            CREATE TABLE IF NOT EXISTS tailor_measurements (
                id SERIAL PRIMARY KEY,
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
                customer_id INTEGER REFERENCES customers(id) ON DELETE CASCADE,
                item_type TEXT, -- e.g. "Shirt", "Pant", "Blouse"
                measurements_json JSONB, -- { "Length": 40, "Waist": 32 }
                notes TEXT, -- "Deep neck design"
                delivery_date DATE,
                status TEXT DEFAULT 'PENDING', -- 'STITCHING', 'READY'
                created_at TIMESTAMP DEFAULT NOW()
            );
        `);

        // 16. 💪 GYM / FITNESS (Membership & Attendance)
        // जिम के मेंबर्स की हाजिरी और डाइट प्लान
        await client.query(`
            CREATE TABLE IF NOT EXISTS gym_attendance (
                id SERIAL PRIMARY KEY,
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
                customer_id INTEGER REFERENCES customers(id) ON DELETE CASCADE,
                check_in_time TIMESTAMP DEFAULT NOW(),
                status TEXT DEFAULT 'PRESENT'
            );

            CREATE TABLE IF NOT EXISTS gym_diet_plans (
                id SERIAL PRIMARY KEY,
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
                customer_id INTEGER REFERENCES customers(id),
                plan_name TEXT, -- "Weight Loss"
                diet_json JSONB, -- { "Morning": "Oats", "Lunch": "Salad" }
                created_at TIMESTAMP DEFAULT NOW()
            );
        `);

        // 17. 🍽️ RESTAURANT (Tables & KOT)
        // रेस्टोरेंट के लिए टेबल बुकिंग और किचन आर्डर (KOT)
        await client.query(`
            CREATE TABLE IF NOT EXISTS restaurant_tables (
                id SERIAL PRIMARY KEY,
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
                table_number TEXT,
                capacity INTEGER,
                status TEXT DEFAULT 'FREE' -- 'OCCUPIED', 'RESERVED'
            );

            CREATE TABLE IF NOT EXISTS restaurant_kots (
                id SERIAL PRIMARY KEY,
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
                table_id INTEGER REFERENCES restaurant_tables(id),
                items_json JSONB, -- [{ "item": "Dal", "qty": 1 }]
                status TEXT DEFAULT 'PREPARING', -- 'SERVED', 'BILLED'
                created_at TIMESTAMP DEFAULT NOW()
            );
        `);

        // 18. 🛠️ SERVICE CENTER (Repair Job Cards)
        // मोबाइल/इलेक्ट्रॉनिक्स रिपेयरिंग का जॉब कार्ड
        await client.query(`
            CREATE TABLE IF NOT EXISTS repair_job_cards (
                id SERIAL PRIMARY KEY,
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
                customer_name TEXT,
                customer_mobile TEXT,
                device_model TEXT, -- "iPhone 13"
                imei_serial TEXT,
                issue_description TEXT, -- "Screen Broken"
                estimated_cost NUMERIC,
                advance_paid NUMERIC DEFAULT 0,
                status TEXT DEFAULT 'RECEIVED', -- 'REPAIRED', 'DELIVERED', 'CANT_FIX'
                created_at TIMESTAMP DEFAULT NOW()
            );
        `);



// 16. Geo-Tagging Columns for Recovery Agents
await client.query(`
    DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = (SELECT oid FROM pg_class WHERE relname = 'invoices') AND attname = 'latitude') THEN
            ALTER TABLE invoices ADD COLUMN latitude NUMERIC DEFAULT NULL;
            ALTER TABLE invoices ADD COLUMN longitude NUMERIC DEFAULT NULL;
        END IF;
    END $$;
`);

// 17. Finance/Collection Column (Loan/RD/FD Number)
await client.query(`
    DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = (SELECT oid FROM pg_class WHERE relname = 'invoices') AND attname = 'loan_account_no') THEN
            ALTER TABLE invoices ADD COLUMN loan_account_no TEXT DEFAULT NULL;
        END IF;
    END $$;
`);


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


//-- Add DOB to customers and business_type to shops (safe – only if not exists)
await client.query(`
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_attribute
    WHERE attrelid = (SELECT oid FROM pg_class WHERE relname = 'customers')
      AND attname = 'dob'
  ) THEN
    ALTER TABLE customers ADD COLUMN dob DATE;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_attribute
    WHERE attrelid = (SELECT oid FROM pg_class WHERE relname = 'shops')
      AND attname = 'business_type'
  ) THEN
    ALTER TABLE shops ADD COLUMN business_type TEXT DEFAULT 'RETAIL';
  END IF;
END $$;
`);

//-- Salon specific tables (safe: only add if not exists)
await client.query(`
DO $$
BEGIN
  -- appointments
  IF NOT EXISTS (SELECT 1 FROM pg_tables WHERE tablename='appointments') THEN
    CREATE TABLE appointments (
      id SERIAL PRIMARY KEY,
      shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
      customer_id INTEGER REFERENCES customers(id) ON DELETE SET NULL,
      customer_name TEXT,
      customer_mobile TEXT,
      service_id INTEGER,
      service_name TEXT,
      scheduled_at TIMESTAMP WITH TIME ZONE,
      status TEXT DEFAULT 'SCHEDULED' CHECK (status IN ('SCHEDULED','COMPLETED','CANCELLED','NO_SHOW')),
      created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );
  END IF;

  -- salon services (catalog)
  IF NOT EXISTS (SELECT 1 FROM pg_tables WHERE tablename='salon_services') THEN
    CREATE TABLE salon_services (
      id SERIAL PRIMARY KEY,
      shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
      code TEXT,
      name TEXT NOT NULL,
      duration_minutes INTEGER DEFAULT 30,
      price NUMERIC DEFAULT 0,
      cost NUMERIC DEFAULT 0,
      category TEXT,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );
  END IF;

  -- bookings (payments + appointments link)
  IF NOT EXISTS (SELECT 1 FROM pg_tables WHERE tablename='salon_bookings') THEN
    CREATE TABLE salon_bookings (
      id SERIAL PRIMARY KEY,
      shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
      appointment_id INTEGER REFERENCES appointments(id) ON DELETE SET NULL,
      invoice_id INTEGER REFERENCES invoices(id) ON DELETE SET NULL,
      paid_amount NUMERIC DEFAULT 0,
      payment_status TEXT DEFAULT 'PENDING' CHECK (payment_status IN ('PENDING','PAID','REFUNDED')),
      created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );
  END IF;

  -- salon staff
  IF NOT EXISTS (SELECT 1 FROM pg_tables WHERE tablename='salon_staff') THEN
    CREATE TABLE salon_staff (
      id SERIAL PRIMARY KEY,
      shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
      name TEXT,
      mobile TEXT,
      role TEXT,
      is_active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );
  END IF;

  -- service inventory if salon sells products (shampoos, oils)
  IF NOT EXISTS (SELECT 1 FROM pg_tables WHERE tablename='service_inventory') THEN
    CREATE TABLE service_inventory (
      id SERIAL PRIMARY KEY,
      shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
      sku TEXT,
      name TEXT,
      qty NUMERIC DEFAULT 0,
      purchase_price NUMERIC DEFAULT 0,
      sale_price NUMERIC DEFAULT 0,
      created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );
  END IF;
END $$;
`);


// [ ✅ server.cjs: createTables() के अंदर इसे पेस्ट करें ]

// 16. Service Recipes Table (कंजम्पशन लॉजिक के लिए)
await client.query(`
    CREATE TABLE IF NOT EXISTS service_recipes (
        id SERIAL PRIMARY KEY,
        shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
        service_sku TEXT NOT NULL,       -- सर्विस का कोड (जैसे: Haircut)
        consumable_sku TEXT NOT NULL,    -- क्या खर्च होगा (जैसे: Shampoo)
        quantity_needed NUMERIC NOT NULL DEFAULT 0, -- कितना खर्च होगा (जैसे: 5ml)
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
    );
`);



// ====================================================================
        // 🏗️ GOD MODE TABLES: जो आपके कोड में मिसिंग थीं (Furniture, School, etc.)
        // ====================================================================

        // 7. 🛋️ FURNITURE & ELECTRONICS (Delivery & Warranty)
        // यह टेबल फर्नीचर की डिलीवरी और इलेक्ट्रॉनिक्स की वारंटी ट्रैक करेगी
        await client.query(`
            CREATE TABLE IF NOT EXISTS product_deliveries (
                id SERIAL PRIMARY KEY,
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
                invoice_id INTEGER, -- किस बिल का सामान है
                customer_name TEXT,
                delivery_address TEXT,
                delivery_date DATE,
                assembly_required BOOLEAN DEFAULT FALSE, -- क्या मिस्त्री चाहिए?
                warranty_end_date DATE, -- इलेक्ट्रॉनिक्स के लिए
                status TEXT DEFAULT 'PENDING' -- 'DELIVERED', 'RETURNED'
            );
        `);

        // 8. 🚨 GARMENTS SECURITY (Anti-Theft / Spy Mode)
        // जब दरवाजे पर बीप बजेगी, तो चोर की फोटो और टाइम यहाँ सेव होगा
        await client.query(`
            CREATE TABLE IF NOT EXISTS security_alerts (
                id SERIAL PRIMARY KEY,
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
                alert_time TIMESTAMP DEFAULT NOW(),
                camera_image TEXT, -- चोर की फोटो (Base64)
                rfid_tag_detected TEXT, -- चोरी हुए कपड़े का कोड
                status TEXT DEFAULT 'UNRESOLVED'
            );
        `);

        // 9. 🎨 PAINT SHOP (Color Formulas)
        // पेंटर का बनाया हुआ कलर फार्मूला सेव करने के लिए
        await client.query(`
            CREATE TABLE IF NOT EXISTS paint_formulas (
                id SERIAL PRIMARY KEY,
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
                customer_name TEXT,
                color_code TEXT, -- e.g. "Royal Blue 9012"
                base_product TEXT, 
                formula_json JSONB, -- { "Red": "2ml", "Yellow": "5ml" }
                created_at TIMESTAMP DEFAULT NOW()
            );
        `);

        // 10. 🏨 HOTEL MANAGEMENT (Rooms)
        await client.query(`
            CREATE TABLE IF NOT EXISTS hotel_rooms (
                id SERIAL PRIMARY KEY,
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
                room_number TEXT NOT NULL,
                status TEXT DEFAULT 'AVAILABLE', -- 'OCCUPIED', 'DIRTY'
                current_guest_name TEXT
            );
        `);

        // 11. 🎓 SCHOOL / COACHING (Students & Fees)
        await client.query(`
            CREATE TABLE IF NOT EXISTS school_students (
                id SERIAL PRIMARY KEY,
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
                roll_number TEXT,
                student_name TEXT,
                father_name TEXT,
                fees_due NUMERIC DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS school_fee_transactions (
                id SERIAL PRIMARY KEY,
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
                student_id INTEGER,
                amount_paid NUMERIC,
                payment_date TIMESTAMP DEFAULT NOW()
            );
        `);

        // 12. 🚛 TRANSPORT (Trips)
        await client.query(`
            CREATE TABLE IF NOT EXISTS transport_trips (
                id SERIAL PRIMARY KEY,
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
                vehicle_no TEXT,
                driver_name TEXT,
                start_location TEXT,
                end_location TEXT,
                freight_amount NUMERIC, -- भाड़ा
                diesel_expense NUMERIC DEFAULT 0,
                trip_date TIMESTAMP DEFAULT NOW()
            );
        `);

        // 13. 🧪 PERFUME SHOP (Decants)
        await client.query(`
            CREATE TABLE IF NOT EXISTS perfume_blends (
                id SERIAL PRIMARY KEY,
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
                blend_name TEXT,
                ingredients_json JSONB, -- { "Rose": "2ml", "Oud": "1ml" }
                price NUMERIC
            );
        `);

        // 14. 🩺 MEDICAL REPORTS (Sonography/Xray)
        // (अगर यह पहले से नहीं है, तो इसे जरूर जोड़ें)
        await client.query(`
            CREATE TABLE IF NOT EXISTS medical_reports (
                id SERIAL PRIMARY KEY,
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
                patient_name TEXT,
                doctor_name TEXT,
                report_type TEXT,
                report_content TEXT,
                findings_json JSONB,
                created_at TIMESTAMP DEFAULT NOW()
            );
        `);
		
		
		// ====================================================================
        // 🏗️ FINAL MISSING TABLES: GYM, TAILOR, RESTAURANT, REPAIR
        // ====================================================================

        // 15. 🧵 TAILOR / BOUTIQUE (Measurements)
        // दर्जी के लिए नाप (Measurements) सेव करने की टेबल
        await client.query(`
            CREATE TABLE IF NOT EXISTS tailor_measurements (
                id SERIAL PRIMARY KEY,
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
                customer_id INTEGER REFERENCES customers(id) ON DELETE CASCADE,
                item_type TEXT, -- e.g. "Shirt", "Pant", "Blouse"
                measurements_json JSONB, -- { "Length": 40, "Waist": 32 }
                notes TEXT, -- "Deep neck design"
                delivery_date DATE,
                status TEXT DEFAULT 'PENDING', -- 'STITCHING', 'READY'
                created_at TIMESTAMP DEFAULT NOW()
            );
        `);

        // 16. 💪 GYM / FITNESS (Membership & Attendance)
        // जिम के मेंबर्स की हाजिरी और डाइट प्लान
        await client.query(`
            CREATE TABLE IF NOT EXISTS gym_attendance (
                id SERIAL PRIMARY KEY,
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
                customer_id INTEGER REFERENCES customers(id) ON DELETE CASCADE,
                check_in_time TIMESTAMP DEFAULT NOW(),
                status TEXT DEFAULT 'PRESENT'
            );

            CREATE TABLE IF NOT EXISTS gym_diet_plans (
                id SERIAL PRIMARY KEY,
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
                customer_id INTEGER REFERENCES customers(id),
                plan_name TEXT, -- "Weight Loss"
                diet_json JSONB, -- { "Morning": "Oats", "Lunch": "Salad" }
                created_at TIMESTAMP DEFAULT NOW()
            );
        `);

        // 17. 🍽️ RESTAURANT (Tables & KOT)
        // रेस्टोरेंट के लिए टेबल बुकिंग और किचन आर्डर (KOT)
        await client.query(`
            CREATE TABLE IF NOT EXISTS restaurant_tables (
                id SERIAL PRIMARY KEY,
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
                table_number TEXT,
                capacity INTEGER,
                status TEXT DEFAULT 'FREE' -- 'OCCUPIED', 'RESERVED'
            );

            CREATE TABLE IF NOT EXISTS restaurant_kots (
                id SERIAL PRIMARY KEY,
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
                table_id INTEGER REFERENCES restaurant_tables(id),
                items_json JSONB, -- [{ "item": "Dal", "qty": 1 }]
                status TEXT DEFAULT 'PREPARING', -- 'SERVED', 'BILLED'
                created_at TIMESTAMP DEFAULT NOW()
            );
        `);

        // 18. 🛠️ SERVICE CENTER (Repair Job Cards)
        // मोबाइल/इलेक्ट्रॉनिक्स रिपेयरिंग का जॉब कार्ड
        await client.query(`
            CREATE TABLE IF NOT EXISTS repair_job_cards (
                id SERIAL PRIMARY KEY,
                shop_id INTEGER REFERENCES shops(id) ON DELETE CASCADE,
                customer_name TEXT,
                customer_mobile TEXT,
                device_model TEXT, -- "iPhone 13"
                imei_serial TEXT,
                issue_description TEXT, -- "Screen Broken"
                estimated_cost NUMERIC,
                advance_paid NUMERIC DEFAULT 0,
                status TEXT DEFAULT 'RECEIVED', -- 'REPAIRED', 'DELIVERED', 'CANT_FIX'
                created_at TIMESTAMP DEFAULT NOW()
            );
        `);
		
		
		

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
/**
 * Middleware to verify JWT and attach user/shop information to the request.
 * All protected routes must use this first.
 */
/**
 * Middleware to verify JWT and attach user/shop information to the request.
 * All protected routes must use this first.
 */
const authenticateJWT = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const token = authHeader.split(' ')[1];
        try {
            // 1. टोकन डिकोड करें
            const decoded = jwt.verify(token, process.env.JWT_SECRET || 'default_secret');

            // 2. 🚀 REAL-TIME CHECK: डेटाबेस से ताज़ा स्टेटस लाएँ
            const client = await pool.connect();
            try {
                // 🔴 FIX: 's.status as shop_status' को यहाँ जोड़ा गया है
                const freshData = await client.query(
                    `SELECT s.plan_type, s.add_ons, s.license_expiry_date, s.status as shop_status, u.status, u.role 
                     FROM shops s 
                     JOIN users u ON s.id = u.shop_id 
                     WHERE s.id = $1 AND u.id = $2`,
                    [decoded.shopId, decoded.id]
                );

                if (freshData.rows.length > 0) {
                    const fresh = freshData.rows[0];

                    // 🛑 BLOCK CHECK: अगर दुकान ब्लॉक है, तो यहीं रोक दें
                    if (fresh.shop_status === 'blocked') {
                        return res.status(403).json({ 
                            success: false, 
                            message: '⛔ आपकी दुकान को एडमिन द्वारा अस्थाई रूप से बंद (Blocked) कर दिया गया है। कृपया संपर्क करें।' 
                        });
                    }

                    // टोकन के पुराने डेटा को ताज़ा डेटा से बदलें
                    decoded.plan_type = fresh.plan_type;
                    decoded.add_ons = fresh.add_ons;
                    decoded.licenseExpiryDate = fresh.license_expiry_date;
                    decoded.status = fresh.status;
                    decoded.role = fresh.role;
                }
            } catch (dbErr) {
                console.error("Auth Refresh Error", dbErr);
            } finally {
                client.release();
            }

            // 3. रिक्वेस्ट में अटैच करें
            req.user = decoded;
            req.shopId = decoded.shopId;
            req.userRole = decoded.role;
            next();

        } catch (err) {
            console.warn('JWT Verification Failed:', err.message);
            return res.status(403).json({ success: false, message: 'अमान्य या समाप्त टोकन।' });
        }
    } else {
        res.status(401).json({ success: false, message: 'अनधिकृत पहुँच।' });
    }
};

/**
 * Middleware for Role-Based Access Control (RBAC).
 * Role hierarchy: ADMIN (3) > MANAGER (2) > CASHIER (1)
 */
/* [Line 86] - यह आपका मौजूदा checkRole फ़ंक्शन है */
const checkRole = (requiredRole) => (req, res, next) => {
    const roles = { 'ADMIN': 3, 'MANAGER': 2, 'ACCOUNTANT': 2, 'CASHIER': 1 };
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


// 3. User Registration (Updated for ALL Business Types)
app.post('/api/register', async (req, res) => {
    // 🚀 FIX: 'business_type' ko req.body se nikaalein
    const { shopName, name, email, mobile, password, business_type } = req.body;

    if (!shopName || !name || !email || !mobile || !password) {
        return res.status(400).json({ success: false, message: 'सभी फ़ील्ड आवश्यक हैं.' });
    }
    
    // Default value 'RETAIL' agar user ne select nahi kiya
    const finalBusinessType = business_type || 'RETAIL';

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 1. Email Check
        const existingUser = await client.query('SELECT id FROM users WHERE email = $1', [email]);
        if (existingUser.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(409).json({ success: false, message: 'यह ईमेल पहले से पंजीकृत है।' });
        }

        // 2. Create Shop (🚀 CRITICAL: Save business_type here)
        const shopResult = await client.query(
            'INSERT INTO shops (shop_name, business_type) VALUES ($1, $2) RETURNING id, business_type',
            [shopName, finalBusinessType]
        );
        const shopId = shopResult.rows[0].id;

        // 3. Hash Password
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

        // 4. Create User (Admin)
        const userInsertQuery = `
            INSERT INTO users (shop_id, email, password_hash, name, mobile, role, status)
            VALUES ($1, $2, $3, $4, $5, $6, 'active')
            RETURNING id, shop_id, email, name, mobile, role, status
        `;
        const userResult = await client.query(userInsertQuery, [shopId, email, hashedPassword, name, mobile, 'ADMIN']);
        const user = userResult.rows[0];

        // 5. Generate Token (🚀 Include businessType in token)
        const tokenUser = {
            id: user.id,
            email: user.email,
            mobile: user.mobile,
            shopId: user.shop_id,
            name: user.name,
            role: user.role,
            shopName: shopName,
            status: user.status,
            plan_type: 'TRIAL',
            add_ons: {},
            licenseExpiryDate: null,
            businessType: finalBusinessType // <--- Ye frontend ke liye zaroori hai
        };
        const token = jwt.sign(tokenUser, JWT_SECRET, { expiresIn: '30d' });

        await client.query('COMMIT');
        res.json({
            success: true,
            message: 'अकाउंट सफलतापूर्वक बनाया गया।',
            token: token,
            user: tokenUser
        });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error("Error registering:", err.message);
        res.status(500).json({ success: false, message: 'रजिस्ट्रेशन विफल: ' + err.message });
    } finally {
        client.release();
    }
});


// [ server.cjs फ़ाइल में यह कोड बदलें ]


/// 4. User Login (UPDATED FOR BLOCKING, PLAN TYPE, ADDONS)
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, message: 'ईमेल और पासवर्ड आवश्यक हैं.' });
    }

    try {
        // --- 🚀 FIX 1: Query में 's.status' भी मंगवाया गया है ---
        // ध्यान दें: हमने 's.status' को 'shop_status' नाम दिया है ताकि user के status से कंफ्यूजन न हो
        const result = await pool.query(
            `SELECT u.*, 
                    s.shop_name, 
                    s.license_expiry_date, 
                    s.plan_type, 
                    s.add_ons, 
                    s.business_type, 
                    s.status as shop_status 
             FROM users u 
             JOIN shops s ON u.shop_id = s.id 
             WHERE u.email = $1`,
            [email]
        );

        if (result.rows.length === 0) {
            console.log(`DEBUG LOGIN: User not found for email: ${email}`);
            return res.status(401).json({ success: false, message: 'अमान्य ईमेल या पासवर्ड.' });
        }

        let user = result.rows[0]; 

        // --- 🔴 NEW BLOCK CHECK (यह वह नया कोड है जो आप ढूंढ रहे थे) ---
        // पासवर्ड चेक करने से पहले ही देखें कि दुकान ब्लॉक तो नहीं है
        if (user.shop_status === 'blocked') {
            return res.status(403).json({ 
                success: false, 
                message: '⛔ आपकी दुकान को एडमिन द्वारा अस्थाई रूप से बंद (Blocked) कर दिया गया है। कृपया भुगतान या जानकारी के लिए संपर्क करें।' 
            });
        }
        // -------------------------------------------------------------

        // --- Step 2: Check Password ---
        const isMatch = await bcrypt.compare(password, user.password_hash);
        
        if (!isMatch) {
            return res.status(401).json({ success: false, message: 'अमान्य ईमेल या पासवर्ड.' });
        }

        // --- Step 3: Check/Update User Status ---
        if (user.status !== 'active') {
             await pool.query('UPDATE users SET status = $1 WHERE id = $2', ['active', user.id]);
             user.status = 'active'; 
        }

        // --- Step 4: Shop Details Extract ---
        const shopExpiryDate = user.license_expiry_date; 
        const shopPlanType = user.plan_type || 'TRIAL'; 
        const shopAddOns = user.add_ons || {}; 
        const businessType = user.business_type || 'RETAIL'; 

        // --- Step 5: Token Payload ---
        const tokenUser = {
            id: user.id,
            email: user.email,
            shopId: user.shop_id,
            name: user.name,
            mobile: user.mobile,
            role: user.role,
            shopName: user.shop_name,
            licenseExpiryDate: shopExpiryDate, 
            status: user.status,
            plan_type: shopPlanType,
            add_ons: shopAddOns,
            businessType: businessType
        };
        
        const token = jwt.sign(tokenUser, process.env.JWT_SECRET || 'secret_key', { expiresIn: '30d' });

        // --- Step 6: Check SHOP's License Expiry ---
        const expiryDate = shopExpiryDate ? new Date(shopExpiryDate) : null;
        const currentDate = new Date();
        currentDate.setHours(0, 0, 0, 0);

        if (!expiryDate || expiryDate < currentDate) {
            return res.json({
                success: true, 
                message: 'लाइसेंस समाप्त हो गया है।', 
                requiresLicense: true, 
                token: token, 
                user: tokenUser
            });
        }

        // --- Step 7: Successful Login ---
        res.json({
            success: true,
            message: 'लॉगिन सफल।',
            requiresLicense: false, 
            token: token,
            user: tokenUser
       });

    } catch (err) {
        console.error("Error logging in:", err.message);
        res.status(500).json({ success: false, message: 'Server Error: ' + err.message });
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

        // 7. Fetch user data again (shop_name AND business_type needed)
// 🚀 FIX: 's.business_type' को query में जोड़ा गया
const updatedUserResult = await pool.query(
    'SELECT u.*, s.shop_name, s.shop_logo, s.license_expiry_date, s.plan_type, s.add_ons, s.business_type FROM users u JOIN shops s ON u.shop_id = s.id WHERE u.id = $1',
    [userId]
);
const updatedUser = updatedUserResult.rows[0];

// 8. 🚀 FIX: नए टोकन में 'businessType' भी जोड़ें
const tokenUser = {
    id: updatedUser.id,
    email: updatedUser.email,
    shopId: updatedUser.shop_id,
    name: updatedUser.name,
    mobile: updatedUser.mobile,
    role: updatedUser.role,
    shopName: updatedUser.shop_name,
    licenseExpiryDate: updatedShopExpiryDate,
    status: updatedUser.status,
    plan_type: updatedPlanType,
    add_ons: updatedAddOns,
    businessType: updatedUser.business_type || 'RETAIL' // <--- 🚀 यह लाइन सबसे जरूरी है
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

    if (!name || !email || !password || !['ADMIN', 'MANAGER', 'CASHIER','ACCOUNTANT'].includes(role.toUpperCase())) {
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

// [ ✅ FIXED: Trim SKU to prevent duplicates & Fix Quantity Logic ]

app.post('/api/stock', authenticateJWT, checkRole('CASHIER'), async (req, res) => {
    const { sku, name, quantity, unit, purchase_price, sale_price, gst, cost_price, category, product_attributes, recipe, action_type } = req.body;
    const shopId = req.shopId;

    if (!sku || !name) return res.status(400).json({ success: false, message: 'SKU और नाम आवश्यक हैं.' });

    // 🚀 FIX: SKU से एक्स्ट्रा स्पेस हटाएँ (ताकि "Tube" और "Tube " एक ही माने जाएँ)
    const cleanSku = sku.trim(); 

    const safeQuantity = parseFloat(quantity) || 0;
    const safePurchasePrice = parseFloat(purchase_price) || 0;
    const safeSalePrice = parseFloat(sale_price) || 0;
    const safeGst = parseFloat(gst || 0);
    const safeCostPrice = parseFloat(cost_price || safePurchasePrice);

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 🚀 लॉजिक: अगर action='set' है तो रिप्लेस करो, वरना जोड़ो
        const quantityLogic = (action_type === 'set') 
            ? 'EXCLUDED.quantity'            // Edit Mode (Replace)
            : 'stock.quantity + EXCLUDED.quantity'; // Add Mode (Sum)

        // 🚀 FIX: अब हम cleanSku का उपयोग कर रहे हैं
        const queryText = `
            INSERT INTO stock (shop_id, sku, name, quantity, unit, purchase_price, sale_price, gst, cost_price, category, product_attributes)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (shop_id, sku) DO UPDATE
            SET quantity = ${quantityLogic},
                name = EXCLUDED.name,
                purchase_price = EXCLUDED.purchase_price,
                sale_price = EXCLUDED.sale_price,
                gst = EXCLUDED.gst,
                cost_price = EXCLUDED.cost_price,
                category = EXCLUDED.category,
                product_attributes = EXCLUDED.product_attributes,
                updated_at = CURRENT_TIMESTAMP
            WHERE stock.shop_id = EXCLUDED.shop_id RETURNING *;
        `;

        const result = await client.query(queryText, [
            shopId, cleanSku, name, safeQuantity, unit, safePurchasePrice, safeSalePrice, safeGst, safeCostPrice, category, product_attributes || null
        ]);

        // --- Recipe Logic ---
        if (recipe && Array.isArray(recipe) && recipe.length > 0) {
            await client.query('DELETE FROM service_recipes WHERE shop_id=$1 AND service_sku=$2', [shopId, cleanSku]);
            for (const r of recipe) {
                if (r.sku && r.qty) {
                    // 🚀 FIX: Recipe के अंदर वाले SKU को भी trim करें
                    await client.query(
                        `INSERT INTO service_recipes (shop_id, service_sku, consumable_sku, quantity_needed)
                         VALUES ($1, $2, $3, $4)`,
                        [shopId, cleanSku, r.sku.trim(), parseFloat(r.qty)]
                    );
                }
            }
        }

        await client.query('COMMIT');
        if (typeof broadcastToShop === 'function') broadcastToShop(shopId, JSON.stringify({ type: 'DASHBOARD_UPDATE', view: 'stock' }));
        
        res.json({ success: true, stock: result.rows[0], message: 'स्टॉक सफलतापूर्वक अपडेट हो गया।' });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error("Error adding stock:", err.message);
        res.status(500).json({ success: false, message: 'Error: ' + err.message });
    } finally {
        if (client) client.release();
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

// [ ✅ server.cjs: 8.1 वाले पूरे कोड को इससे बदलें ]
// 8.1 Process New Sale / Create Invoice (UPDATED FOR TALLY-GST, SALON CONSUMPTION & FINANCE)
app.post('/api/invoices', authenticateJWT, async (req, res) => {
    // FIX 1: Extract all necessary fields from req.body including new ones
    const { 
        customerName, 
        customerMobile, 
        total_amount, 
        sale_items, 
        place_of_supply, 
        latitude, 
        longitude, 
        loanAccountNo // New field for Finance/Recovery Agents
    } = req.body;
    
    const shopId = req.shopId;

    if (!total_amount || !Array.isArray(sale_items) || sale_items.length === 0) {
        return res.status(400).json({ success: false, message: 'कुल राशि और बिक्री आइटम आवश्यक हैं.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN'); // Transaction Start

        let customerId = null;
        let customerGstin = null; // TALLY UPDATE

        // 1. Find or Create Customer
        if (customerName && customerName.trim() !== 'अनाम ग्राहक') {
            // Check if customer exists by name
            let customerResult = await client.query('SELECT id, gstin FROM customers WHERE shop_id = $1 AND name = $2', [shopId, customerName.trim()]);
            
            // If not found by name, try finding by mobile
            if (customerResult.rows.length === 0 && customerMobile) {
                 customerResult = await client.query('SELECT id, gstin FROM customers WHERE shop_id = $1 AND phone = $2', [shopId, customerMobile]);
            }

            if (customerResult.rows.length > 0) {
                customerId = customerResult.rows[0].id;
                customerGstin = customerResult.rows[0].gstin;
            } else {
                // Create new customer
                const newCustomerResult = await client.query('INSERT INTO customers (shop_id, name, phone) VALUES ($1, $2, $3) RETURNING id, gstin', [shopId, customerName.trim(), customerMobile]);
                customerId = newCustomerResult.rows[0].id;
                customerGstin = newCustomerResult.rows[0].gstin;
            }
        }

        const safeTotalAmount = parseFloat(total_amount);
        let calculatedTotalCost = 0;

        // TALLY UPDATE: Get Shop's GSTIN for Place of Supply logic
        const profileRes = await client.query('SELECT gstin FROM company_profile WHERE shop_id = $1', [shopId]);
        const shopGstin = (profileRes.rows[0]?.gstin || '').substring(0, 2);
        const supplyPlace = (place_of_supply || shopGstin);

        // 2. Create Invoice
        // [🚀 UPDATED QUERY: Added loan_account_no]
        const invoiceResult = await client.query(
            `INSERT INTO invoices (
                shop_id, customer_id, total_amount, customer_gstin, place_of_supply, 
                latitude, longitude, loan_account_no
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
            [
                shopId, 
                customerId, 
                parseFloat(total_amount), 
                customerGstin, 
                (place_of_supply || ''), 
                latitude || null, 
                longitude || null,
                loanAccountNo || null // Save Loan Account Number here
            ]
        );
        const invoiceId = invoiceResult.rows[0].id;

        // 3. Process Items Loop (Tally + Salon Logic)
        for (const item of sale_items) {
            const safeQuantity = parseFloat(item.quantity);
            const safePurchasePrice = parseFloat(item.purchase_price || 0);
            const salePrice = parseFloat(item.sale_price);
            
            // === TALLY UPDATE START: GST Calc ===
            const gstRate = parseFloat(item.gst || 0);
            const taxableValue = (salePrice * safeQuantity);
            const totalGstAmount = taxableValue * (gstRate / 100);

            let cgst_amount = 0, sgst_amount = 0, igst_amount = 0;

            if (supplyPlace === shopGstin) {
                cgst_amount = totalGstAmount / 2;
                sgst_amount = totalGstAmount / 2;
            } else {
                igst_amount = totalGstAmount;
            }
            // === TALLY UPDATE END ===

            calculatedTotalCost += safeQuantity * safePurchasePrice;
            
            // A. Save Invoice Item
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
            
            // ============================================================
            // 🚀🚀🚀 SALON CONSUMPTION LOGIC START 🚀🚀🚀
            // ============================================================
            
            // 1. Check if recipe exists for this item (Service)
            const recipeRes = await client.query(
                `SELECT consumable_sku, quantity_needed FROM service_recipes WHERE shop_id = $1 AND service_sku = $2`,
                [shopId, item.sku]
            );

            if (recipeRes.rows.length > 0) {
                // === CASE 1: Service with Recipe ===
                console.log(`Salon Logic: ${item.name} sold. Reducing stock based on recipe...`);
                
                for (const recipe of recipeRes.rows) {
                    const qtyNeeded = parseFloat(recipe.quantity_needed);
                    const totalConsume = qtyNeeded * safeQuantity;
                    const targetSku = recipe.consumable_sku;

                    console.log(`Reducing: ${targetSku} by ${totalConsume}`);

                    // Reduce stock
                    await client.query(
                        `UPDATE stock SET quantity = quantity - $1 WHERE sku = $2 AND shop_id = $3`,
                        [totalConsume, targetSku, shopId]
                    );
                }
            } else {
                // === CASE 2: Normal Product ===
                // Only reduce if NOT a service (SKU check or attribute check)
                const isServiceSku = item.sku.startsWith('SVC-') || (item.product_attributes && item.product_attributes.type === 'SERVICE');
                
                if (!isServiceSku) {
                    await client.query(
                        `UPDATE stock SET quantity = quantity - $1 WHERE sku = $2 AND shop_id = $3`,
                        [safeQuantity, item.sku, shopId]
                    );
                }
            }
            // ============================================================
            // 🚀🚀🚀 LOGIC END 🚀🚀🚀
            // ============================================================
        }

        // 4. Update COGS in Invoice
        await client.query(
            `UPDATE invoices SET total_cost = $1 WHERE id = $2`,
            [calculatedTotalCost, invoiceId]
        );
        
        await client.query('COMMIT'); // Transaction End

        // 🚀 Update Dashboard via WebSocket
        if (typeof broadcastToShop === 'function') {
            broadcastToShop(shopId, JSON.stringify({ type: 'DASHBOARD_UPDATE', view: 'sales' }));
        }

        res.json({ success: true, invoiceId: invoiceId, message: 'बिक्री और इन्वेंटरी खपत (Consumption) सफलतापूर्वक दर्ज की गई।' });
    
    } catch (err) {
        await client.query('ROLLBACK');
        console.error("Error processing invoice:", err.message, err.stack);
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

        // --- नया लॉजिक (GST + Finance Data जोड़ने के लिए) ---
        // 🚀 फिक्स: latitude, longitude, loan_account_no को SELECT में जोड़ा गया
        const result = await pool.query(`
            SELECT 
                i.id, 
                i.total_amount, 
                i.created_at, 
                i.latitude, 
                i.longitude, 
                i.loan_account_no, 
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

        res.json({ success: true, sales: result.rows, message: "चालान सफलतापूर्वक लोड किए गए।" });
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
        // 🚀 FIX: Services (जिनका SKU 'SVC-' है या Unit 'Session' है) को स्टॉक वैल्यू में न जोड़ें
        const stockValueResult = await client.query(
            `SELECT COALESCE(SUM(quantity * purchase_price), 0) AS inventory_value 
             FROM stock 
             WHERE shop_id = $1 
               AND sku NOT LIKE 'SVC-%' 
               AND unit != 'Session'`,
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



// [ यह नया API अपनी server.cjs फ़ाइल के अंत में पेस्ट करें ]

// -----------------------------------------------------------------------------
// --- 🚀 18. AI INSIGHTS API (Oracle Bypass) ---
// -----------------------------------------------------------------------------
app.get('/api/ai/stock-insights', authenticateJWT, checkPlan(['MEDIUM','PREMIUM'],'has_ai_insights'), async (req, res) => {
    const shopId = req.shopId;
    const client = await pool.connect();

    try {
        // 1) SALES VELOCITY (last 30 days)
        const velocityQuery = `
            SELECT 
                ii.item_sku AS sku,
                SUM(ii.quantity) AS total_sold_30d,
                (SUM(ii.quantity) / 30.0) AS avg_sales_per_day,
                AVG(ii.sale_price) AS avg_sale_price
            FROM invoice_items ii
            JOIN invoices i ON ii.invoice_id = i.id
            WHERE i.shop_id = $1
            AND i.created_at >= (CURRENT_DATE - INTERVAL '30 days')
            GROUP BY ii.item_sku
        `;
        const velocityResult = await client.query(velocityQuery, [shopId]);

        const velocityMap = new Map();
        velocityResult.rows.forEach(r => {
            velocityMap.set(r.sku, {
                avg_per_day: Number(r.avg_sales_per_day || 0),
                avg_sale_price: Number(r.avg_sale_price || 0)
            });
        });

        // 2) CURRENT STOCK WITH PRICE
        const stockQuery = `
            SELECT 
                s.sku, s.name, s.quantity, 
                s.purchase_price, s.sale_price,
                (s.quantity * s.purchase_price) AS stock_value,
                (
                    SELECT MAX(i.created_at)
                    FROM invoices i 
                    JOIN invoice_items ii ON i.id = ii.invoice_id
                    WHERE i.shop_id = s.shop_id AND ii.item_sku = s.sku
                ) AS last_sold_date
            FROM stock s
            WHERE s.shop_id = $1 AND s.quantity > 0
        `;
        const stockResult = await client.query(stockQuery, [shopId]);

        const fast_moving = [];
        const dead_stock = [];
        const restock = [];

        let totalStockValue = 0;
        let deadStockValue = 0;

        const thresholdDate = new Date();
        thresholdDate.setDate(thresholdDate.getDate() - 30);

        for (const item of stockResult.rows) {

            const sku = item.sku;
            const name = item.name;
            const qty = Number(item.quantity || 0);
            const pprice = Number(item.purchase_price || 0);
            const sprice = Number(item.sale_price || 0);
            const stockValue = qty * pprice;

            totalStockValue += stockValue;

            const v = velocityMap.get(sku);
            const avgDay = v ? v.avg_per_day : 0;

            if (avgDay > 0) {
                const days_left = qty / avgDay;

                if (days_left < 3) {
                    fast_moving.push({
                        sku, name,
                        days_left: Math.round(days_left * 10) / 10,
                        current_qty: qty,
                        sale_price: sprice
                    });
                }

                if (days_left < 7) {
                    const suggested = Math.ceil((30 * avgDay) - qty);
                    if (suggested > 0) {
                        restock.push({
                            sku, name,
                            current_qty: qty,
                            suggested_reorder: suggested
                        });
                    }
                }
            } else {
                const lastSold = item.last_sold_date ? new Date(item.last_sold_date) : null;
                if (!lastSold || lastSold < thresholdDate) {
                    if (stockValue > 500) {
                        dead_stock.push({
                            sku, name,
                            stock_value: Math.round(stockValue),
                            current_qty: qty
                        });
                        deadStockValue += stockValue;
                    }
                }
            }
        }

        let businessScore = 100;
        if (totalStockValue > 0) {
            const deadRatio = deadStockValue / totalStockValue;
            businessScore = Math.max(20, Math.round(100 - deadRatio * 120));
        }

        res.json({
            success: true,
            insights: {
                business_health_score: businessScore,
                fast_moving,
                dead_stock,
                restock
            }
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ success:false, message:"AI Insights error: " + err.message });
    } finally {
        client.release();
    }
});


// ===========================================
// REAL CUSTOMER INTELLIGENCE API
// ===========================================
app.get('/api/ai/customers-intel', authenticateJWT, async (req, res) => {
  const client = await pool.connect();
  const shopId = req.shopId;

  try {
    // 1) हर ग्राहक ने क्या खरीदा + कितनी बार खरीदा
    const purchaseQuery = `
      SELECT 
        c.id AS customer_id,
        c.name AS customer_name,
        ii.item_sku,
        ii.item_name,
        COUNT(ii.item_sku) AS buy_count,
        MAX(i.created_at) AS last_buy
      FROM customers c
      LEFT JOIN invoices i ON c.id = i.customer_id
      LEFT JOIN invoice_items ii ON ii.invoice_id = i.id
      WHERE c.shop_id = $1
      GROUP BY c.id, c.name, ii.item_sku, ii.item_name
      ORDER BY c.name ASC;
    `;
    const result = await client.query(purchaseQuery, [shopId]);

    // Group by customer
    const customers = {};
    result.rows.forEach(r => {
      if (!customers[r.customer_id]) {
        customers[r.customer_id] = {
          id: r.customer_id,
          name: r.customer_name,
          last_buy: r.last_buy,
          items: []
        };
      }
      if (r.item_sku) {
        customers[r.customer_id].items.push({
          sku: r.item_sku,
          name: r.item_name,
          buy_count: Number(r.buy_count)
        });
      }
    });

    // Convert object to array
    const data = Object.values(customers);

    res.json({ success: true, customers: data });

  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  } finally {
    client.release();
  }
});



// ===========================================
// REAL PRODUCT INTELLIGENCE API
// ===========================================
app.get('/api/ai/products-intel', authenticateJWT, async (req, res) => {
  const client = await pool.connect();
  const shopId = req.shopId;

  try {
    const query = `
      SELECT 
        s.sku,
        s.name,
        s.quantity,
        s.purchase_price,
        s.sale_price,
        (SELECT SUM(ii.quantity)
         FROM invoice_items ii
         JOIN invoices i ON ii.invoice_id = i.id
         WHERE ii.item_sku = s.sku AND i.shop_id = $1) AS total_sold,
        (SELECT MAX(i.created_at)
         FROM invoices i 
         JOIN invoice_items ii ON i.id = ii.invoice_id
         WHERE ii.item_sku = s.sku AND i.shop_id = $1) AS last_sold
      FROM stock s
      WHERE s.shop_id = $1;
    `;

    const result = await client.query(query, [shopId]);

    res.json({ success: true, products: result.rows });

  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  } finally {
    client.release();
  }
});



// ===========================================
// SALES + STOCK PREDICTION AI
// ===========================================
app.get('/api/ai/prediction', authenticateJWT, async (req, res) => {
  const client = await pool.connect();
  const shopId = req.shopId;

  try {
    const query = `
      SELECT 
        DATE(i.created_at) AS day,
        SUM(i.total_amount) AS total_sales
      FROM invoices i
      WHERE i.shop_id = $1
      AND i.created_at >= NOW() - INTERVAL '30 days'
      GROUP BY DATE(i.created_at)
      ORDER BY DATE(i.created_at);
    `;

    const result = await client.query(query, [shopId]);

    res.json({ success: true, sales: result.rows });

  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  } finally {
    client.release();
  }
});

// ===============================================
// WHATSAPP ADVISOR AI — HIGH PROBABILITY SUGGESTIONS
// ===============================================
app.get('/api/ai/clients-whatsapp', authenticateJWT, async (req, res) => {
  const client = await pool.connect();
  const shopId = req.shopId;

  try {

    // 1) Customers + last purchase + total spend
    const q = `
      SELECT 
        c.id,
        c.name,
        c.phone,
        MAX(i.created_at) AS last_purchase,
        SUM(i.total_amount) AS total_spent
      FROM customers c
      LEFT JOIN invoices i ON c.id = i.customer_id
      WHERE c.shop_id = $1
      GROUP BY c.id, c.name, c.phone
      ORDER BY c.name ASC;
    `;
    const customers = (await client.query(q, [shopId])).rows;

    // 2) Customer-wise purchase items
    const itemQ = `
      SELECT 
        ii.item_sku,
        ii.item_name,
        ii.quantity,
        i.customer_id,
        i.created_at
      FROM invoice_items ii
      JOIN invoices i ON ii.invoice_id = i.id
      WHERE i.shop_id = $1
      ORDER BY i.customer_id, i.created_at DESC;
    `;
    const allItems = (await client.query(itemQ, [shopId])).rows;

    let output = [];

    for (let c of customers) {

      // उस customer के items filter करो
      const bought = allItems.filter(x => x.customer_id === c.id);

      if (!bought.length) {
        // कोई purchase नहीं → कोई suggestion नहीं
        output.push({
          ...c,
          suggestions: []
        });
        continue;
      }

      // Top repeated item निकाल रहे हैं
      let itemCount = {};
      bought.forEach(b => {
        if (!itemCount[b.item_name]) itemCount[b.item_name] = 0;
        itemCount[b.item_name] += b.quantity;
      });

      // सबसे ज्यादा खरीदा हुआ item
      let bestItem = Object.keys(itemCount).sort(
        (a, b) => itemCount[b] - itemCount[a]
      )[0];

      output.push({
        ...c,
        suggestions: [
          {
            item: bestItem,
            suggestedQty: 2,
            liftPercent: 35
          }
        ]
      });
    }

    res.json({ success: true, clients: output });

  } catch (err) {
    console.error("WHATSAPP ADVISOR ERROR:", err);
    res.status(500).json({ success: false, message: err.message });
  } finally {
    client.release();
  }
});


// ===============================================
// AI CUSTOMER PROBABILITY + OFFER ENGINE
// ===============================================
app.get('/api/ai/customer-probability', authenticateJWT, async (req, res) => {
  const client = await pool.connect();
  const shopId = req.shopId;

  try {
    const q = `
      SELECT 
        c.id,
        c.name,
        c.phone,
        MAX(i.created_at) AS last_purchase,
        COUNT(i.id) AS total_bills,
        SUM(i.total_amount) AS total_spent,
        (SELECT item_name FROM invoice_items ii 
          JOIN invoices ix ON ii.invoice_id = ix.id
          WHERE ix.customer_id = c.id
          ORDER BY ix.created_at DESC LIMIT 1) AS last_item,
        (SELECT item_name 
          FROM invoice_items ii 
          JOIN invoices ix ON ii.invoice_id = ix.id
          WHERE ix.customer_id = c.id
          GROUP BY item_name 
          ORDER BY COUNT(*) DESC LIMIT 1) AS frequent_item
      FROM customers c
      LEFT JOIN invoices i ON c.id = i.customer_id
      WHERE c.shop_id = $1
      GROUP BY c.id, c.name, c.phone
      ORDER BY c.name ASC;
    `;

    const result = await client.query(q, [shopId]);
    const customers = result.rows.map(c => {
      let daysInactive = c.last_purchase 
          ? Math.floor((Date.now() - new Date(c.last_purchase)) / (1000*60*60*24))
          : 999;

      // --- Probability (AI Formula) ---
      let p = 80;
      p -= daysInactive * 2;
      p += c.total_bills * 1.5;
      p += c.total_spent > 20000 ? 10 : 0;

      if (p < 5) p = 5;
      if (p > 95) p = 95;

      // --- Offer suggestion logic ---
      let offer;
      if (p >= 70) {
        offer = "5% छूट — High Probability Customer";
      } else if (p >= 40) {
        offer = "₹50 Cashback Offer";
      } else {
        offer = "Exclusive Reminder Message";
      }

      return {
        ...c,
        inactive_days: daysInactive,
        probability: Math.round(p),
        offer
      };
    });

    res.json({ success: true, customers });

  } catch (err) {
    res.status(500).json({ success:false, message: err.message });
  } finally {
    client.release();
  }
});



// ========================================================
// FULL BUSINESS AI CHAT (Real Data + Smart Advisor)
// ========================================================
// ==============================
// ULTIMATE LOCAL AI: Business + World Answers (No OpenAI Key required)
// Replace any existing app.post('/api/ai/business-chat' ...) block with this.
// ==============================
// -------------------------
// AI: Business Chat (Rule-based, DB-driven, Hindi)
// -------------------------
app.post('/api/ai/business-chat', authenticateJWT, async (req, res) => {
  const client = await pool.connect();
  const shopId = req.shopId;
  const userQuery = (req.body && req.body.question) ? String(req.body.question).trim() : "";

  try {
    if (!userQuery) return res.status(400).json({ success:false, message: 'प्रश्न रिक्त है। कृपया कुछ लिखें।' });

    // 1) Fetch lightweight datasets (only required columns) — keep queries small for speed
    const stockQ = await client.query(`SELECT sku, name, quantity, purchase_price, sale_price FROM stock WHERE shop_id=$1`, [shopId]);
    const invoicesQ = await client.query(`SELECT id, total_amount, total_cost, created_at, customer_id FROM invoices WHERE shop_id=$1 ORDER BY created_at DESC LIMIT 500`, [shopId]);
    const invoiceItemsQ = await client.query(`SELECT invoice_id, item_sku, item_name, quantity, sale_price, purchase_price FROM invoice_items WHERE invoice_id IN (SELECT id FROM invoices WHERE shop_id=$1)`, [shopId]);
    const customersQ = await client.query(`SELECT id, name, phone, balance FROM customers WHERE shop_id=$1`, [shopId]);

    const stock = stockQ.rows || [];
    const invoices = invoicesQ.rows || [];
    const invoiceItems = invoiceItemsQ.rows || [];
    const customers = customersQ.rows || [];

    // 2) Basic derived metrics (fast calculations)
    const totals = {
      sales: invoices.reduce((s, r) => s + Number(r.total_amount || 0), 0),
      cost: invoices.reduce((s, r) => s + Number(r.total_cost || 0), 0)
    };
    totals.profit = totals.sales - totals.cost;

    // 3) Helper functions
    function topFastMoving(n=5) {
      // compute sold qty per SKU from invoiceItems
      const map = new Map();
      invoiceItems.forEach(it => {
        const qty = Number(it.quantity || 0);
        map.set(it.item_sku, (map.get(it.item_sku) || 0) + qty);
      });
      const arr = Array.from(map.entries()).map(([sku, qty]) => {
        const s = stock.find(st => st.sku === sku) || {};
        return { sku, name: s.name || sku, qtySold: qty, current_qty: Number(s.quantity || 0) };
      });
      arr.sort((a,b)=>b.qtySold - a.qtySold);
      return arr.slice(0,n);
    }

    function findCustomerByName(nameFragment) {
      const q = String(nameFragment || "").toLowerCase();
      return customers.find(c => (c.name || '').toLowerCase().includes(q) || (c.phone || '').includes(q));
    }

    // 4) Intent detection (simple, pattern-based)
    const qLower = userQuery.toLowerCase();

    // Common intents
    const intents = {
      profit: /profit|munafa|मुनाफा|लाभ|profit|कमाई/,
      deadStock: /dead|न बिक|dead stock|फँसा|न बिकने|न बिकता/,
      customerInfo: /customer|ग्राहक|कस्टमर|किसने|कौन/ ,
      offer: /offer|discount|ऑफ़र|डिस्काउंट|छूट/,
      productInfo: /product|product name|प्रोडक्ट|कौन सा सामान|कौनसा सामान|कौनसा/,
      retention: /wont come|न आएगा|वापस|वापिस|dobara|दोबारा/,
      whatsapp: /whatsapp|व्हाट्स|message|मैसेज|संदेश/,
      generic: /.*/
    };

    // Decide applicable intent
    let matchedIntent = 'generic';
    for (const [k, pattern] of Object.entries(intents)) {
      if (pattern.test(qLower)) { matchedIntent = k; break; }
    }

    // 5) Response builders per intent (rich, Hindi)
    let answer = '';

    if (matchedIntent === 'profit') {
      answer = `मैंने हाल के रिकॉर्ड (जिनकी गणना उपलब्ध रही) से आपका संक्षेप निकाला है:\n\n`;
      answer += `• अनुमानित कुल बिक्री: ₹${Math.round(totals.sales)}\n`;
      answer += `• अनुमानित कुल लागत: ₹${Math.round(totals.cost)}\n`;
      answer += `• अनुमानित कुल मुनाफा: ₹${Math.round(totals.profit)}\n\n`;
      answer += `तेज़ सुझाव:\n• जो आइटम तेज़ बिक रहे हैं (Top ${Math.min(5, topFastMoving(5).length)}): ${topFastMoving(5).map(i=>i.name).join(', ') || '—'} — इनकी स्टॉक बनाए रखें।\n`;
      answer += `• पाँच बड़े कस्टमर को targeted WhatsApp ऑफर दें और weekend/tyohar पर combo offers रखें।\n`;
      answer += `अगर आप चाहें तो मैं detailed margin-by-product निकाल दूँ — बस पूछिए "product wise profit बताओ"।`;
    }

    else if (matchedIntent === 'deadStock') {
      // heuristics: not sold in last 30 days OR stock_value>threshold
      const thirtyAgo = new Date(Date.now() - 30*24*60*60*1000);
      // compute last sold per sku from invoices/invoiceItems
      const lastSold = {};
      invoiceItems.forEach(ii=>{
        // find invoice date
        const inv = invoices.find(iv => iv.id === ii.invoice_id);
        const date = inv ? new Date(inv.created_at) : null;
        if (!lastSold[ii.item_sku] || (date && date > lastSold[ii.item_sku])) lastSold[ii.item_sku] = date;
      });
      const dead = stock.filter(s=>{
        const last = lastSold[s.sku];
        return (!last || last < thirtyAgo) && Number(s.quantity || 0) > 0;
      }).map(s=>({ sku:s.sku, name:s.name, qty: Number(s.quantity||0), stock_value: Math.round(Number(s.quantity||0)*Number(s.purchase_price||0)) }));

      answer = `Dead stock analysis:\n• ऐसे ${dead.length} आइटम मिले जो 30+ दिनों से नहीं बिके।\n`;
      if (dead.length) {
        answer += dead.slice(0,8).map(d=>`  - ${d.name} (SKU:${d.sku}) — Qty: ${d.qty}, फँसा पैसा: ₹${d.stock_value}`).join('\n') + '\n\n';
        answer += 'सलाह:\n• इनपर 10–25% का limited-time discount डालें या bundle/combo बनाकर बेचें।\n• Social/WhatsApp पर daily special में इन्हें include करें।';
      } else {
        answer += 'कोई प्रमुख dead stock नहीं दिख रहा।';
      }
    }

    else if (matchedIntent === 'customerInfo' || matchedIntent === 'retention' || matchedIntent === 'whatsapp') {
      // try to extract customer name or phone from query (simple)
      const nameMatch = (userQuery.match(/[A-Z][a-z]+|[A-Za-z]+|[^\s]+/g) || []).slice(0,3).join(' ');
      const cust = findCustomerByName(nameMatch) || null;

      if (cust) {
        // compute purchases by this customer
        const custInvoices = invoices.filter(iv => Number(iv.customer_id) === Number(cust.id));
        const totalSpent = custInvoices.reduce((s,r)=>s+Number(r.total_amount||0),0);
        answer = `ग्राहक: ${cust.name} (${cust.phone || 'N/A'})\n• पिछले खरीदारी रिकॉर्ड: ${custInvoices.length} बिल, कुल खर्च ~ ₹${Math.round(totalSpent)}\n`;
        answer += `Retention idea:\n• इस ग्राहक के लिए personalised offer भेजें: "₹${Math.max(50, Math.round(totalSpent*0.05))} का immediate discount on next purchase" — WhatsApp broadcast से सबसे ज़्यादा असर मिलता है।`;
      } else {
        // generic steps to recover lost customer
        answer = `मुझे ग्राहक की पहचान नहीं मिली। कृपया ग्राहक का नाम या मोबाइल बताइए (या invoice न. दें)।\nसामान्य रणनीति जब ग्राहक दूसरी दुकान चला जाए:\n• SMS/WhatsApp पर 'हम आपको मिस करते हैं' का short coupon भेजें\n• उसके खरीदे सामान के आधार पर relevant bundle भेजें\n• 7 दिन के भीतर repeat-visit पर extra incentive दें`;
      }
    }

    else if (matchedIntent === 'productInfo') {
      // attempt to find product mentioned
      const words = userQuery.split(/\s+/).slice(0,6).join(' ');
      let found = stock.find(s => (s.name || '').toLowerCase().includes(words.toLowerCase()));
      if (!found) {
        // try best-effort by SKU patterns
        found = stock.find(s => (userQuery.toLowerCase().includes(s.sku ? s.sku.toLowerCase() : '')));
      }
      if (found) {
        // compute last sold and sold count
        const soldQty = invoiceItems.filter(ii => ii.item_sku === found.sku).reduce((a,b)=>a+Number(b.quantity||0),0);
        answer = `Product: ${found.name} (SKU: ${found.sku})\n• Current stock: ${found.quantity}\n• Total sold (available data): ${soldQty}\n`;
        if (Number(found.quantity) < 5) answer += 'Recommendation: तुरंत reorder करें — यह fast-moving लग रहा है।';
        else answer += 'Recommendation: stock ठीक है।';
      } else {
        answer = `उस प्रोडक्ट का सही मिलान नहीं हुआ। कृपया product का पूरा नाम या SKU दें।`;
      }
    }

    else {
      // generic: smart summary + call-to-action
      const topFast = topFastMoving(4);
      answer = `मैंने आपके बिजनेस डेटा का संक्षेप निकाला है — quick actionable insights:\n\n`;
      answer += `• Estimated profit (available records): ₹${Math.round(totals.profit)}\n• Fast-moving (Top ${topFast.length}): ${topFast.map(i=>i.name).join(', ') || '—'}\n`;
      answer += `• Dead stock: (उपलब्ध डेटा के हिसाब से analyze करें) — आप 'dead stock दिखाओ' पूछें।\n\n`;
      answer += `अगला कदम सुझाएँ? — आप ये पूछ सकते हैं:\n• 'Rahul का पूरा record दिखाओ' (किसी ग्राहक पर स्पेसिफिक)\n• 'Top 5 profit-margin items बताओ'\n• 'WhatsApp campaign बनाओ — 2 लाइन का message बनाओ'`;
    }

    // add small variation / personalization so answer not always identical
    answer += `\n\n(सूचना: यह सुझाव आपके उपलब्ध रिकॉर्ड पर आधारित हैं — और अधिक सटीकता के लिए specific SKU/Customer/Date-range पूछें)`;

    return res.json({ success:true, answer });

  } catch (err) {
    console.error('AI Chat Error:', err);
    return res.status(500).json({ success:false, message: 'AI चैट में त्रुटि: ' + (err.message || 'unknown') });
  } finally {
    try { client.release(); } catch(e){}
  }
});


// ===========================================
// MONTHLY / FESTIVAL STRATEGY AI
// Returns Hindi strategy, reorder suggestions, ad-calendar, top items
// ===========================================
app.get('/api/ai/monthly-strategy', authenticateJWT, async (req, res) => {
  const client = await pool.connect();
  const shopId = req.shopId;

  try {
    // params (optional): month and year (default = current month)
    const month = parseInt(req.query.month) || (new Date().getMonth() + 1);
    const year = parseInt(req.query.year) || new Date().getFullYear();

    // 1) basic sales aggregates: last 90 days sales per item + last 30 days avg per day
    const salesQuery = `
      SELECT 
        ii.item_sku AS sku,
        ii.item_name AS name,
        SUM(ii.quantity) AS total_qty_90d,
        (SUM(ii.quantity) / 90.0) AS avg_day_90d
      FROM invoice_items ii
      JOIN invoices i ON ii.invoice_id = i.id
      WHERE i.shop_id = $1 AND i.created_at >= (CURRENT_DATE - INTERVAL '90 days')
      GROUP BY ii.item_sku, ii.item_name
      ORDER BY SUM(ii.quantity) DESC
      LIMIT 200;
    `;
    const salesRes = await client.query(salesQuery, [shopId]);

    // 2) stock snapshot (to compute reorder)
    const stockQuery = `SELECT sku, name, quantity, purchase_price, sale_price, category FROM stock WHERE shop_id=$1`;
    const stockRes = await client.query(stockQuery, [shopId]);

    // 3) category sales last 90 days (if category exists)
    const catQuery = `
      SELECT COALESCE(s.category, 'अनिर्दिष्ट') AS category,
             SUM(ii.quantity * COALESCE(ii.sale_price, s.sale_price, 0)) AS revenue
      FROM invoice_items ii
      JOIN invoices i ON ii.invoice_id = i.id
      LEFT JOIN stock s ON ii.item_sku = s.sku AND s.shop_id = i.shop_id
      WHERE i.shop_id = $1 AND i.created_at >= (CURRENT_DATE - INTERVAL '90 days')
      GROUP BY COALESCE(s.category, 'अनिर्दिष्ट')
      ORDER BY revenue DESC;
    `;
    const catRes = await client.query(catQuery, [shopId]);

    // 4) daily average sales last 30 days (global)
    const dailyQuery = `
      SELECT DATE(i.created_at) as day, SUM(i.total_amount) as total
      FROM invoices i
      WHERE i.shop_id=$1 AND i.created_at >= (CURRENT_DATE - INTERVAL '30 days')
      GROUP BY DATE(i.created_at)
      ORDER BY DATE(i.created_at);
    `;
    const dailyRes = await client.query(dailyQuery, [shopId]);

    // 5) identify fast movers and dead stock using existing heuristics
    const fast_movers = [];
    const dead_stock = [];
    const thirtyDaysAgo = new Date(Date.now() - 30*24*3600*1000);

    const salesMap = new Map(); // sku -> avg_day_90d
    salesRes.rows.forEach(r => salesMap.set(r.sku, Number(r.avg_day_90d || 0)));

    const stockMap = new Map(); // sku -> stock row
    stockRes.rows.forEach(s => stockMap.set(s.sku, s));

    for (const [sku, stockRow] of stockMap.entries()) {
      const qty = Number(stockRow.quantity || 0);
      const avgDay = salesMap.get(sku) || 0;
      const days_left = avgDay > 0 ? qty / avgDay : Infinity;

      if (avgDay > 0 && days_left < 7) {
        fast_movers.push({
          sku,
          name: stockRow.name,
          current_qty: qty,
          avg_day: Number(avgDay.toFixed(2)),
          days_left: Math.round(days_left*10)/10
        });
      }

      // dead: not sold in last 30 days OR total sold 90d == 0 and stock value > threshold
      const sold90 = salesRes.rows.find(r=>r.sku===sku);
      if ((!sold90 || Number(sold90.total_qty_90d || 0) === 0) && qty > 0 && (qty * Number(stockRow.purchase_price || 0) > 500)) {
        dead_stock.push({
          sku, name: stockRow.name, current_qty: qty,
          stock_value: Math.round(qty * Number(stockRow.purchase_price || 0))
        });
      }
    }

    // 6) Reorder suggestions based on avg_day_90d * leadTime * safetyFactor
    const leadTimeDays = 7;
    const safetyFactor = 1.5;
    const reorder = [];
    salesRes.rows.forEach(it => {
      const sku = it.sku;
      const avgDay = Number(it.avg_day_90d || 0);
      const s = stockMap.get(sku);
      const currentQty = s ? Number(s.quantity || 0) : 0;
      const suggested = Math.max(0, Math.ceil((avgDay * leadTimeDays * safetyFactor) - currentQty));
      if (suggested > 0) {
        reorder.push({
          sku,
          name: it.name,
          current_qty: currentQty,
          suggested_reorder: suggested,
          avg_day: Number(avgDay.toFixed(2))
        });
      }
    });

    // 7) Top categories to promote (top 3 by revenue)
    const topCategories = (catRes.rows || []).slice(0,3).map(r => ({ category: r.category, revenue: Math.round(Number(r.revenue||0)) }));

    // 8) Simple monthly forecast: avg daily sales * days in month (last 30 days avg)
    const dailyTotals = dailyRes.rows.map(r => Number(r.total || 0));
    const avgDaily = dailyTotals.length ? Math.round(dailyTotals.reduce((a,b)=>a+b,0)/dailyTotals.length) : 0;
    const daysInMonth = new Date(year, month, 0).getDate();
    const forecastMonth = Math.round(avgDaily * daysInMonth);

    // 9) Festival detection by month (simple mapping)
    const festivalMap = {
      1: ['मकर संक्रांति'],
      2: ['वैलेंटाइन डे'],
      3: ['होली'],
      4: ['राम नवमी','ईस्टर'],
      5: ['अनेक लोकल त्यौहार'],
      6: ['गर्मी सेल'],
      7: ['राखी (कभी अगस्त)'],
      8: ['रक्षा बंधन','स्वतंत्रता दिवस'],
      9: ['नवरात्रि'],
      10: ['दिवाली'],
      11: ['दिवाली/छठ'],
      12: ['नया साल','क्रिसमस']
    };
    const festivals = festivalMap[month] || [];

    // 10) Build campaign calendar recommendations (weekly)
    const campaign = [];
    campaign.push({ week:1, action: `Fast-moving items पर Social पोस्ट और Reels` });
    campaign.push({ week:2, action: `Top categories (${topCategories.map(t=>t.category).join(', ') || '—'}) पर 10% ऑफ़र` });
    campaign.push({ week:3, action: `Dead stock पर BOGO/Combo और local WhatsApp blast` });
    campaign.push({ week:4, action: `High-value ग्राहकों के लिए Exclusive coupon भेजें` });

    // 11) Final Hindi strategy text (short)
    let strategyText = `इस महीने की संक्षिप्त रणनीति:\n`;
    strategyText += `• उम्मीद की कुल बिक्री (अनुमान) : ₹${forecastMonth}\n`;
    if (festivals.length) strategyText += `• मुख्य त्यौहार: ${festivals.join(', ')}\n`;
    strategyText += `• तेज़-चलने वाले: ${fast_movers.slice(0,5).map(f=>f.name).join(', ') || '—'}\n`;
    strategyText += `• हटाने/डील के लिए (Dead stock): ${dead_stock.slice(0,5).map(d=>d.name).join(', ') || '—'}\n`;
    strategyText += `• सुझाव: महीने की पहली 2 सप्ताह में विज्ञापन बढ़ाएँ; त्यौहार से 10-15 दिन पहले स्टॉक सुनिश्चित करें।`;

    // response
    res.json({
      success: true,
      month,
      year,
      forecast_month_amount: forecastMonth,
      avg_daily_sales: avgDaily,
      top_categories: topCategories,
      fast_movers,
      dead_stock,
      reorder,
      campaign_calendar: campaign,
      festivals,
      strategy_text: strategyText
    });

  } catch (err) {
    console.error("monthly-strategy error:", err.stack || err);
    res.status(500).json({ success:false, message: err.message });
  } finally {
    client.release();
  }
});



// ===============================
// FESTIVAL STRATEGY (AI INSIGHTS)
// ===============================
// Add / replace this route in server.cjs
app.get('/api/ai/festival-strategy', authenticateJWT, async (req, res) => {
  const client = await pool.connect();
  const shopId = req.shopId;

  // Config: festival list (month-day). You can extend this list.
  const FESTIVALS = [
    { key:'diwali', name:'Diwali', month:10, day:24 },     // example (update if needed)
    { key:'holi', name:'Holi', month:3, day:25 },
    { key:'raksha', name:'Raksha Bandhan', month:8, day:19 },
    { key:'navratri', name:'Navratri', month:10, day:15 },
    { key:'eid', name:'Eid', month:6, day:5 },
    { key:'christmas', name:'Christmas', month:12, day:25 }
  ];

  try {
    // 1) Fetch invoice & invoice_items for past 730 days (2 years) for this shop
    const twoYearsAgo = new Date();
    twoYearsAgo.setDate(twoYearsAgo.getDate() - 730);
    const invoicesRes = await client.query(
      `SELECT id, created_at FROM invoices WHERE shop_id=$1 AND created_at >= $2`,
      [shopId, twoYearsAgo.toISOString()]
    );
    const invoiceIds = invoicesRes.rows.map(r=>r.id);
    if (!invoiceIds.length) {
      return res.json({ success:true, festivals: [], message: 'कोई पिछले 2 वर्षों के invoice रिकॉर्ड नहीं मिले।' });
    }

    // Fetch invoice_items for those invoices
    const invoiceItemsRes = await client.query(
      `SELECT invoice_id, item_sku, item_name, quantity, sale_price, purchase_price 
       FROM invoice_items WHERE invoice_id = ANY($1::int[])`,
      [invoiceIds]
    );
    const items = invoiceItemsRes.rows || [];

    // Utility: convert date to YYYY-MM-DD
    const toYMD = d => {
      const dt = new Date(d);
      const y = dt.getFullYear();
      const m = String(dt.getMonth()+1).padStart(2,'0');
      const day = String(dt.getDate()).padStart(2,'0');
      return `${y}-${m}-${day}`;
    };

    // Build a map: date -> { sku -> qty, revenue, count }
    const dailyMap = new Map();
    for (const it of items) {
      const inv = invoicesRes.rows.find(iv => iv.id === it.invoice_id);
      if (!inv) continue;
      const dateKey = toYMD(inv.created_at);
      if (!dailyMap.has(dateKey)) dailyMap.set(dateKey, {});
      const sku = it.item_sku || it.item_name || 'UNKNOWN';
      const entry = dailyMap.get(dateKey);
      if (!entry[sku]) entry[sku] = { qty:0, revenue:0 };
      entry[sku].qty += Number(it.quantity || 0);
      entry[sku].revenue += Number(it.sale_price || 0) * Number(it.quantity || 0);
    }

    // Helper to sum qty/revenue in window around a given date for each SKU
    function aggregateWindowAround(month, day, yearWindow = [ -2, -1, 0 ]) {
      // yearWindow: relative years to consider (e.g., -2,-1)
      const resultBySku = new Map();
      const now = new Date();
      const thisYear = now.getFullYear();
      for (const rel of yearWindow) {
        const y = thisYear + rel;
        // target date
        const dt = new Date(y, month-1, day); // month-1 because JS months 0-indexed
        if (isNaN(dt)) continue;
        // window +/-7 days (configurable)
        for (let offset=-7; offset<=7; offset++) {
          const d = new Date(dt);
          d.setDate(dt.getDate() + offset);
          const key = toYMD(d);
          const dayObj = dailyMap.get(key);
          if (!dayObj) continue;
          for (const [sku, stats] of Object.entries(dayObj)) {
            if (!resultBySku.has(sku)) resultBySku.set(sku, { qty:0, revenue:0, samples:0 });
            const r = resultBySku.get(sku);
            r.qty += stats.qty;
            r.revenue += stats.revenue;
            r.samples += 1;
            resultBySku.set(sku, r);
          }
        }
      }
      return resultBySku; // Map sku -> aggregated stats
    }

    // Compute baseline daily average for each sku over the entire period
    const baseline = new Map(); // sku -> { totalQty, totalDaysSeen }
    for (const [dateKey, skuObj] of dailyMap.entries()) {
      for (const [sku, s] of Object.entries(skuObj)) {
        if (!baseline.has(sku)) baseline.set(sku, { totalQty:0, days:0 });
        const b = baseline.get(sku);
        b.totalQty += s.qty;
        b.days += 1;
        baseline.set(sku, b);
      }
    }
    // Convert baseline to avg per day
    const baselineAvg = new Map();
    for (const [sku, b] of baseline.entries()) {
      baselineAvg.set(sku, b.days ? (b.totalQty / b.days) : 0);
    }

    // For each festival compute aggregated stats and detect top rising SKUs
    const festivalsOut = [];
    for (const fest of FESTIVALS) {
      const agg = aggregateWindowAround(fest.month, fest.day, [-2, -1]); // last 2 years
      // Convert Map -> array and compute lift vs baseline
      const arr = [];
      for (const [sku, s] of agg.entries()) {
        const avg = baselineAvg.get(sku) || 0.0001; // avoid divide by zero
        // samples is number of days data seen for that sku in the windows across years
        // compute avg daily qty in festival window = s.qty / s.samples
        const avgFestival = s.samples ? (s.qty / s.samples) : 0;
        const liftPercent = avg ? Math.round(((avgFestival - avg) / (avg || 1)) * 100) : 0;
        arr.push({ sku, qty: s.qty, revenue: Math.round(s.revenue), samples: s.samples, avgFestival: Math.round(avgFestival*100)/100, baselineAvg: Math.round(avg*100)/100, liftPercent });
      }
      arr.sort((a,b)=>b.liftPercent - a.liftPercent);
      const top = arr.slice(0,8);

      // Suggest stock days: if avgFestival > 0 then suggestedQty = avgFestival * leadDays (7)
      const suggested = top.map(t => {
        const suggestedQty = Math.ceil((t.avgFestival || 0) * 7); // keep a week's buffer
        return { sku: t.sku, liftPercent: t.liftPercent, suggestedQty, revenue: t.revenue, samples: t.samples };
      });

      // build human-friendly recommendation
      const rec = suggested.slice(0,5).map(s => `SKU:${s.sku} — suggest keep ${s.suggestedQty} units (lift ~${s.liftPercent}%)`).join('\n');

      // next festival date (compute upcoming date for this festival in current or next year)
      const now = new Date();
      let nextDate = new Date(now.getFullYear(), fest.month-1, fest.day);
      if (nextDate < now) nextDate = new Date(now.getFullYear()+1, fest.month-1, fest.day);

      festivalsOut.push({
        key: fest.key,
        name: fest.name,
        nextDate: nextDate.toISOString().split('T')[0],
        topProducts: top,
        suggestions: suggested,
        recommendationText: rec
      });
    }

    return res.json({ success:true, festivals: festivalsOut });

  } catch (err) {
    console.error('festival-strategy error:', err);
    return res.status(500).json({ success:false, message: err.message || 'Server error' });
  } finally {
    try { client.release(); } catch(e){}
  }
});


// ===============================
// MARKETING & ADS AI (Backend)
// ===============================
app.get('/api/ai/marketing-ads', authenticateJWT, async (req, res) => {
  const client = await pool.connect();
  const shopId = req.shopId;

  try {
    // timeframe
    const daysWindow = 90;
    const since = new Date(Date.now() - daysWindow * 24*60*60*1000);

    // 1) fetch invoices + items + customers (lightweight)
    const invoicesRes = await client.query(
      `SELECT id, created_at, total_amount, customer_id FROM invoices WHERE shop_id=$1 AND created_at >= $2 ORDER BY created_at DESC`,
      [shopId, since.toISOString()]
    );
    const invoiceIds = invoicesRes.rows.map(r => r.id);
    const itemsRes = invoiceIds.length ? await client.query(
      `SELECT invoice_id, item_sku, item_name, quantity, sale_price FROM invoice_items WHERE invoice_id = ANY($1::int[])`,
      [invoiceIds]
    ) : { rows: [] };
    const customersRes = await client.query(`SELECT id, name, phone FROM customers WHERE shop_id=$1`, [shopId]);

    const invoices = invoicesRes.rows || [];
    const items = itemsRes.rows || [];
    const customers = customersRes.rows || [];

    // 2) aggregate metrics
    const productMap = new Map(); // sku -> { name, qty, revenue, daysSeen }
    const dateSet = new Set();
    for (const inv of invoices) dateSet.add((new Date(inv.created_at)).toISOString().split('T')[0]);

    for (const it of items) {
      const sku = it.item_sku || it.item_name || 'UNKNOWN';
      if (!productMap.has(sku)) productMap.set(sku, { sku, name: it.item_name || sku, qty:0, revenue:0, daysSeen: new Set() });
      const p = productMap.get(sku);
      p.qty += Number(it.quantity || 0);
      p.revenue += Number(it.sale_price || 0) * Number(it.quantity || 0);
      // mark day seen
      const inv = invoices.find(iv => iv.id === it.invoice_id);
      if (inv) p.daysSeen.add((new Date(inv.created_at)).toISOString().split('T')[0]);
    }

    // convert productMap -> array and compute avg/day
    const totalDays = Math.max(1, dateSet.size);
    const products = Array.from(productMap.values()).map(p => ({
      sku: p.sku,
      name: p.name,
      qty: p.qty,
      revenue: Math.round(p.revenue),
      avgPerDay: Math.round((p.qty / totalDays) * 100)/100,
      daysSeen: p.daysSeen.size
    })).sort((a,b)=>b.qty - a.qty);

    // 3) customer RFM segmentation (Recency, Frequency, Monetary)
    // build invoices by customer
    const invByCust = {};
    invoices.forEach(inv => {
      if (!invByCust[inv.customer_id]) invByCust[inv.customer_id] = [];
      invByCust[inv.customer_id].push(inv);
    });

    const now = Date.now();
    const customersRFM = customers.map(c => {
      const invs = invByCust[c.id] || [];
      const freq = invs.length;
      const monetary = invs.reduce((s,i)=>s+Number(i.total_amount||0),0);
      const lastDate = invs.length ? new Date(invs[0].created_at) : null;
      const recency = lastDate ? Math.floor((now - lastDate.getTime())/(24*60*60*1000)) : 9999;
      return { id: c.id, name: c.name, phone: c.phone, recency, frequency: freq, monetary };
    });

    // simple scoring and segments
    const rfmScored = customersRFM.map(c => {
      let score = 0;
      // recency score
      if (c.recency <= 7) score += 40;
      else if (c.recency <= 30) score += 25;
      else if (c.recency <= 90) score += 10;
      // frequency
      if (c.frequency >= 5) score += 30;
      else if (c.frequency >= 2) score += 15;
      // monetary
      if (c.monetary >= 5000) score += 30;
      else if (c.monetary >= 1000) score += 15;
      return { ...c, score };
    }).sort((a,b)=>b.score - a.score);

    // top segments
    const topCustomers = rfmScored.slice(0,10);
    const atRisk = rfmScored.filter(c => c.recency > 30 && c.score < 30).slice(0,10);

    // 4) generate marketing ideas (heuristic templates)
    const top3Products = products.slice(0,3);
    const adIdeas = [];

    // Idea A: Local Reel / Short-Video (product push)
    if (top3Products.length) {
      adIdeas.push({
        type: 'reel',
        title: `Top seller: ${top3Products[0].name} — Quick Reel Idea`,
        script: `Video: ${top3Products[0].name} close-up → price tag → customer smiling\nCaption: "आज का स्पेशल ${top3Products[0].name} — सिर्फ आज! #LocalDeals"`,
        budgetSuggestion: Math.max(300, Math.round(top3Products[0].revenue*0.02)), // heuristic
        expectedUpliftPercent: 8 + Math.min(25, Math.round(top3Products[0].qty/10))
      });
    }

    // Idea B: WhatsApp re-engage for at-risk customers
    adIdeas.push({
      type: 'whatsapp_reengage',
      title: `Re-engage lost customers`,
      script: `नमस्ते {name}, आपका हम पर भरोसा है — आपकी याद के लिए 10% OFF on next purchase. Use code: COMEBACK10`,
      targetCount: atRisk.length,
      budgetSuggestion: Math.max(200, atRisk.length * 5), // small incentive cost per customer
      expectedUpliftPercent: 12
    });

    // Idea C: Bundle offer for slow moving / high stock items
    const slowMoving = products.filter(p => p.daysSeen <= Math.max(1, Math.floor(totalDays*0.2))).slice(0,4);
    if (slowMoving.length) {
      adIdeas.push({
        type: 'bundle',
        title: 'Combo Offer for slow-moving items',
        script: `Bundle: ${slowMoving.map(x=>x.name).slice(0,3).join(' + ')} — flat 15% off for 3 days`,
        budgetSuggestion: 300,
        expectedUpliftPercent: 10
      });
    }

    // Idea D: Weekend flash sale focusing on high-margin item
    const highRevenue = products.slice(0,6).sort((a,b)=>b.revenue - a.revenue)[0];
    if (highRevenue) {
      adIdeas.push({
        type: 'flash_sale',
        title: `Weekend Flash on ${highRevenue.name}`,
        script: `यह weekend सिर्फ ${highRevenue.name} पर एक्स्ट्रा ऑफर! limited stock. Hurry!`,
        budgetSuggestion: 400,
        expectedUpliftPercent: 15
      });
    }

    // 5) response
    return res.json({
      success: true,
      timeframeDays: daysWindow,
      metrics: { totalProducts: products.length, totalCustomers: customers.length },
      topProducts: products.slice(0,12),
      segments: { topCustomers, atRisk },
      adIdeas
    });

  } catch (err) {
    console.error('marketing-ads error:', err);
    return res.status(500).json({ success:false, message: err.message || 'Server error' });
  } finally {
    try { client.release(); } catch(e){}
  }
});




// ===============================
// STEP 13: LOSS FINDER ENGINE (AI)
// ===============================
app.get('/api/ai/loss-finder', authenticateJWT, async (req, res) => {
  const client = await pool.connect();
  const shopId = req.shopId;

  try {
    // ---- समय सीमा ----
    const now = new Date();
    const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

    // 1) पिछले 24 घंटे के invoices + items
    const invoices24Res = await client.query(
      `SELECT id, created_at, total_amount, total_cost
       FROM invoices
       WHERE shop_id = $1 AND created_at >= $2`,
      [shopId, yesterday.toISOString()]
    );
    const inv24Ids = invoices24Res.rows.map(r => r.id);

    let items24 = [];
    if (inv24Ids.length) {
      const itemsRes = await client.query(
        `SELECT ii.invoice_id, ii.item_sku, ii.item_name, ii.quantity,
                ii.sale_price, ii.purchase_price
         FROM invoice_items ii
         WHERE ii.invoice_id = ANY($1::int[])`,
        [inv24Ids]
      );
      items24 = itemsRes.rows || [];
    }

    // 2) पूरा stock (dead/excess stock के लिए)
    const stockRes = await client.query(
      `SELECT s.sku, s.name, s.quantity, s.purchase_price, s.sale_price,
              (s.quantity * s.purchase_price) AS stock_value,
              (SELECT MAX(i.created_at)
               FROM invoices i
               JOIN invoice_items ii ON i.id = ii.invoice_id
               WHERE i.shop_id = s.shop_id AND ii.item_sku = s.sku) AS last_sold_date
       FROM stock s
       WHERE s.shop_id = $1 AND s.quantity > 0`,
      [shopId]
    );
    const stockRows = stockRes.rows || [];

    // 3) Customers for outstanding (उधार)
    const custRes = await client.query(
      `SELECT id, name, balance
       FROM customers
       WHERE shop_id = $1`,
      [shopId]
    );
    const customers = custRes.rows || [];

    // -----------------------------
    // (A) Rate Mistakes (पिछले 24 घंटे)
    // -----------------------------
    const rateMistakes = [];
    let rateMistakeLoss = 0;

    for (const it of items24) {
      const sp = Number(it.sale_price || 0);
      const pp = Number(it.purchase_price || 0);
      const qty = Number(it.quantity || 0);

      if (pp > 0 && sp < pp) {
        const loss = (pp - sp) * qty;
        rateMistakeLoss += loss;

        rateMistakes.push({
          item_name: it.item_name || it.item_sku,
          sku: it.item_sku,
          qty,
          purchase_price: pp,
          sale_price: sp,
          loss: Math.round(loss)
        });
      }
    }

    // -----------------------------
    // (B) Zero / Low Profit Items (overall)
    // -----------------------------
    // -----------------------------
// (B) Zero / Low Profit Items (overall)
// -----------------------------
const lowMarginItems = [];

const lowMarginRes = await client.query(
  `SELECT ii.item_sku, ii.item_name,
          SUM(ii.quantity) AS total_qty,
          AVG(ii.purchase_price) AS avg_pp,
          AVG(ii.sale_price) AS avg_sp
    FROM invoice_items ii
    JOIN invoices i ON i.id = ii.invoice_id
    WHERE i.shop_id = $1
    GROUP BY ii.item_sku, ii.item_name
    HAVING AVG(ii.sale_price) <= AVG(ii.purchase_price) * 1.05
  `,
  [shopId]
);

for (const r of lowMarginRes.rows) {
  const avg_pp = Number(r.avg_pp || 0);
  const avg_sp = Number(r.avg_sp || 0);

  const marginPercent = avg_pp ? ((avg_sp - avg_pp) / avg_pp) * 100 : 0;

  lowMarginItems.push({
    sku: r.item_sku,
    name: r.item_name,
    total_qty: Number(r.total_qty || 0),
    avg_purchase: Math.round(avg_pp),
    avg_sale: Math.round(avg_sp),
    margin_percent: Math.round(marginPercent * 10) / 10
  });
}


    // -----------------------------
    // (C) Dead Stock (30+ दिन से नहीं बिका)
    // -----------------------------
    const deadStock = [];
    let deadLockedValue = 0;

    for (const s of stockRows) {
      const lastSold = s.last_sold_date ? new Date(s.last_sold_date) : null;
      const isDead = !lastSold || lastSold < thirtyDaysAgo;
      const stockValue = Number(s.stock_value || 0);

      if (isDead && stockValue > 0) {
        deadStock.push({
          sku: s.sku,
          name: s.name,
          qty: Number(s.quantity || 0),
          stock_value: Math.round(stockValue),
          last_sold_date: lastSold ? lastSold.toISOString().split('T')[0] : null
        });
        deadLockedValue += stockValue;
      }
    }

    // -----------------------------
    // (D) Excess Stock (बहुत ज्यादा quantity)
    // Simple heuristic: quantity > 90 days अनुमानित बिक्री
    // -----------------------------
    // Sales velocity last 60 days
    const sixtyDaysAgo = new Date(now.getTime() - 60 * 24 * 60 * 60 * 1000);
    const velRes = await client.query(
      `SELECT ii.item_sku,
              SUM(ii.quantity) AS total_qty
       FROM invoice_items ii
       JOIN invoices i ON i.id = ii.invoice_id
       WHERE i.shop_id = $1 AND i.created_at >= $2
       GROUP BY ii.item_sku`,
      [shopId, sixtyDaysAgo.toISOString()]
    );
    const velocity = new Map(); // sku -> avg per day
    const days60 = 60;
    for (const v of velRes.rows) {
      const perDay = Number(v.total_qty || 0) / days60;
      velocity.set(v.item_sku, perDay);
    }

    const excessStock = [];
    for (const s of stockRows) {
      const perDay = velocity.get(s.sku) || 0;
      if (perDay <= 0) continue;
      const maxRecommended = perDay * 90; // 90 days का buffer
      const qty = Number(s.quantity || 0);
      if (qty > maxRecommended * 1.3) { // 30% ज्यादा
        const extraQty = qty - maxRecommended;
        const extraValue = extraQty * Number(s.purchase_price || 0);
        excessStock.push({
          sku: s.sku,
          name: s.name,
          qty,
          approx_daily_sales: Math.round(perDay * 100) / 100,
          recommended_max: Math.round(maxRecommended),
          extra_qty: Math.round(extraQty),
          extra_value: Math.round(extraValue)
        });
      }
    }

    // -----------------------------
    // (E) Risky Customers (उधार वाला रिस्क)
    // -----------------------------
    const riskyCustomers = [];
    let totalOutstanding = 0;

    for (const c of customers) {
      const bal = Number(c.balance || 0);
      if (bal > 0) {
        totalOutstanding += bal;
        if (bal >= 2000) {   // threshold configurable
          riskyCustomers.push({
            id: c.id,
            name: c.name,
            mobile: c.mobile,
            balance: Math.round(bal)
          });
        }
      }
    }

    // -----------------------------
    // SUMMARY बनाएं
    // -----------------------------
    const summary = {
      rate_mistake_loss_24h: Math.round(rateMistakeLoss),
      dead_stock_locked_value: Math.round(deadLockedValue),
      risky_customers_count: riskyCustomers.length,
      risky_customers_outstanding: Math.round(totalOutstanding),
      low_margin_item_count: lowMarginItems.length,
      excess_stock_count: excessStock.length
    };

    return res.json({
      success: true,
      summary,
      rate_mistakes_24h: rateMistakes.slice(0, 50),
      dead_stock: deadStock.slice(0, 50),
      low_margin_items: lowMarginItems.slice(0, 50),
      excess_stock: excessStock.slice(0, 50),
      risky_customers: riskyCustomers.slice(0, 50)
    });

  } catch (err) {
    console.error('LOSS FINDER ERROR:', err);
    return res.status(500).json({ success: false, message: 'Loss Finder में त्रुटि: ' + err.message });
  } finally {
    try { client.release(); } catch (e) {}
  }
});



// ===============================
// STEP 14 — Personalised Customer Targeting AI
// ===============================
app.get('/api/ai/customer-targeting', authenticateJWT, async (req, res) => {
  const client = await pool.connect();
  const shopId = req.shopId;

  try {
    // 1) Basic customer list
    const cRes = await client.query(
      `SELECT id, name, COALESCE(phone, '') AS phone
       FROM customers
       WHERE shop_id = $1`,
      [shopId]
    );
    const customers = cRes.rows;

    // 2) Fetch invoices (id, customer_id, created_at, total_amount) for shop
    const invRes = await client.query(
      `SELECT id, customer_id, created_at, total_amount
       FROM invoices
       WHERE shop_id = $1
       ORDER BY customer_id, created_at ASC`,
      [shopId]
    );
    const invoices = invRes.rows;

    // 3) Fetch invoice_items (for top items per customer)
    const itemsRes = await client.query(
      `SELECT i.customer_id, ii.item_sku, ii.item_name, ii.quantity, i.created_at
       FROM invoice_items ii
       JOIN invoices i ON ii.invoice_id = i.id
       WHERE i.shop_id = $1
       ORDER BY i.customer_id, i.created_at DESC`,
      [shopId]
    );
    const items = itemsRes.rows;

    const now = new Date();
    const output = [];

    // Helper to group invoices per customer
    const invByCustomer = new Map();
    invoices.forEach(inv => {
      const arr = invByCustomer.get(inv.customer_id) || [];
      arr.push(inv);
      invByCustomer.set(inv.customer_id, arr);
    });

    // Items per customer
    const itemsByCustomer = new Map();
    items.forEach(it => {
      const arr = itemsByCustomer.get(it.customer_id) || [];
      arr.push(it);
      itemsByCustomer.set(it.customer_id, arr);
    });

    // For each customer compute metrics
    for (const c of customers) {
      const custInvs = invByCustomer.get(c.id) || [];
      const custItems = itemsByCustomer.get(c.id) || [];

      // last purchase
      const lastPurchase = custInvs.length ? new Date(custInvs[custInvs.length - 1].created_at) : null;

      // frequency & avg interval
      let avgIntervalDays = null;
      if (custInvs.length >= 2) {
        // compute diffs between consecutive purchases in days
        const diffs = [];
        for (let i = 1; i < custInvs.length; i++) {
          const prev = new Date(custInvs[i-1].created_at);
          const cur = new Date(custInvs[i].created_at);
          const d = Math.round((cur - prev) / (1000*60*60*24));
          if (d >= 0) diffs.push(d);
        }
        if (diffs.length) {
          const sum = diffs.reduce((a,b)=>a+b,0);
          avgIntervalDays = sum / diffs.length;
        }
      }

      // top items (by total quantity)
      const topMap = {};
      custItems.forEach(it => {
        const name = it.item_name || it.item_sku || 'UNKNOWN';
        topMap[name] = (topMap[name] || 0) + Number(it.quantity || 0);
      });
      const topItems = Object.keys(topMap)
        .map(name => ({ name, qty: topMap[name] }))
        .sort((a,b) => b.qty - a.qty)
        .slice(0,3);

      // predict next purchase date (simple) = lastPurchase + avgInterval
      let predictedNextDate = null;
      let willReturnSoon = false;
      if (lastPurchase && avgIntervalDays !== null) {
        const next = new Date(lastPurchase.getTime() + Math.round(avgIntervalDays) * 24*60*60*1000);
        predictedNextDate = next.toISOString().split('T')[0];
        const diffDays = Math.round((next - now)/(1000*60*60*24));
        // if predicted next within next 2 days -> high probability
        if (diffDays >= 0 && diffDays <= 2) willReturnSoon = true;
      }

      // classify status
      const daysSinceLast = lastPurchase ? Math.round((now - lastPurchase)/(1000*60*60*24)) : null;
      const status = daysSinceLast === null ? 'no_purchase' :
                     daysSinceLast > 90 ? 'lost' :
                     (daysSinceLast <= 7 ? 'recent' : 'inactive');

      // recommended offer item: topItems[0] or fallback popular item from their list
      const recommendedItem = topItems.length ? topItems[0].name : (custItems[0] ? (custItems[0].item_name||custItems[0].item_sku) : null);

      // create a suggested message (Hindi) — keep short
      const message = recommendedItem ? 
        `${c.name} जी, प्रणाम! आपने पहले ${recommendedItem} लिया था। आज हम आपको यह ऑफर दे रहे हैं: 10% छूट—अगर चाहिए तो Reply करें.` :
        `${c.name} जी, प्रणाम! हम आपकी दुकान पर नए ऑफर लेकर आए हैं—चेक करिए और बताइए।`;
		

      // final probability score (simple heuristic)
      let score = 0;
      if (willReturnSoon) score += 60;
      if (status === 'recent') score += 20;
      if (topItems.length) score += 10;
      if (avgIntervalDays !== null && avgIntervalDays <= 7) score += 10;
      if (score > 100) score = 100;

      output.push({
        id: c.id,
        name: c.name,
        phone: c.phone || '',
        last_purchase: lastPurchase ? lastPurchase.toISOString().split('T')[0] : null,
        days_since_last: daysSinceLast,
        total_purchases: custInvs.length,
        avg_interval_days: avgIntervalDays === null ? null : Math.round(avgIntervalDays*10)/10,
        predicted_next: predictedNextDate,
        will_return_soon: willReturnSoon,
        status,
        top_items: topItems,
        recommended_item: recommendedItem,
        suggested_message: message,
        probability_score: score
      });
    }

    // sort by probability_score desc
    output.sort((a,b)=>b.probability_score - a.probability_score);

    res.json({ success: true, customers: output });

  } catch (err) {
    console.error('CUSTOMER TARGETING ERROR:', err);
    res.status(500).json({ success: false, message: err.message });
  } finally {
    client.release();
  }
});



// -----------------------------
// Saloon support & Birthday APIs
// -----------------------------
app.post('/api/shop/set-business-type', authenticateJWT, async (req, res) => {
  const client = await pool.connect();
  try {
    const shopId = req.shopId;
    const { business_type } = req.body; // e.g., 'SALON' or 'RETAIL' etc.
    if(!business_type) return res.status(400).json({ success:false, message:'business_type required' });
    await client.query(`UPDATE shops SET business_type=$1 WHERE id=$2`, [business_type, shopId]);
    res.json({ success:true, message:'Business type updated', business_type });
  } catch(err){
    console.error(err);
    res.status(500).json({ success:false, message: err.message });
  } finally { client.release(); }
});


// Saloon dashboard data (appointments summary, services stock if any, birthday count)

// [ ✅ server.cjs: /api/saloon/dashboard (Date-wise & Future Booking Support) ]

app.get('/api/saloon/dashboard', authenticateJWT, async (req, res) => {
  const client = await pool.connect();
  const shopId = req.shopId;
  try {
    // 1) COMBINED LIST: Future Appointments + Today's Activity
    const mixedQuery = `
        (
            -- A. आज और आने वाली बुकिंग्स (Future Bookings)
            SELECT 
                customer_name, 
                customer_mobile, 
                scheduled_at AS event_time, 
                service_name,
                status,
                'BOOKING' as type
            FROM appointments
            WHERE shop_id = $1 AND scheduled_at >= CURRENT_DATE
            AND status != 'CANCELLED' -- (कैंसिल बुकिंग न दिखाएं)
        )
        UNION ALL
        (
            -- B. आज की बिक्री/Walk-ins (सिर्फ आज की, पुरानी नहीं)
            SELECT 
                c.name AS customer_name, 
                c.phone AS customer_mobile, 
                i.created_at AS event_time, 
                COALESCE(
                    (SELECT string_agg(item_name, ', ') FROM invoice_items WHERE invoice_id = i.id),
                    'Walk-in Sale'
                ) AS service_name,
                'COMPLETED' AS status,
                'SALE' as type
            FROM invoices i
            LEFT JOIN customers c ON i.customer_id = c.id
            WHERE i.shop_id = $1 AND i.created_at::date = CURRENT_DATE
        )
        -- 🚀 ORDER BY ASC: जो समय पहले आएगा, वो ऊपर दिखेगा
        ORDER BY event_time ASC 
        LIMIT 100
    `;
    
    const timelineRes = await client.query(mixedQuery, [shopId]);

    // 2) Today's Revenue
    const todayRes = await client.query(
      `SELECT COALESCE(SUM(total_amount),0) AS today_sales
       FROM invoices
       WHERE shop_id=$1 AND created_at::date = CURRENT_DATE`, 
      [shopId]
    );

    // 3) Upcoming Birthdays
    const bdRes = await client.query(
      `SELECT COUNT(*)::int AS upcoming_birthdays
       FROM customers
       WHERE shop_id=$1 AND dob IS NOT NULL
         AND (to_char(dob,'MM-DD') BETWEEN to_char(current_date, 'MM-DD') AND to_char(current_date + INTERVAL '7 days','MM-DD'))`,
      [shopId]
    ).catch(()=>({ rows:[{ upcoming_birthdays:0 }] }));

    // 4) Low Stock Count
    const lowStockRes = await client.query(
        `SELECT COUNT(*)::int as low_count FROM stock WHERE shop_id=$1 AND quantity < 5`, 
        [shopId]
    );

    res.json({
      success:true,
      appointments: timelineRes.rows || [], 
      today_sales: todayRes.rows[0] ? Number(todayRes.rows[0].today_sales||0) : 0,
      upcoming_birthdays: bdRes.rows[0] ? Number(bdRes.rows[0].upcoming_birthdays||0) : 0,
      low_stock_count: lowStockRes.rows[0] ? Number(lowStockRes.rows[0].low_count||0) : 0
    });

  } catch(err){ 
      console.error("Dashboard Error:", err); 
      res.status(500).json({ success:false, message: err.message }); 
  } finally { 
      client.release(); 
  }
});

// Get customers with birthdays in next N days
// [ ✅ server.cjs: /api/saloon/upcoming-birthdays को इससे बदलें ]
app.get('/api/saloon/upcoming-birthdays', authenticateJWT, async (req, res) => {
  const client = await pool.connect();
  const shopId = req.shopId;
  try {
    const q = `
      SELECT id, name, phone, dob
      FROM customers
      WHERE shop_id=$1 AND dob IS NOT NULL
      AND to_char(dob, 'MM-DD') BETWEEN to_char(CURRENT_DATE, 'MM-DD') 
                                   AND to_char(CURRENT_DATE + INTERVAL '7 days', 'MM-DD')
      ORDER BY to_char(dob, 'MM-DD') ASC
      LIMIT 10
    `;
    const result = await client.query(q, [shopId]);
    res.json({ success:true, customers: result.rows });
  } catch(err){ 
      // अगर कोई बर्थडे नहीं है तो खाली लिस्ट भेजें (एरर नहीं)
      res.json({ success:true, customers: [] }); 
  } finally { client.release(); }
});


// Ensure customer create/update endpoints accept dob (example: modify your existing /api/customers POST/PUT)
// Example handler (add to existing code)
app.post('/api/customers', authenticateJWT, async (req, res) => {
  const client = await pool.connect();
  try {
    const shopId = req.shopId;
    const { name, phone, address, dob } = req.body;
    const inserted = await client.query(
      `INSERT INTO customers (shop_id, name, phone, address, dob, created_at)
       VALUES ($1,$2,$3,$4,$5,NOW()) RETURNING *`,
      [shopId, name, phone, address, dob || null]
    );
    res.json({ success:true, customer: inserted.rows[0] });
  } catch(err){ console.error(err); res.status(500).json({ success:false, message: err.message }); } finally { client.release(); }
});




// Saloon services list (stock-like services table). If you don't have 'services' table, adapt to static list.
// [ ✅ server.cjs: /api/saloon/services को इससे बदलें ]
app.get('/api/saloon/services', authenticateJWT, async (req, res) => {
  const client = await pool.connect();
  const shopId = req.shopId;
  try {
    // सीधे STOCK टेबल से वो आइटम लाएं जो 'Service' हैं (SKU या Unit चेक करके)
    const sres = await client.query(
        `SELECT sku as code, name, sale_price as price, quantity 
         FROM stock 
         WHERE shop_id=$1 AND (sku LIKE 'SVC-%' OR unit='Session') 
         ORDER BY name`, 
        [shopId]
    );
    res.json({ success:true, services: sres.rows });
  } catch(err){
    res.status(500).json({ success:false, message: err.message });
  } finally { client.release(); }
});



// Add into server.cjs near other /api/ai routes
// [ ✅ server.cjs: /api/ai/saloon-insights को इस नए कोड से बदलें ]

app.get('/api/ai/saloon-insights', authenticateJWT, async (req, res) => {
  const client = await pool.connect();
  const shopId = req.shopId;
  try {
    const now = new Date();
    
    // 1) Recent Activity (Invoices + Appointments mix)
    // हम POS (Invoices) और Appointments दोनों को मिलाकर दिखाएंगे
    const activityQuery = `
        (
            SELECT 
                c.name AS customer_name, 
                c.phone AS customer_mobile, 
                'Walk-in / Sale' AS service_name,
                i.created_at AS scheduled_at, 
                'COMPLETED' AS status
            FROM invoices i
            LEFT JOIN customers c ON i.customer_id = c.id
            WHERE i.shop_id = $1 AND i.created_at >= $2
        )
        UNION ALL
        (
            SELECT 
                customer_name, 
                customer_mobile, 
                service_name, 
                scheduled_at, 
                status
            FROM appointments
            WHERE shop_id = $1 AND scheduled_at >= $2
        )
        ORDER BY scheduled_at DESC 
        LIMIT 20
    `;
    const apptRes = await client.query(activityQuery, [shopId, new Date(now.getTime() - 7*24*60*60*1000).toISOString()]);

    // 2) Repeat Customers (Based on Invoices count)
    // अब यह देखेगा कि किसने कितनी बार 'बिल' बनवाया है
    const repeatRes = await client.query(
      `SELECT c.id, c.name, COALESCE(c.phone, '') AS phone,
              COUNT(i.id)::int AS visits,
              MAX(i.created_at) AS last_visit
       FROM customers c
       JOIN invoices i ON i.customer_id = c.id
       WHERE c.shop_id=$1
       GROUP BY c.id, c.name, c.phone
       HAVING COUNT(i.id) >= 2
       ORDER BY visits DESC
       LIMIT 50`,
      [shopId]
    );

    // 3) No-shows (Only from appointments)
    const noShowRes = await client.query(
      `SELECT COUNT(*) FILTER (WHERE status='NO_SHOW')::int AS no_shows,
              COUNT(*) FILTER (WHERE status='CANCELLED')::int AS cancelled
       FROM appointments
       WHERE shop_id=$1 AND scheduled_at >= $2`,
      [shopId, new Date(now.getTime() - 30*24*60*60*1000).toISOString()]
    );

    // 4) Top Services (Based on Invoice Items)
    // अब यह देखेगा कि POS में कौन सा आइटम/सर्विस सबसे ज्यादा बिका
    const topSvcRes = await client.query(
      `SELECT item_name AS service_name, 
              COUNT(*)::int AS cnt, 
              SUM(sale_price * quantity)::numeric AS revenue
       FROM invoice_items ii
       JOIN invoices i ON ii.invoice_id = i.id
       WHERE i.shop_id=$1 AND i.created_at >= $2
       GROUP BY item_name
       ORDER BY cnt DESC
       LIMIT 10`,
      [shopId, new Date(now.getTime() - 60*24*60*60*1000).toISOString()]
    );

    // 5) Upcoming Birthdays
    const bdRes = await client.query(
      `SELECT id, name, COALESCE(phone, '') AS phone, dob
       FROM customers
       WHERE shop_id=$1 AND dob IS NOT NULL
         AND to_char(dob,'MM-DD') BETWEEN to_char(current_date,'MM-DD') AND to_char(current_date + INTERVAL '7 days','MM-DD')
       ORDER BY to_char(dob,'MM-DD')`,
      [shopId]
    );

    // 6) Today's Revenue
    const revRes = await client.query(
      `SELECT COALESCE(SUM(total_amount),0)::numeric AS today_revenue
       FROM invoices
       WHERE shop_id=$1 AND created_at::date = CURRENT_DATE`,
      [shopId]
    );

    res.json({
      success: true,
      appointments: apptRes.rows,      // अब इसमें POS का डेटा भी होगा
      repeat_customers: repeatRes.rows,// अब इसमें POS के रिपीट ग्राहक होंगे
      no_shows: noShowRes.rows[0] || { no_shows:0, cancelled:0 },
      top_services: topSvcRes.rows,    // अब इसमें सबसे ज्यादा बिकी सर्विस दिखेंगी
      upcoming_birthdays: bdRes.rows,
      today_revenue: Number(revRes.rows[0].today_revenue || 0)
    });

  } catch (err) {
    console.error('SALOON INSIGHTS ERROR:', err);
    res.status(500).json({ success:false, message: err.message });
  } finally {
    client.release();
  }
});


// [ ✅ server.cjs: इसे सबसे नीचे पेस्ट करें ]

// 19. Book New Appointment (Salon)
app.post('/api/appointments', authenticateJWT, async (req, res) => {
    const shopId = req.shopId;
    const { name, mobile, service, date, time } = req.body;

    if (!name || !service || !date || !time) {
        return res.status(400).json({ success: false, message: 'नाम, सर्विस, तारीख और समय आवश्यक हैं।' });
    }

    // तारीख और समय को मिलाकर Timestamp बनाएं
    const scheduledAt = new Date(`${date}T${time}`);

    const client = await pool.connect();
    try {
        // अपॉइंटमेंट सेव करें
        await client.query(
            `INSERT INTO appointments (shop_id, customer_name, customer_mobile, service_name, scheduled_at, status)
             VALUES ($1, $2, $3, $4, $5, 'SCHEDULED')`,
            [shopId, name, mobile, service, scheduledAt]
        );

        res.json({ success: true, message: 'अपॉइंटमेंट बुक हो गई!' });

    } catch (err) {
        console.error("Booking Error:", err);
        res.status(500).json({ success: false, message: 'बुकिंग विफल: ' + err.message });
    } finally {
        client.release();
    }
});


// ============================================================
// 🚀 MISSING BUSINESS APIs (Furniture, Security, Medical, etc.)
// ============================================================

// 1. 🚨 SECURITY API (Save Thief Photo)
// जब दरवाजे पर सेंसर बजेगा, तो फ्रंटएंड इस API को फोटो भेजेगा
app.post('/api/security/alert', authenticateJWT, async (req, res) => {
    const { imageBase64, rfidTag } = req.body;
    try {
        await pool.query(
            `INSERT INTO security_alerts (shop_id, camera_image, rfid_tag_detected) VALUES ($1, $2, $3)`,
            [req.shopId, imageBase64, rfidTag]
        );
        res.json({ success: true, message: 'Security Alert Logged! Photo Saved.' });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// 2. 🛋️ FURNITURE API (Delivery Update)
app.post('/api/furniture/update-delivery', authenticateJWT, async (req, res) => {
    const { invoiceId, date, status, assembly } = req.body;
    try {
        await pool.query(
            `INSERT INTO product_deliveries (shop_id, invoice_id, delivery_date, delivery_status, assembly_required)
             VALUES ($1, $2, $3, $4, $5)`,
            [req.shopId, invoiceId, date, status, assembly]
        );
        res.json({ success: true, message: 'Delivery Scheduled.' });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// 3. 🩺 MEDICAL REPORT API (Save Sonography/XRay)
app.post('/api/medical/save-report', authenticateJWT, async (req, res) => {
    const { patientId, doctorName, testName, reportContent, lmp, edd } = req.body;
    try {
        await pool.query(
            `INSERT INTO medical_reports (shop_id, patient_name, doctor_name, report_type, report_content, findings_json)
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [req.shopId, patientId, doctorName, testName, reportContent, { lmp, edd }]
        );
        res.json({ success: true, message: 'Report Saved.' });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// 4. 🎨 PAINT FORMULA API
app.post('/api/paints/save-formula', authenticateJWT, async (req, res) => {
    const { name, colorCode, formula } = req.body;
    try {
        await pool.query(
            `INSERT INTO paint_formulas (shop_id, customer_name, color_code, formula_json) VALUES ($1, $2, $3, $4)`,
            [req.shopId, name, colorCode, formula]
        );
        res.json({ success: true, message: 'Color Formula Saved.' });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// 5. 🏨 HOTEL API (Room Status)
app.get('/api/hotel/rooms', authenticateJWT, async (req, res) => {
    try {
        const result = await pool.query(`SELECT * FROM hotel_rooms WHERE shop_id = $1 ORDER BY room_number`, [req.shopId]);
        res.json({ success: true, rooms: result.rows });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// 6. 🎓 SCHOOL API (Pay Fee)
app.post('/api/school/pay-fee', authenticateJWT, async (req, res) => {
    const { studentId, amount } = req.body;
    try {
        await pool.query(`INSERT INTO school_fee_transactions (shop_id, student_id, amount_paid) VALUES ($1, $2, $3)`, [req.shopId, studentId, amount]);
        await pool.query(`UPDATE school_students SET fees_due = fees_due - $1 WHERE id = $2`, [amount, studentId]);
        res.json({ success: true, message: 'Fee Collected.' });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// 7. 🚛 TRANSPORT API (New Trip)
app.post('/api/transport/new-trip', authenticateJWT, async (req, res) => {
    const { vehicle, driver, start, end, freight } = req.body;
    try {
        await pool.query(
            `INSERT INTO transport_trips (shop_id, vehicle_no, driver_name, start_location, end_location, freight_amount)
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [req.shopId, vehicle, driver, start, end, freight]
        );
        res.json({ success: true, message: 'Trip Created.' });
    } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});



// ============================================================
// 🚀 6. NEW BUSINESS LOGIC HANDLERS (Missing Piece)
// ============================================================

// 1. 🏨 HOTEL: Check-In Logic
async function processHotelCheckIn() {
    const data = {
        room_id: document.getElementById('hotel_room_select').value || '101', // Fallback for now
        customer_name: document.getElementById('hotel_guest_name').value,
        mobile: document.getElementById('hotel_guest_mobile').value,
        check_in_date: document.getElementById('hotel_checkin_date').value,
        advance: document.getElementById('hotel_advance').value
    };

    if(!data.customer_name || !data.check_in_date) return showNotification("❌ Please fill Guest Name and Date");

    try {
        const res = await fetchApi('/api/hotel/checkin', { method: 'POST', body: data });
        if(res.success) {
            showNotification("✅ Guest Checked In Successfully!");
            // Clear fields
            document.getElementById('hotel_guest_name').value = '';
            document.getElementById('hotel_guest_mobile').value = '';
        }
    } catch(e) { alert(e.message); }
}

// 2. 🎓 SCHOOL: Fee Collection
async function processSchoolFee() {
    const data = {
        studentId: document.getElementById('school_student_id').value,
        amount: document.getElementById('school_fee_amount').value,
        month: document.getElementById('school_fee_month').value
    };
    
    if(!data.studentId || !data.amount) return showNotification("❌ Enter Student ID and Amount");

    try {
        const res = await fetchApi('/api/school/pay-fee', { method: 'POST', body: data });
        if(res.success) {
            showNotification("✅ Fee Collected Successfully!");
            document.getElementById('school_fee_amount').value = '';
        }
    } catch(e) { alert(e.message); }
}

// 3. 🚛 TRANSPORT: Create Trip
async function createTransportTrip() {
    const data = {
        vehicle: document.getElementById('trans_vehicle').value,
        driver: document.getElementById('trans_driver').value,
        start: document.getElementById('trans_start').value,
        end: document.getElementById('trans_end').value,
        freight: document.getElementById('trans_freight').value,
        advance: document.getElementById('trans_advance').value
    };

    if(!data.vehicle || !data.freight) return showNotification("❌ Vehicle No and Freight required");

    try {
        const res = await fetchApi('/api/transport/new-trip', { method: 'POST', body: data });
        if(res.success) showNotification("✅ Trip Created!");
    } catch(e) { alert(e.message); }
}

// 4. 🛠️ REPAIR: Create Job Card
async function createRepairJob() {
    const data = {
        customerName: document.getElementById('repair_customer').value,
        mobile: document.getElementById('repair_mobile').value,
        device: document.getElementById('repair_device').value,
        imei: document.getElementById('repair_imei').value,
        issue: document.getElementById('repair_issue').value,
        cost: document.getElementById('repair_cost').value,
        advance: document.getElementById('repair_advance').value
    };

    if(!data.customerName || !data.device) return showNotification("❌ Name and Device required");

    try {
        const res = await fetchApi('/api/repair/create-job', { method: 'POST', body: data });
        if(res.success) showNotification("✅ Job Card Generated! ID: " + (res.jobId || ''));
    } catch(e) { alert(e.message); }
}

// 5. 🍽️ RESTAURANT: KOT Logic
function addKotRow() {
    const div = document.createElement('div');
    div.className = 'input-group input-group-sm mb-1 kot-row';
    div.innerHTML = `<input type="text" class="form-control kot-item" placeholder="Item Name"><input type="number" class="form-control kot-qty" placeholder="Qty" style="max-width: 70px;">`;
    document.getElementById('kot-items-container').appendChild(div);
}

async function sendKotToKitchen() {
    const tableId = document.getElementById('rest_table_no').value;
    const items = [];
    document.querySelectorAll('.kot-row').forEach(row => {
        const item = row.querySelector('.kot-item').value;
        const qty = row.querySelector('.kot-qty').value;
        if(item && qty) items.push({ item, qty });
    });

    if(!tableId || items.length === 0) return showNotification("❌ Table No and Items required");
    
    // Note: Assuming API expects 'tableId' as integer (mapping needed in real app)
    // Here sending as 1 for demo if text provided
    try {
        const res = await fetchApi('/api/restaurant/create-kot', { method: 'POST', body: { tableId: 1, items } }); 
        if(res.success) {
            showNotification("✅ KOT Sent to Kitchen! 🍳");
            document.getElementById('kot-items-container').innerHTML = ''; // Clear
            addKotRow(); // Add one empty row
        }
    } catch(e) { alert(e.message); }
}

// 6. 🎨 PAINT: Save Formula
async function savePaintFormula() {
    const data = {
        name: document.getElementById('paint_cust_name').value,
        colorCode: document.getElementById('paint_code').value,
        baseProduct: document.getElementById('paint_base').value,
        formula: JSON.parse(document.getElementById('paint_formula').value || '{}')
    };

    try {
        const res = await fetchApi('/api/paints/save-formula', { method: 'POST', body: data });
        if(res.success) showNotification("✅ Formula Saved!");
    } catch(e) { alert("Invalid JSON or Error: " + e.message); }
}

// 7. 🧵 TAILOR: Save Measurements
async function saveTailorMeasurements() {
    const data = {
        customerId: document.getElementById('tailor_cust_id').value || 1, // Fallback ID
        itemType: document.getElementById('tailor_item_type').value,
        deliveryDate: document.getElementById('tailor_delivery').value,
        notes: document.getElementById('tm_notes').value,
        measurements: {
            len: document.getElementById('tm_length').value,
            waist: document.getElementById('tm_waist').value,
            chest: document.getElementById('tm_chest').value,
            shldr: document.getElementById('tm_shoulder').value
        }
    };

    try {
        const res = await fetchApi('/api/tailor/save-measurements', { method: 'POST', body: data });
        if(res.success) showNotification("✅ Measurements Saved!");
    } catch(e) { alert(e.message); }
}

// 8. 💪 GYM: Attendance
async function markGymAttendance() {
    const id = document.getElementById('gym_member_id').value;
    if(!id) return showNotification("❌ Member ID required");

    try {
        // Assuming we look up customer by this ID/Phone logic
        // For demo, sending ID 1. Real app needs lookup.
        const res = await fetchApi('/api/gym/attendance', { method: 'POST', body: { customerId: 1 } });
        if(res.success) showNotification("✅ Attendance Marked!");
    } catch(e) { alert(e.message); }
}

// 9. 🛋️ FURNITURE: Delivery
async function scheduleFurnitureDelivery() {
    const data = {
        invoiceId: document.getElementById('furn_invoice_id').value || 0,
        date: document.getElementById('furn_delivery_date').value,
        assembly: document.getElementById('furn_assembly').checked
    };
    
    if(!data.date) return showNotification("❌ Select Date");

    try {
        const res = await fetchApi('/api/furniture/update-delivery', { method: 'POST', body: data });
        if(res.success) showNotification("✅ Delivery Scheduled!");
    } catch(e) { alert(e.message); }
}



// [PASTE THIS IN server.cjs (AT THE BOTTOM, BEFORE app.listen)]

// [REPLACE THIS IN server.cjs (ADMIN SECTION)]

// 12.6 Upgrade Shop Plan (Super Admin Only)
// यह API दुकान का प्लान तुरंत बदल देती है (Basic -> Premium)
app.post('/api/admin/upgrade-shop-plan', async (req, res) => {
    const { adminPassword, shop_id, new_plan, extend_days } = req.body;

    // 1. सिक्योरिटी चेक
    if (!process.env.GLOBAL_ADMIN_PASSWORD) {
        return res.status(500).json({ success: false, message: 'Server Config Error: GLOBAL_ADMIN_PASSWORD missing.' });
    }
    if (adminPassword !== process.env.GLOBAL_ADMIN_PASSWORD) {
        return res.status(401).json({ success: false, message: 'गलत एडमिन पासवर्ड।' });
    }

    if (!shop_id || !new_plan) {
        return res.status(400).json({ success: false, message: 'Shop ID और New Plan नाम आवश्यक है।' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 2. प्लान अपडेट करें
        let updateQuery = `UPDATE shops SET plan_type = $1 WHERE id = $2`;
        let queryParams = [new_plan.toUpperCase(), shop_id];

        // 3. (Optional) अगर आप वैलिडिटी भी बढ़ाना चाहते हैं
        // (पुराना लॉजिक सुरक्षित है)
        if (extend_days && parseInt(extend_days) > 0) {
            updateQuery = `
                UPDATE shops 
                SET plan_type = $1, 
                    license_expiry_date = license_expiry_date + INTERVAL '${parseInt(extend_days)} days' 
                WHERE id = $2`;
        }

        const result = await client.query(updateQuery, queryParams);

        if (result.rowCount === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ success: false, message: 'Shop ID नहीं मिली।' });
        }

        // 4. Shop के एडमिन का ईमेल ढूँढें (Confirmation के लिए)
        const userRes = await client.query('SELECT email FROM users WHERE shop_id = $1 AND role = $2', [shop_id, 'ADMIN']);
        const shopAdminEmail = userRes.rows[0]?.email || 'Unknown';

        await client.query('COMMIT');

        // ---------------------------------------------------------
        // 🚀 NEW UPDATION: Real-time Notification भेजें
        // ---------------------------------------------------------
        // इससे दुकानदार की स्क्रीन पर तुरंत असर दिखेगा
        if (typeof broadcastToShop === 'function') {
            broadcastToShop(shop_id, JSON.stringify({ 
                type: 'PLAN_UPDATED', 
                message: `बधाई हो! आपका प्लान '${new_plan.toUpperCase()}' में अपग्रेड कर दिया गया है।`,
                newPlan: new_plan.toUpperCase()
            }));
        }

        console.log(`PLAN UPGRADE: Shop ${shop_id} upgraded to ${new_plan} by Super Admin.`);

        res.json({ 
            success: true, 
            message: `सफलता! Shop ID ${shop_id} (Email: ${shopAdminEmail}) का प्लान अब '${new_plan}' कर दिया गया है।`,
            new_plan: new_plan
        });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error("Upgrade Error:", err);
        res.status(500).json({ success: false, message: 'प्लान बदलने में विफल: ' + err.message });
    } finally {
        client.release();
    }
});

// [PASTE THIS IN server.cjs (ADMIN SECTION)]
// 12.7 Find Shop Details (Smart Search & Fixes)
app.post('/api/admin/find-shop', async (req, res) => {
    const { adminPassword, query } = req.body;

    // 1. पासवर्ड चेक
    if (!process.env.GLOBAL_ADMIN_PASSWORD) {
         return res.status(500).json({ success: false, message: 'Server Error: Password Config Missing' });
    }
    if (adminPassword !== process.env.GLOBAL_ADMIN_PASSWORD) {
        return res.status(401).json({ success: false, message: 'गलत एडमिन पासवर्ड!' });
    }

    try {
        // 2. Query का लॉजिक (Expiry Date और Status को सही से निकालें)
        let sql = `
            SELECT s.id, s.shop_name, s.business_type, s.plan_type, 
                   s.status,  -- यह कॉलम DB में होना जरूरी है
                   s.license_expiry_date as expiry_date, 
                   u.name as owner_name, u.mobile as owner_mobile, u.email
            FROM shops s
            LEFT JOIN users u ON s.id = u.shop_id AND u.role = 'ADMIN'
        `;
        
        let params = [];
        
        if (query) {
            // स्मार्ट सर्च: ID या नाम में कहीं भी मैच हो
            sql += ` WHERE s.id::text ILIKE $1 OR s.shop_name ILIKE $1 OR u.name ILIKE $1 OR u.mobile ILIKE $1 OR u.email ILIKE $1`;
            params.push(`%${query}%`); // वाइल्डकार्ड (%) दोनों तरफ लगाएं
        }
        
        sql += ` ORDER BY s.id DESC LIMIT 50`;

        const result = await pool.query(sql, params);
        
        // सफलता!
        res.json({ success: true, shops: result.rows });

    } catch (err) {
        console.error("Find Shop Error:", err);
        // असली एरर फ्रंटएंड को भेजें ताकि पता चले क्या गलत है
        res.status(500).json({ success: false, message: "DB Error: " + err.message });
    }
});

// --- ADMIN: BLOCK/UNBLOCK SHOP (CORRECTED) ---
app.post('/api/admin/update-shop-status', async (req, res) => {
    const { adminPassword, shop_id, status } = req.body;

    // 1. सही पासवर्ड चेक (Fix: हार्डकोड पासवर्ड हटाया)
    if (!process.env.GLOBAL_ADMIN_PASSWORD) {
         return res.status(500).json({ success: false, message: 'Server Config Error: GLOBAL_ADMIN_PASSWORD missing.' });
    }
    
    // यह लाइन चेक करती है कि भेजा गया पासवर्ड असली एडमिन पासवर्ड है या नहीं
    if (adminPassword !== process.env.GLOBAL_ADMIN_PASSWORD) { 
        return res.status(401).json({ success: false, message: "Wrong Admin Password" });
    }

    try {
        const result = await pool.query(
            'UPDATE shops SET status = $1 WHERE id = $2 RETURNING *',
            [status, shop_id]
        );
        
        if (result.rowCount === 0) return res.json({ success: false, message: "Shop ID Invalid" });
        
        res.json({ success: true, message: "Status Updated Successfully" });
    } catch (err) {
        console.error("Status Update Error:", err);
        res.status(500).json({ success: false, message: err.message });
    }
});

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