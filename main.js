// ============================================================
// 🚀 DUKAN PRO ULTIMATE: MASTER BUSINESS CONFIGURATION
// ============================================================
// यह सेटिंग्स तय करती हैं कि सॉफ्टवेयर किस बिज़नेस के लिए कैसा दिखेगा

const MASTER_BUSINESS_CONFIG = {

    // --- GROUP 1: RETAIL (दुकानें) ---
    RETAIL: {
        name: "General Store / Kirana",
        theme: "#198754", // Green
        labels: { customer: "Customer", stock: "Items" },
        features: ['barcode', 'expiry_date', 'loose_weight'], 
        dashboard_view: 'retail_grid'
    },
    MOBILE_SHOP: {
        name: "Mobile & Accessories",
        theme: "#0d6efd", // Blue
        labels: { customer: "Customer", stock: "Units" },
        features: ['imei_scan', 'repair_jobcard', 'exchange_offer', 'warranty_date'],
        dashboard_view: 'retail_grid'
    },
    CLOTHING: {
        name: "Garments / Boutique",
        theme: "#d63384", // Pink
        labels: { customer: "Client", stock: "Pcs" },
        features: ['size_color_matrix', 'barcode', 'tailoring_measurements'],
        dashboard_view: 'fashion_grid'
    },
    FURNITURE: { 
        name: "Furniture Showroom",
        theme: "#795548", // Brown
        labels: { customer: "Client", stock: "Units" },
        features: ['delivery_tracking', 'assembly_date', 'dimensions', 'warranty_card'],
        dashboard_view: 'showroom_grid'
    },
    JEWELLERY: {
        name: "Jewellery / Imitation",
        theme: "#ffc107", // Gold
        labels: { customer: "Client", stock: "Pcs" },
        features: ['small_barcode', 'weight_mg', 'purity_check', 'making_charges'],
        dashboard_view: 'retail_grid'
    },
    HARDWARE_PAINT: {
        name: "Hardware & Paint",
        theme: "#fd7e14", // Orange/Yellow
        labels: { customer: "Painter/Client", stock: "Liters/Kg" },
        features: ['paint_mixing', 'painter_commission', 'sqft_calc'],
        dashboard_view: 'retail_grid'
    },
    SWEET_SHOP: {
        name: "Sweet Shop / Bakery",
        theme: "#fd7e14", // Orange
        labels: { customer: "Customer", stock: "Kg" },
        features: ['expiry_date', 'manufacturing_date', 'bulk_order'],
        dashboard_view: 'quick_pos'
    },
    ELECTRONICS: {
        name: "Electronics Showroom",
        theme: "#212529", // Dark
        labels: { customer: "Client", stock: "Units" },
        features: ['imei_scan', 'warranty_date', 'delivery_tracking'],
        dashboard_view: 'showroom_grid'
    },

    // --- GROUP 2: MEDICAL & HEALTH (डॉक्टर्स और दवाइयां) ---
    PHARMACY: {
        name: "Medical Store / Pharmacy",
        theme: "#20c997", // Teal
        labels: { customer: "Patient", stock: "Strips/Bottles" },
        features: ['expiry_date', 'batch_number', 'doctor_name', 'salt_composition'],
        dashboard_view: 'pharma_grid'
    },
    DOCTOR_CLINIC: { 
        name: "General Physician (MBBS)",
        theme: "#0dcaf0", // Cyan
        labels: { customer: "Patient", stock: "Services" },
        features: ['appointment', 'prescription_pad', 'patient_history', 'vitals_check'],
        dashboard_view: 'clinic_dashboard'
    },
    ORTHOPEDIC: { 
        name: "Orthopedic Clinic (Haddi)",
        theme: "#dc3545", // Red
        labels: { customer: "Patient", stock: "Implants" },
        features: ['appointment', 'prescription_pad', 'xray_templates'], // X-Ray templates active
        dashboard_view: 'clinic_dashboard'
    },
    DENTIST: { 
        name: "Dental Clinic",
        theme: "#0d6efd", // Blue
        labels: { customer: "Patient", stock: "Implants" },
        features: ['appointment', 'tooth_chart', 'sitting_history', 'lab_work'],
        dashboard_view: 'clinic_dashboard'
    },
    SONOGRAPHY: { 
        name: "Sonography / X-Ray Centre",
        theme: "#6610f2", // Indigo
        labels: { customer: "Patient", stock: "Films" },
        features: ['appointment', 'report_templates', 'pcpndt_form', 'referral_doctor'],
        dashboard_view: 'lab_dashboard'
    },
    PHYSIOTHERAPY: {
        name: "Physiotherapy Centre",
        theme: "#198754", // Green
        labels: { customer: "Patient", stock: "Sessions" },
        features: ['appointment', 'session_tracker', 'exercise_chart', 'package_expiry'],
        dashboard_view: 'clinic_dashboard'
    },
    PATHOLOGY: {
        name: "Pathology Lab",
        theme: "#dc3545", // Red
        labels: { customer: "Patient", stock: "Kits" },
        features: ['report_templates', 'referral_doctor', 'sample_collection'],
        dashboard_view: 'lab_dashboard'
    },

    // --- GROUP 3: SERVICES (सेवाएं) ---
    SALON: {
        name: "Salon / Spa",
        theme: "#6f42c1", // Purple
        labels: { customer: "Client", stock: "Products" },
        features: ['appointment', 'staff_commission', 'product_consumption', 'packages'],
        dashboard_view: 'salon_dashboard'
    },
    SERVICE_CENTER: {
        name: "Repairing Center (Electronics)",
        theme: "#6c757d", // Slate
        labels: { customer: "Customer", stock: "Parts" },
        features: ['job_card', 'repair_status', 'spare_parts_stock', 'warranty'],
        dashboard_view: 'service_grid'
    },
    TAILOR: {
        name: "Tailor / Boutique",
        theme: "#d63384", // Pink
        labels: { customer: "Client", stock: "Fabric" },
        features: ['tailoring_measurements', 'delivery_tracking'],
        dashboard_view: 'fashion_grid'
    },
    GYM: {
        name: "Gym / Fitness Center",
        theme: "#000000", // Black
        labels: { customer: "Member", stock: "Supplements" },
        features: ['package_expiry', 'attendance'],
        dashboard_view: 'gym_dashboard'
    },
    
    // --- GROUP 4: OTHERS (अन्य) ---
    HOTEL: {
        name: "Hotel / Lodging",
        theme: "#dc3545", // Red
        labels: { customer: "Guest", stock: "Rooms" },
        features: ['room_checkin', 'night_audit', 'id_proof_upload', 'food_service'],
        dashboard_view: 'hotel_desk'
    },
    RESTAURANT: {
        name: "Restaurant / Cafe",
        theme: "#fd7e14", // Orange
        labels: { customer: "Table", stock: "Ingredients" },
        features: ['table_kot', 'recipe_management', 'food_expiry'],
        dashboard_view: 'restaurant_pos'
    },
    SCHOOL: {
        name: "School / Coaching",
        theme: "#0d6efd", // Blue
        labels: { customer: "Student", stock: "Books" },
        features: ['fees_management', 'attendance', 'id_card', 'batch_sms'],
        dashboard_view: 'school_admin'
    },
    TRANSPORT: {
        name: "Transport / Logistics",
        theme: "#6c757d", // Slate
        labels: { customer: "Party", stock: "Vehicles" },
        features: ['trip_management', 'diesel_tracking'],
        dashboard_view: 'transport_grid'
    }
	
	// --- GROUP 9: FINANCE & BANKING AGENTS ---
    
    // 1. लोन एजेंट / DSA (जो लोन बेचते हैं)
    LOAN_DSA: {
        name: "Loan / Credit Card DSA",
        theme: "#2c3e50", // Dark Blue
        labels: { customer: "Lead / Applicant", stock: "Products (Loans)" },
        features: [
            'lead_management',      // Lead Follow-up (Call Reminder)
            'document_upload',      // Aadhar/Pan Photo
            'commission_calc',      // Payout Calculation
            'bank_status_tracker'   // File Login -> Sanction -> Disbursed
        ],
        dashboard_view: 'crm_focused' // यहाँ स्टॉक नहीं, CRM मुख्य है
    },

    // 2. रिकवरी एजेंट / पिग्मी कलेक्शन (जो पैसा लाते हैं)
    RECOVERY_AGENT: {
        name: "Recovery / Daily Collection",
        theme: "#c0392b", // Dark Red
        labels: { customer: "Borrower", stock: "EMI Due" },
        features: [
            'daily_collection_route', // किस रास्ते पर जाना है
            'geo_tagging',            // लोकेशन सेव करना (Saboot)
            'sms_receipt',            // तुरंत SMS रसीद
            'promise_to_pay_date'     // अगर आज नहीं दिया तो कब देगा?
        ],
        dashboard_view: 'quick_pos' // फास्ट एंट्री के लिए
    }
};

// ============================================================
// 🧠 GLOBAL VARIABLES
// ============================================================
let CURRENT_USER_TYPE = ''; 
let APP_USER = null;       

// ============================================================
// 🚀 1. INITIALIZATION LOGIC (ब्रेन)
// ============================================================

function initializeSoftware(user) {
    console.log("🚀 Initializing Dukan Pro Ultimate for:", user.business_type);
    
    APP_USER = user;
    CURRENT_USER_TYPE = user.business_type;
    const config = MASTER_BUSINESS_CONFIG[CURRENT_USER_TYPE];

    if (!config) {
        alert("CRITICAL ERROR: Unknown Business Type! Contact Admin.");
        return;
    }

    // 1. थीम और कलर सेट करें
    document.documentElement.style.setProperty('--primary-theme', config.theme);
    
    // 2. हैडर टाइटल अपडेट करें
    const headerTitle = document.getElementById('header-title');
    if(headerTitle) headerTitle.innerText = `Dukan Pro: ${config.name}`;

    // 3. लेबल्स अपडेट करें (Customer vs Patient)
    updateLabels(config.labels);

    // 4. UI Modules को Show/Hide करें (सबसे जरूरी)
    configureDashboardModules(config.features, config.dashboard_view);

    // 5. Expiry और Birthday चेक करें
    checkUniversalAlerts();
}

// ------------------------------------------------------------
// 🎨 UI Switcher Function (Final Updated Version)
// ------------------------------------------------------------
function configureDashboardModules(features, viewMode) {
    // A. पहले सब कुछ छुपा दें (Reset - Old Logic)
    document.querySelectorAll('.biz-module').forEach(el => el.style.display = 'none');
    document.querySelectorAll('.input-group-special').forEach(el => el.style.display = 'none');

    // Labels को भी Reset करें (Default Retail Values)
    const qtyLabel = document.querySelector('label[for="stock-quantity"]');
    if(qtyLabel) qtyLabel.innerText = "मात्रा (Qty)";
    
    const sPriceLabel = document.querySelector('label[for="stock-sale-price"]');
    if(sPriceLabel) sPriceLabel.innerText = "बिक्री मूल्य (₹)";

    const searchInput = document.getElementById('pos-item-search');
    if(searchInput) searchInput.placeholder = "आइटम का नाम या SKU टाइप करें...";

    // B. फीचर्स के हिसाब से सेक्शन्स दिखाएं
    features.forEach(feature => {
        
        // --- [OLD CODE: EXISTING FEATURES (Medical, Salon, Furniture etc.)] ---

        // 1. Expiry Date (Pharmacy, Sweet Shop)
        if (feature === 'expiry_date') {
            document.querySelectorAll('.module-expiry').forEach(el => el.style.display = 'block');
        }

        // 2. IMEI / Serial No (Mobile)
        if (feature === 'imei_scan') {
            const imeiMod = document.getElementById('module-imei-scan');
            if(imeiMod) imeiMod.style.display = 'block';
        }

        // 3. Medical Module (Doctors, Sonography, Dentist)
        if (feature === 'appointment' || feature === 'prescription_pad' || feature === 'report_templates') {
            const medModule = document.getElementById('module-prescription-pad');
            if(medModule) {
                medModule.style.display = 'block';
                // Doctor के टाइप के हिसाब से बटन लोड करें
                if(typeof setupDoctorDashboard === 'function') {
                    setupDoctorDashboard(CURRENT_USER_TYPE);
                }
            }
        }

        // 4. Furniture / Electronics Delivery
        if (feature === 'delivery_tracking') {
            const furnMod = document.getElementById('module-furniture-showroom');
            if(furnMod) furnMod.style.display = 'block';
        }

        // 5. Dentist Chart (Teeth)
        if (feature === 'tooth_chart') {
            const toothMod = document.getElementById('module-tooth-chart');
            if(toothMod) toothMod.style.display = 'block';
        }

        // 6. Paint Mixing
        if (feature === 'paint_mixing') {
            const paintMod = document.getElementById('module-paint-mixer');
            if(paintMod) paintMod.style.display = 'block';
        }

        // 7. Hotel Front Desk
        if (feature === 'room_checkin') {
            const hotelMod = document.getElementById('module-hotel-management');
            if(hotelMod) hotelMod.style.display = 'block';
        }

        // 8. Tailoring Measurements
        if (feature === 'tailoring_measurements') {
            const tailorMod = document.getElementById('module-tailor-measurements');
            if(tailorMod) tailorMod.style.display = 'block';
        }

        // --- [🚀 NEW UPDATES: TILES, TENT & FINANCE] ---

        // 9. TILES & CERAMIC (Sq.Ft Calculation)
        if (feature === 'sqft_calc') {
            const tilesMod = document.getElementById('module-tiles-calc');
            if(tilesMod) {
                tilesMod.style.display = 'block';
                if(qtyLabel) qtyLabel.innerText = "Quantity (Boxes)";
            }
        }

        // 10. TENT HOUSE / RENTAL (किराये का सामान)
        if (feature === 'rental_dates') {
            const rentalMod = document.getElementById('module-rental-stock');
            if(rentalMod) {
                rentalMod.style.display = 'block';
                if(sPriceLabel) sPriceLabel.innerText = "Replacement Cost (अगर खो जाए)";
            }
        }

        // 11. FINANCE / RECOVERY (Loan & GPS)
        // (यहाँ GPS और Loan Number दोनों का लॉजिक एक साथ सही कर दिया गया है)
        if (feature === 'geo_tagging' || feature === 'commission_calc') {
            // A. GPS Location Box दिखाएं
            const geoMod = document.getElementById('module-geo-tagging');
            if(geoMod) geoMod.style.display = 'block';

            // B. Loan/Account Number Box दिखाएं
            const finMod = document.getElementById('module-finance-collection');
            if(finMod) finMod.style.display = 'block';

            // C. Search Placeholder बदलें (ताकि एजेंट को आसानी हो)
            if(searchInput) searchInput.placeholder = "EMI, RD, FD या Loan Product खोजें...";
        }
    });

    console.log(`✅ Dashboard Configured for: ${CURRENT_USER_TYPE}`);
}


function updateLabels(labels) {
    document.querySelectorAll('.lbl-customer').forEach(el => el.innerText = labels.customer);
    document.querySelectorAll('.lbl-stock').forEach(el => el.innerText = labels.stock);
}

// ============================================================
// 🩺 2. MEDICAL / DOCTOR / SONOGRAPHY LOGIC (Unified)
// ============================================================

// A. Templates Library (सारे डॉक्टर्स के टेम्पलेट)
const MEDICAL_TEMPLATES = {
    'SONOGRAPHY': {
        buttons: [
            { label: 'Whole Abdomen', code: 'USG_ABD' },
            { label: 'Obstetric (Pregnancy)', code: 'USG_OBS' }, // LMP Calc Button yahan dikhega
            { label: 'KUB / Prostate', code: 'USG_KUB' },
            { label: 'Neck / Thyroid', code: 'USG_NECK' }
        ],
        texts: {
            'USG_ABD': "REPORT: ULTRASOUND WHOLE ABDOMEN\n\nLIVER: Normal size & echotexture. No focal lesion.\nGALL BLADDER: Well distended. Wall normal. No calculus.\nPANCREAS: Normal.\nKIDNEYS: Normal size & shape. No hydronephrosis.\n\nIMPRESSION: NORMAL STUDY.",
            'USG_OBS': "REPORT: OBSTETRIC ULTRASOUND\n\nSingle live intrauterine fetus seen.\nCardiac activity present.\nPlacenta: Upper segment.\nLiquor: Adequate.\n\nEFW: ___ grams\nGA: __ Weeks\n\nIMPRESSION: Single live fetus corresponding to GA.",
            'USG_KUB': "REPORT: KUB ULTRASOUND\n\nRight Kidney: Normal.\nLeft Kidney: Normal.\nBladder: Distended, Wall Normal.\n\nIMPRESSION: Normal KUB Study.",
            'USG_NECK': "REPORT: NECK/THYROID\n\nThyroid lobes normal in size and echotexture.\nNo lymphadenopathy."
        }
    },
    'ORTHOPEDIC': {
        buttons: [
            { label: 'X-Ray Knee', code: 'XR_KNEE' },
            { label: 'Fracture Report', code: 'XR_FRAC' },
            { label: 'Spine (LS)', code: 'XR_SPINE' },
            { label: 'Blood Test Ref', code: 'LAB_REF' }
        ],
        texts: {
            'XR_KNEE': "X-RAY REPORT: KNEE JOINT (AP/LAT)\n\nBones: Normal alignment.\nJoint Space: Reduced medially (Osteoarthritis Grade 1).\nSoft Tissues: Normal.\n\nIMPRESSION: Early Osteoarthritic changes.",
            'XR_FRAC': "REPORT: RADIOGRAPH\n\nFindings: Fracture line seen involving the distal end of Radius.\nDisplacement: Minimal.\n\nIMPRESSION: Distal Radius Fracture.",
            'XR_SPINE': "REPORT: LUMBOSACRAL SPINE\n\nVertebral alignment normal.\nDisc spaces maintained.\nNo bony injury seen.",
            'LAB_REF': "Rx:\n\n1. CBC\n2. Uric Acid\n3. Calcium / Vit D3\n\nReview with reports."
        }
    },
    'DOCTOR_CLINIC': { // General Physician
        buttons: [
            { label: 'General OPD', code: 'GEN_OPD' },
            { label: 'Fever/Flu', code: 'FEVER' },
            { label: 'Lab Requisition', code: 'LAB_REQ' }
        ],
        texts: {
            'GEN_OPD': "CLINICAL NOTES:\n\nC/O: \n\nO/E: BP: __/__ mmHg, Pulse: __/min\n\nRx:\n1. Tab. Paracetamol 650mg SOS\n2. \n3. ",
            'FEVER': "DIAGNOSIS: Viral Fever\n\nRx:\n1. Tab. PCM 650mg TDS x 3 days\n2. Plenty of fluids\n3. Bed Rest",
            'LAB_REQ': "INVESTIGATION REQUIRED:\n\n1. CBC\n2. Widal\n3. Urine R/M"
        }
    },
    'DENTIST': {
        buttons: [
            { label: 'Root Canal', code: 'RCT' },
            { label: 'Extraction', code: 'EXT' },
            { label: 'Scaling', code: 'SCALE' }
        ],
        texts: {
            'RCT': "PROCEDURE: ROOT CANAL TREATMENT\n\nTooth No: __\nAccess opening done. Canal located and biomechanical preparation done.\nObturation completed.",
            'EXT': "PROCEDURE: EXTRACTION\n\nTooth No: __\nExtraction done under LA. Hemostasis achieved.",
            'SCALE': "PROCEDURE: SCALING & POLISHING\n\nFull mouth ultrasonic scaling done.\nPolishing completed."
        }
    },
    'PHYSIOTHERAPY': {
        buttons: [
            { label: 'Back Pain', code: 'BP' },
            { label: 'Knee Rehab', code: 'KNEE' }
        ],
        texts: {
            'BP': "ASSESSMENT: Low Back Pain.\nPLAN: IFT + Hot Pack + Core Strengthening Exercises.\nSessions Recommended: 7 Days.",
            'KNEE': "ASSESSMENT: Knee OA.\nPLAN: Ultrasound Therapy + Quads Drills."
        }
    }
};

// B. Doctor Dashboard Setup Logic
function setupDoctorDashboard(bizType) {
    const btnContainer = document.getElementById('medical-template-buttons');
    if(!btnContainer) return;
    
    btnContainer.innerHTML = ''; // Clear old buttons
    
    // 1. Title Update
    const titleEl = document.getElementById('medical-title-text');
    if(titleEl) titleEl.innerText = MASTER_BUSINESS_CONFIG[bizType].name + " Report";

    // 2. Select Category (अगर लिस्ट में नहीं है तो General Physician मानो)
    let category = 'DOCTOR_CLINIC'; 
    if (MEDICAL_TEMPLATES[bizType]) category = bizType;

    // 3. बटन बनाओ
    const data = MEDICAL_TEMPLATES[category];
    if (data) {
        data.buttons.forEach(btn => {
            const b = document.createElement('button');
            b.className = 'btn btn-sm btn-outline-primary';
            b.innerText = btn.label;
            b.onclick = () => injectMedicalTemplate(category, btn.code);
            btnContainer.appendChild(b);
        });
    }

    // 4. Special Logic: Sonography (LMP Box) & Dentist (Chart)
    const lmpBox = document.getElementById('box-lmp-calc');
    const teethBox = document.getElementById('box-dentist-chart');

    if(lmpBox) lmpBox.style.display = (bizType === 'SONOGRAPHY') ? 'block' : 'none';
    if(teethBox) teethBox.style.display = (bizType === 'DENTIST') ? 'block' : 'none';
}

// C. Load Template Text
function injectMedicalTemplate(type, code) {
    const text = MEDICAL_TEMPLATES[type].texts[code];
    if (text) {
        document.getElementById('medical_report_editor').value = text;
    }
}

// D. Sonography: LMP to EDD Calculation
function calculateEDD() {
    const lmpVal = document.getElementById('med_lmp_date').value;
    if (!lmpVal) return alert("Please select LMP date");

    const lmp = new Date(lmpVal);
    const edd = new Date(lmp);
    edd.setDate(lmp.getDate() + 280); // +40 weeks (280 days)

    const today = new Date();
    const diffTime = Math.abs(today - lmp);
    const totalDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    const weeks = Math.floor(totalDays / 7);
    const days = totalDays % 7;

    // Show Badge
    const badgeDiv = document.getElementById('pregnancy-badge');
    if(badgeDiv) badgeDiv.style.display = 'block';
    
    document.getElementById('disp_edd').innerText = edd.toLocaleDateString('en-IN');
    document.getElementById('disp_ga').innerText = `${weeks}w ${days}d`;

    // Append to Report Text
    const editor = document.getElementById('medical_report_editor');
    if(editor) {
        editor.value = `LMP: ${lmp.toLocaleDateString('en-IN')}\nEDD: ${edd.toLocaleDateString('en-IN')}\nGA: ${weeks} Weeks ${days} Days\n\n` + editor.value;
    }
}

// E. Dentist: Toggle Teeth Selection
function toggleToothSelection(toothId) {
    const btn = document.getElementById(`tooth-${toothId}`);
    if(!btn) return;
    
    if (btn.classList.contains('btn-outline-secondary')) {
        btn.classList.remove('btn-outline-secondary');
        btn.classList.add('btn-danger'); // Selected
        console.log(`Tooth ${toothId} Selected`);
    } else {
        btn.classList.remove('btn-danger');
        btn.classList.add('btn-outline-secondary'); // Deselected
    }
}

// F. Save Report API Call
async function saveMedicalReport() {
    // 1. Data Collect
    const data = {
        patientId: document.getElementById('medical_patient_id')?.value || null,
        doctorName: document.getElementById('med_ref_doc')?.value || 'Self',
        testName: document.getElementById('report_title')?.value || 'General Report',
        reportContent: document.getElementById('medical_report_editor')?.value,
        lmp: document.getElementById('med_lmp_date')?.value || null,
        edd: document.getElementById('disp_edd')?.innerText || null
    };

    if(!data.reportContent) {
        return alert("Please write a report or select a template.");
    }

    // 2. Send to Server (Mock Function)
    try {
        const res = await fetchApi('/api/medical/save-report', { method: 'POST', body: data });
        if(res.success) {
            showNotification('✅ Report Saved Successfully!');
            // Optional: window.print();
        }
    } catch(e) {
        console.error(e);
        showNotification('❌ Failed to save report.');
    }
}

// ============================================================
// 📅 3. UNIVERSAL ALERTS (Birthday & Expiry)
// ============================================================

function checkUniversalAlerts() {
    console.log("🔔 Checking Alerts...");
    
    const config = MASTER_BUSINESS_CONFIG[CURRENT_USER_TYPE];
    
    // Check Expiry (Pharmacy/Sweet Shop/Retail)
    if (config.features.includes('expiry_date')) {
        console.log("Checking Product Expiry for: " + config.name);
        // (Real app would fetch from API here and show alert)
    }
}

// ============================================================
// 📝 4. FORM DATA HANDLERS (Used by Index.html Forms)
// ============================================================

// A. Add Customer Form Handler
function getCustomerFormData() {
    const dobValue = document.getElementById('cust_dob').value;
    const data = {
        name: document.getElementById('cust_name').value,
        mobile: document.getElementById('cust_mobile').value,
        // Optional DOB
        dob: dobValue ? dobValue : null, 
        anniversary: document.getElementById('cust_anniversary').value || null,
        medical_history: null,
        gstin: null,
    };

    // Doctor specific fields logic
    if (['DOCTOR_CLINIC', 'DENTIST', 'PHYSIOTHERAPY', 'ORTHOPEDIC'].includes(CURRENT_USER_TYPE)) {
        const historyEl = document.getElementById('cust_medical_history');
        data.medical_history = historyEl ? historyEl.value : '';
    }
    return data;
}

// B. Add Stock Form Handler

function getStockFormData() {
    const data = {
        name: document.getElementById('item_name').value,
        price: document.getElementById('item_price').value,
        quantity: document.getElementById('item_qty').value,
        
        // Dynamic Fields
        expiry_date: null,
        batch_no: null,
        imei: null,
        warranty_end: null
    };

    const config = MASTER_BUSINESS_CONFIG[CURRENT_USER_TYPE];

    // Expiry Logic
    if (config.features.includes('expiry_date')) {
        data.expiry_date = document.getElementById('item_expiry').value;
        data.batch_no = document.getElementById('item_batch').value;
    }

    // IMEI Logic
    if (config.features.includes('imei_scan')) {
        data.imei = document.getElementById('item_imei').value;
    }

    // Warranty Logic
    if (config.features.includes('warranty_date') || CURRENT_USER_TYPE === 'FURNITURE') {
        data.warranty_end = document.getElementById('item_warranty').value;
    }
	
	// --- NEW LOGIC START ---
    
    // Tiles Data Capture
    if (document.getElementById('module-tiles-calc').style.display === 'block') {
        data.product_attributes.sqft_per_box = document.getElementById('stock-sqft-per-box').value;
        data.product_attributes.pcs_per_box = document.getElementById('stock-pcs-per-box').value;
    }

    // Rental Data Capture
    if (document.getElementById('module-rental-stock').style.display === 'block') {
        data.product_attributes.security_deposit = document.getElementById('rental-security').value;
        data.product_attributes.daily_rent = document.getElementById('rental-daily-price').value;
        data.product_attributes.is_rental = document.getElementById('rental-is-active').checked;
    }
    // --- NEW LOGIC END ---

    return data;
}

// ============================================================
// 🛠️ 5. UTILITIES (Helpers)
// ============================================================

function showNotification(msg) {
    // Simple Toast or Alert replacement
    alert(msg); 
}

// Mock fetchApi for standalone testing (Replace with your real API handler)
async function fetchApi(url, options) {
    console.log(`📡 Mock API Call: ${url}`, options);
    // Simulating Success
    return new Promise(resolve => setTimeout(() => resolve({ success: true }), 500));
}


// ============================================================
// 🚨 ANTI-THEFT & SECURITY LOGIC
// ============================================================

let securityStream = null;

function toggleSecurityMode() {
    const isArmed = document.getElementById('security-arm-switch').checked;
    const video = document.getElementById('security-video');
    
    if (isArmed) {
        // 1. कैमरा चालू करें
        navigator.mediaDevices.getUserMedia({ video: true })
            .then(stream => {
                securityStream = stream;
                video.srcObject = stream;
                document.getElementById('security-status-box').className = "alert alert-success";
                document.getElementById('security-status-box').innerText = "✅ Security Active. Monitoring Gate...";
                
                // 2. Keyboard/RFID Listener चालू करें
                document.addEventListener('keydown', handleRFIDSignal);
            })
            .catch(err => alert("Camera Error: " + err));
    } else {
        // कैमरा बंद करें
        if (securityStream) {
            securityStream.getTracks().forEach(track => track.stop());
            video.srcObject = null;
        }
        document.removeEventListener('keydown', handleRFIDSignal);
        document.getElementById('security-status-box').className = "alert alert-secondary";
        document.getElementById('security-status-box').innerText = "System Disarmed.";
    }
}

// 🕵️‍♂️ यह फंक्शन "RFID टैग" को पकड़ता है
// (असली दुनिया में RFID रीडर कीबोर्ड की तरह नंबर टाइप करता है)
let rfidBuffer = '';
function handleRFIDSignal(e) {
    if (e.key === 'Enter') {
        // सिग्नल पूरा हुआ, चेक करो कि क्या यह बिका हुआ है?
        checkTheftDatabase(rfidBuffer);
        rfidBuffer = '';
    } else {
        rfidBuffer += e.key;
    }
}

// 🔔 अलार्म बजाने और फोटो खींचने का फंक्शन
function triggerTheftAlarm(productName) {
    // 1. जोर से साउंड बजाओ
    const audio = new Audio('https://media.geeksforgeeks.org/wp-content/uploads/20190531135120/beep.mp3'); 
    audio.play();

    // 2. स्क्रीन लाल करो
    document.body.style.backgroundColor = "red";
    setTimeout(() => document.body.style.backgroundColor = "", 2000);

    // 3. फोटो खींचो (Capture Photo)
    const video = document.getElementById('security-video');
    const canvas = document.getElementById('security-canvas');
    const photo = document.getElementById('thief-photo-display');
    
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    canvas.getContext('2d').drawImage(video, 0, 0);
    
    const dataUrl = canvas.toDataURL('image/png');
    photo.src = dataUrl; // फोटो दिखाओ

    // 4. मैसेज दिखाओ
    document.getElementById('security-status-box').className = "alert alert-danger fw-bold";
    document.getElementById('security-status-box').innerHTML = `🚨 THEFT DETECTED! Item: ${productName}`;
    document.getElementById('alert-timestamp').innerText = "Time: " + new Date().toLocaleTimeString();

    // 5. (Optional) सर्वर पर फोटो भेजो
    // uploadTheftEvidence(dataUrl, productName);
}

// डेमो के लिए (Test Button)
function testAlarm() {
    triggerTheftAlarm("Levis Jeans (Blue) - Not Billed!");
}

async function checkTheftDatabase(tagId) {
    // यहाँ हम चेक करेंगे कि क्या यह Tag ID "Sold" लिस्ट में है?
    // अगर नहीं है, तो अलार्म बजेगा
    console.log("Checking Tag:", tagId);
    // triggerTheftAlarm("Unknown Item"); // (Uncomment to test with real scanner)
}



// ============================================================
// 🚀 6. BUSINESS LOGIC HANDLERS (Connects UI to Server)
// ============================================================

// 1. 🏨 HOTEL: Check-In Logic
async function processHotelCheckIn() {
    const data = {
        room_id: document.getElementById('hotel_room_select').value, // You need to populate this via API first
        customer_name: document.getElementById('hotel_guest_name').value,
        mobile: document.getElementById('hotel_guest_mobile').value,
        check_in_date: document.getElementById('hotel_checkin_date').value,
        advance: document.getElementById('hotel_advance').value
    };
    if(!data.room_id || !data.customer_name) return alert("Please fill details");

    try {
        const res = await fetchApi('/api/hotel/checkin', { method: 'POST', body: data });
        if(res.success) showNotification("✅ Guest Checked In Successfully!");
    } catch(e) { alert(e.message); }
}

// 2. 🎓 SCHOOL: Fee Collection
async function processSchoolFee() {
    const data = {
        studentId: document.getElementById('school_student_id').value,
        amount: document.getElementById('school_fee_amount').value,
        month: document.getElementById('school_fee_month').value
    };
    try {
        const res = await fetchApi('/api/school/pay-fee', { method: 'POST', body: data });
        if(res.success) showNotification("✅ Fee Collected Successfully!");
    } catch(e) { alert(e.message); }
}

// 3. 🚛 TRANSPORT: Create Trip
async function createTransportTrip() {
    const data = {
        vehicle: document.getElementById('trans_vehicle').value,
        driver: document.getElementById('trans_driver').value,
        start: document.getElementById('trans_start').value,
        end: document.getElementById('trans_end').value,
        freight: document.getElementById('trans_freight').value
    };
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
    try {
        const res = await fetchApi('/api/repair/create-job', { method: 'POST', body: data });
        if(res.success) showNotification("✅ Job Card Generated!");
    } catch(e) { alert(e.message); }
}

// 5. 🍽️ RESTAURANT: KOT
function addKotRow() {
    const div = document.createElement('div');
    div.className = 'input-group input-group-sm mb-1';
    div.innerHTML = `<input type="text" class="form-control kot-item" placeholder="Item"><input type="number" class="form-control kot-qty" placeholder="Qty" style="max-width: 60px;">`;
    document.getElementById('kot-items-list').appendChild(div);
}

async function sendKotToKitchen() {
    const tableId = document.getElementById('rest_table_no').value; // Need logic to map T1 to ID
    // Gathering items
    const items = [];
    document.querySelectorAll('#kot-items-list .input-group').forEach(row => {
        const item = row.querySelector('.kot-item').value;
        const qty = row.querySelector('.kot-qty').value;
        if(item && qty) items.push({ item, qty });
    });

    if(items.length === 0) return alert("Add items first");
    
    // Note: You need to implement mapping Table No -> Table ID in backend or UI
    // For now passing tableId as text (Server might need int, adjust accordingly)
    // Assuming we send to an API
    try {
        // Mocking table ID for now, in real app fetch tables first
        const res = await fetchApi('/api/restaurant/create-kot', { method: 'POST', body: { tableId: 1, items } }); 
        if(res.success) showNotification("✅ KOT Sent to Kitchen!");
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
    } catch(e) { alert("Invalid JSON Formula or Error: " + e.message); }
}

// 7. 🚨 GARMENTS: Security Alarm System
// Call this function when valid RFID tag is NOT found in sales DB
async function triggerSecurityAlarm(detectedTag) {
    const audio = new Audio('https://media.geeksforgeeks.org/wp-content/uploads/20190531135120/beep.mp3');
    audio.play();
    
    // Capture Photo
    const video = document.getElementById('security-video');
    const canvas = document.getElementById('security-canvas');
    if(video) {
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        canvas.getContext('2d').drawImage(video, 0, 0);
        const imageBase64 = canvas.toDataURL('image/png');

        // Send to Server
        try {
            await fetchApi('/api/security/alert', { 
                method: 'POST', 
                body: { imageBase64, rfidTag: detectedTag }
            });
            showNotification("🚨 Security Alert Logged!");
        } catch(e) { console.error(e); }
    }
}


// --- GROUP 5: RENTAL & EVENT (Tent, Catering) ---
    TENT_HOUSE: {
        name: "Tent House / Event Rentals",
        theme: "#d63384", // Pink/Red
        labels: { customer: "Party Name", stock: "Items (Stock)" },
        features: ['rental_dates', 'security_deposit', 'bulk_order'], // Stock wapis aane ki date
        dashboard_view: 'rental_grid'
    },
    
    // --- GROUP 6: CONSTRUCTION (Tiles, Glass, Sanitary) ---
    TILES_CERAMIC: {
        name: "Tiles & Sanitaryware",
        theme: "#6c757d", // Grey
        labels: { customer: "Client/Contractor", stock: "Boxes" },
        features: ['sqft_calc', 'breakage_loss', 'batch_number'], // Box to SqFt convertor
        dashboard_view: 'retail_grid'
    },

    // --- GROUP 7: PROFESSIONAL SERVICES (Architect, Software, CA) ---
    ARCHITECT_FIRM: {
        name: "Architect / Interior Design",
        theme: "#212529", // Dark Black
        labels: { customer: "Client Name", stock: "Services" },
        features: ['project_milestones', 'service_invoice', 'quotation_maker'], // No physical stock
        dashboard_view: 'service_grid'
    },
    SOFTWARE_COMPANY: {
        name: "Software / IT Company",
        theme: "#0d6efd", // Blue
        labels: { customer: "Client Name", stock: "Packages" },
        features: ['amc_renewal', 'service_invoice', 'project_tracking'], // Renewal dates helpful
        dashboard_view: 'service_grid'
    },
    INSURANCE_AGENCY: {
        name: "Insurance / LIC Agent",
        theme: "#198754", // Green
        labels: { customer: "Policy Holder", stock: "Policies" },
        features: ['policy_expiry', 'renewal_reminder', 'premium_calc'], // Expiry date = Renewal date
        dashboard_view: 'crm_focused'
    },

    // --- GROUP 8: TELECOM (Sim Cards) ---
    SIM_STORE: {
        name: "SIM Card & Recharge",
        theme: "#ffc107", // Yellow
        labels: { customer: "Customer", stock: "SIM Numbers" },
        features: ['kyc_document', 'mobile_number_select', 'plan_expiry'], // ID Proof zaroori hai
        dashboard_view: 'quick_pos'
    }
	
	// [NEW GPS FUNCTION]
function captureGPS() {
    const statusEl = document.getElementById('gps-status');
    const btn = document.querySelector('button[onclick="captureGPS()"]');
    
    if (!navigator.geolocation) {
        statusEl.innerText = "❌ GPS not supported on this device.";
        return;
    }

    statusEl.innerText = "⏳ Getting Satellite Fix...";
    btn.disabled = true;

    navigator.geolocation.getCurrentPosition(
        (position) => {
            const lat = position.coords.latitude;
            const long = position.coords.longitude;
            const accuracy = position.coords.accuracy;

            document.getElementById('pos-lat').value = lat;
            document.getElementById('pos-long').value = long;

            statusEl.innerHTML = `<span class="text-success">✅ Captured! (Acc: ${Math.round(accuracy)}m)</span>`;
            statusEl.classList.remove('text-danger');
            btn.innerHTML = '<i class="fas fa-check"></i> Done';
            
            // Google Maps Link for Verification (Optional UI update)
            console.log(`GPS: https://maps.google.com/?q=${lat},${long}`);
        },
        (error) => {
            let msg = "Error";
            switch(error.code) {
                case error.PERMISSION_DENIED: msg = "❌ User denied GPS."; break;
                case error.POSITION_UNAVAILABLE: msg = "❌ Signal weak."; break;
                case error.TIMEOUT: msg = "❌ Request timed out."; break;
            }
            statusEl.innerText = msg;
            btn.disabled = false;
        },
        { enableHighAccuracy: true, timeout: 10000, maximumAge: 0 }
    );
}

// Export for Global Usage
window.initializeSoftware = initializeSoftware;
window.calculateEDD = calculateEDD;
window.saveMedicalReport = saveMedicalReport;
window.toggleToothSelection = toggleToothSelection;
window.loadSonoTemplate = (type) => injectMedicalTemplate('SONOGRAPHY', type); // Backward compatibility