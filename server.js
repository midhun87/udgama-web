require('dotenv').config();
const express = require('express');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const QRCode = require('qrcode');
const multer = require('multer');
const Razorpay = require('razorpay');
const crypto = require('crypto');

// AWS SDK v3 Imports
const { DynamoDBClient } = require('@aws-sdk/client-dynamodb');
const { DynamoDBDocumentClient, PutCommand, GetCommand, ScanCommand, UpdateCommand } = require('@aws-sdk/lib-dynamodb');
const { SESClient, SendEmailCommand } = require('@aws-sdk/client-ses');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- PROPER STATIC SERVING BASED ON YOUR FOLDER STRUCTURE ---
// The extensions: ['html'] option allows you to visit URLs without typing .html at the end
const staticOptions = { extensions: ['html'], index: 'index.html' };

// 1. Serve everything in views/home at the root domain (e.g., /staff-login, /about, /)
app.use('/', express.static(path.join(__dirname, 'views', 'home'), staticOptions));

// 2. Serve everything in views/admin under the /admin path (e.g., /admin/dashboard)
app.use('/admin', express.static(path.join(__dirname, 'views', 'admin'), staticOptions));

// 3. Serve everything in views/coordinator under the /coordinator path (e.g., /coordinator/dashboard)
app.use('/coordinator', express.static(path.join(__dirname, 'views', 'coordinator'), staticOptions));

// 4. Serve your public assets (images, global css, etc.)
app.use('/assets', express.static(path.join(__dirname, 'public', 'assets')));

// ==========================================
// FIX: Backward Compatibility Redirects
// If your old HTML files redirect to these old URLs, 
// the server will automatically forward them to the new correct folders.
// ==========================================
app.get('/coordinator_dashboard.html', (req, res) => res.redirect('/coordinator/dashboard'));
app.get('/admin_dashboard.html', (req, res) => res.redirect('/admin/dashboard'));

const JWT_SECRET = process.env.JWT_SECRET || 'udgama-super-secret-key-2026';

// DynamoDB Configuration
const ddbConfig = { region: process.env.AWS_REGION || 'ap-south-1' };
const ddbClient = new DynamoDBClient(ddbConfig);
const docClient = DynamoDBDocumentClient.from(ddbClient);

// SES Configuration (For Invoices and Confirmations)
const sesConfig = { 
    region: process.env.AWS_REGION || 'ap-south-1',
    credentials: {
        accessKeyId: process.env.SES_AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.SES_AWS_SECRET_ACCESS_KEY,
    }
};
const sesClient = new SESClient(sesConfig);

// Initialize Razorpay
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET
});

// DynamoDB Table Names (New Architecture)
const ADMINS_TABLE = 'Udgama_Admins'; // Stores both Admin and Org Coordinators
const ORGS_TABLE = 'Udgama_Organizations';
const EVENTS_TABLE = 'Udgama_Events';
const REGISTRATIONS_TABLE = 'Udgama_Registrations'; // Guest registrations tied to events

// Middleware for JWT Authentication
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized: No token provided' });
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; // Contains { adminId, email, role, orgId }
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Unauthorized: Invalid token' });
    }
};

const requireAdmin = (req, res, next) => {
    authenticateToken(req, res, () => {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Forbidden: Master Admin access required' });
        }
        next();
    });
};

const requireCoordinator = (req, res, next) => {
    authenticateToken(req, res, () => {
        if (req.user.role !== 'coordinator' && req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Forbidden: Coordinator access required' });
        }
        next();
    });
};

const upload = multer({ storage: multer.memoryStorage() });

// --- API: Staff Authentication ---
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const response = await docClient.send(new GetCommand({
            TableName: ADMINS_TABLE,
            Key: { email }
        }));
        const user = response.Item;

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ 
            adminId: user.adminId, 
            email: user.email, 
            role: user.role,
            orgId: user.orgId // Will be undefined for Master Admin
        }, JWT_SECRET, { expiresIn: '24h' });
        
        res.json({ message: 'Login successful', token, role: user.role, orgId: user.orgId, name: user.name });
    } catch (error) {
        console.error('Login Error:', error);
        res.status(500).json({ error: 'Internal server error during login' });
    }
});

// --- API: Master Admin Routes ---
// 1. Create Organization
app.post('/api/admin/organizations', requireAdmin, async (req, res) => {
    try {
        const { name, description, logoUrl } = req.body;
        const orgId = `ORG-${uuidv4().substring(0, 8).toUpperCase()}`;

        const orgItem = {
            orgId,
            name,
            description: description || '',
            logoUrl: logoUrl || '', // Save logo link
            createdAt: new Date().toISOString()
        };

        await docClient.send(new PutCommand({
            TableName: ORGS_TABLE,
            Item: orgItem
        }));

        res.json({ message: 'Organization created successfully', organization: orgItem });
    } catch (error) {
        console.error('Create Org Error:', error);
        res.status(500).json({ error: 'Failed to create organization' });
    }
});
// 2. Create Organization Coordinator
app.post('/api/admin/coordinators', requireAdmin, async (req, res) => {
    try {
        const { email, password, name, orgId } = req.body;
        
        const existing = await docClient.send(new GetCommand({ TableName: ADMINS_TABLE, Key: { email } }));
        if (existing.Item) return res.status(400).json({ error: 'Email already exists' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const adminId = `COORD-${uuidv4().substring(0, 8)}`;

        const coordItem = {
            email, // Partition Key
            adminId,
            name,
            password: hashedPassword,
            role: 'coordinator',
            orgId,
            createdAt: new Date().toISOString()
        };

        await docClient.send(new PutCommand({ TableName: ADMINS_TABLE, Item: coordItem }));
        res.json({ message: 'Coordinator created successfully', email });
    } catch (error) {
        console.error('Create Coord Error:', error);
        res.status(500).json({ error: 'Failed to create coordinator' });
    }
});

// --- API: Organization Coordinator Routes ---
// 1. Create Event
app.post('/api/coordinator/events', requireCoordinator, upload.single('bannerImage'), async (req, res) => {
    try {
        const orgId = req.user.role === 'admin' ? req.body.orgId : req.user.orgId;
        if (!orgId) return res.status(400).json({ error: 'Organization ID is required' });

        const { 
            title, shortDescription, detailedDescription, 
            isTeam, teamSize, 
            ieeeAmount, ieeeTax, nonIeeeAmount, nonIeeeTax,
            bannerUrl, subEvents // Extracted subEvents array
        } = req.body;
        
        const eventId = `EVT-${uuidv4().substring(0, 8).toUpperCase()}`;
        const finalBannerUrl = bannerUrl || ('https://placehold.co/800x400/003057/FFFFFF?text=' + encodeURIComponent(title));

        const eventItem = {
            eventId,
            orgId,
            title,
            shortDescription: shortDescription || '',
            detailedDescription: detailedDescription || '',
            subEvents: Array.isArray(subEvents) ? subEvents : [], // Save the array of strings
            isTeam: isTeam === 'true' || isTeam === true,
            teamSize: Number(teamSize || 1),
            ieeeAmount: Number(ieeeAmount || 0),
            ieeeTax: Number(ieeeTax || 0),
            nonIeeeAmount: Number(nonIeeeAmount || 0),
            nonIeeeTax: Number(nonIeeeTax || 0),
            status: 'opened',
            bannerUrl: finalBannerUrl,
            createdAt: new Date().toISOString()
        };

        await docClient.send(new PutCommand({ TableName: EVENTS_TABLE, Item: eventItem }));
        res.json({ message: 'Event created successfully', event: eventItem });
    } catch (error) {
        console.error('Create Event Error:', error);
        res.status(500).json({ error: 'Failed to create event' });
    }
});

// 2. Modify Event
app.put('/api/coordinator/events/:eventId', requireCoordinator, async (req, res) => {
    try {
        const { eventId } = req.params;
        const orgId = req.user.role === 'admin' ? null : req.user.orgId;

        if (orgId) {
            const eventCheck = await docClient.send(new GetCommand({ TableName: EVENTS_TABLE, Key: { eventId } }));
            if (!eventCheck.Item || eventCheck.Item.orgId !== orgId) {
                return res.status(403).json({ error: 'Unauthorized to edit this event' });
            }
        }

        const updates = req.body;
        const updateExpressions = [];
        const expressionAttributeValues = {};
        const expressionAttributeNames = {};

        // Added 'subEvents' to the allowed array
        Object.keys(updates).forEach((key) => {
            if (['title', 'shortDescription', 'detailedDescription', 'isTeam', 'teamSize', 'ieeeAmount', 'ieeeTax', 'nonIeeeAmount', 'nonIeeeTax', 'status', 'bannerUrl', 'subEvents'].includes(key)) {
                updateExpressions.push(`#${key} = :${key}`);
                expressionAttributeNames[`#${key}`] = key;
                expressionAttributeValues[`:${key}`] = updates[key];
            }
        });

        if (updateExpressions.length === 0) return res.status(400).json({ error: 'No valid fields to update' });

        await docClient.send(new UpdateCommand({
            TableName: EVENTS_TABLE,
            Key: { eventId },
            UpdateExpression: `SET ${updateExpressions.join(', ')}`,
            ExpressionAttributeNames: expressionAttributeNames,
            ExpressionAttributeValues: expressionAttributeValues
        }));

        res.json({ message: 'Event updated successfully' });
    } catch (error) {
        console.error('Update Event Error:', error);
        res.status(500).json({ error: 'Failed to update event' });
    }
});

// 3. View Registrations for Coordinator's Org
app.get('/api/coordinator/registrations', requireCoordinator, async (req, res) => {
    try {
        const orgId = req.user.role === 'admin' ? null : req.user.orgId;
        
        // Fetch all events for this org
        const eventsScan = await docClient.send(new ScanCommand({ TableName: EVENTS_TABLE }));
        let orgEvents = eventsScan.Items || [];
        if (orgId) orgEvents = orgEvents.filter(e => e.orgId === orgId);
        
        const orgEventIds = orgEvents.map(e => e.eventId);

        // Fetch all registrations and filter in-memory (In prod, use Global Secondary Index on eventId)
        const regScan = await docClient.send(new ScanCommand({ TableName: REGISTRATIONS_TABLE }));
        const allRegs = regScan.Items || [];
        
        const orgRegistrations = allRegs.filter(reg => orgEventIds.includes(reg.eventId));
        
        // Map event details to registrations for frontend convenience
        const mappedRegs = orgRegistrations.map(reg => {
            const event = orgEvents.find(e => e.eventId === reg.eventId);
            return { ...reg, eventName: event ? event.title : 'Unknown' };
        });

        res.json({ registrations: mappedRegs });
    } catch (error) {
        console.error('Fetch Coordinator Regs Error:', error);
        res.status(500).json({ error: 'Failed to fetch registrations' });
    }
});

// 4. Modify Registration Details
app.put('/api/coordinator/registrations/:regId', requireCoordinator, async (req, res) => {
    try {
        const { regId } = req.params;
        const { participants } = req.body; // Expecting the updated full array of participants

        if (!participants || !Array.isArray(participants)) {
            return res.status(400).json({ error: 'Participants array is required' });
        }

        await docClient.send(new UpdateCommand({
            TableName: REGISTRATIONS_TABLE,
            Key: { registrationId: regId },
            UpdateExpression: 'SET participants = :p',
            ExpressionAttributeValues: { ':p': participants }
        }));

        res.json({ message: 'Registration updated successfully' });
    } catch (error) {
        console.error('Update Registration Error:', error);
        res.status(500).json({ error: 'Failed to modify registration' });
    }
});

// --- API: Public Facing (Guest Flow) ---
app.get('/api/public/data', async (req, res) => {
    try {
        const [orgsRes, eventsRes] = await Promise.all([
            docClient.send(new ScanCommand({ TableName: ORGS_TABLE })),
            docClient.send(new ScanCommand({ TableName: EVENTS_TABLE }))
        ]);
        
        res.json({ 
            organizations: orgsRes.Items || [], 
            events: (eventsRes.Items || []).filter(e => e.status === 'opened') 
        });
    } catch (error) {
        console.error('Public Data Fetch Error:', error);
        res.status(500).json({ error: 'Failed to fetch public data' });
    }
});

// 1. Guest Registration Init (Create Order)
app.post('/api/public/register/init', async (req, res) => {
    try {
        const { eventId, participants } = req.body;
        
        if (!participants || participants.length === 0) {
            return res.status(400).json({ error: 'Participant details are required' });
        }

        // Fetch event to calculate price securely
        const eventData = await docClient.send(new GetCommand({ TableName: EVENTS_TABLE, Key: { eventId } }));
        const event = eventData.Item;
        
        if (!event || event.status === 'closed') {
            return res.status(400).json({ error: 'Event is unavailable' });
        }

        if (event.isTeam && participants.length > event.teamSize) {
            return res.status(400).json({ error: `Maximum team size is ${event.teamSize}` });
        }

        // Dynamically calculate total amount based on IEEE status of each participant
        let totalAmount = 0;
        let totalTax = 0;

        participants.forEach(p => {
            if (p.isIeee === 'Yes' || p.isIeee === true) {
                totalAmount += Number(event.ieeeAmount);
                totalTax += Number(event.ieeeTax);
            } else {
                totalAmount += Number(event.nonIeeeAmount);
                totalTax += Number(event.nonIeeeTax);
            }
        });

        const finalPayable = totalAmount + totalTax;

        if (finalPayable === 0) {
            return res.json({ requiresPayment: false, eventId, participants, totalPaid: 0, message: 'Free event, proceed to verification' });
        }

        // Create Razorpay Order
        const order = await razorpay.orders.create({
            amount: finalPayable * 100, // paise
            currency: "INR",
            receipt: `rcpt_${uuidv4().substring(0, 8)}`
        });

        res.json({
            requiresPayment: true,
            orderId: order.id,
            amount: order.amount,
            currency: order.currency,
            keyId: process.env.RAZORPAY_KEY_ID,
            totalPaid: finalPayable // Pass down to verification step
        });

    } catch (error) {
        console.error('Guest Register Init Error:', error);
        res.status(500).json({ error: 'Failed to initiate payment order' });
    }
});

// 2. Guest Registration Verify (Save Data & Send Emails)
app.post('/api/public/register/verify', async (req, res) => {
    try {
        // Extract selectedSubEvent from payload
        const { eventId, selectedSubEvent, participants, totalPaid, razorpay_payment_id, razorpay_order_id, razorpay_signature, isFree } = req.body;

        if (!isFree) {
            const hmac = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET);
            hmac.update(razorpay_order_id + "|" + razorpay_payment_id);
            const generated_signature = hmac.digest('hex');

            if (generated_signature !== razorpay_signature) {
                return res.status(400).json({ error: 'Payment verification failed. Invalid signature.' });
            }
        }

        const registrationId = `TKT-${uuidv4().substring(0, 8).toUpperCase()}`;
        const qrDataUrl = await QRCode.toDataURL(registrationId);

        const registrationItem = {
            registrationId,
            eventId,
            selectedSubEvent: selectedSubEvent || null, // Saved to DB
            participants,
            paymentId: razorpay_payment_id || 'FREE_EVENT',
            orderId: razorpay_order_id || 'NONE',
            totalAmountPaid: totalPaid || 0,
            paymentStatus: 'Paid',
            qrCode: qrDataUrl,
            attended: false,
            createdAt: new Date().toISOString()
        };

        await docClient.send(new PutCommand({ TableName: REGISTRATIONS_TABLE, Item: registrationItem }));

        const allEmails = participants.map(p => p.email);
        const senderSource = process.env.SES_SENDER_EMAIL || 'noreply@udgama.in';

        let eventName = "UDGAMA 2026 Event";
        try {
            const eventData = await docClient.send(new GetCommand({ TableName: EVENTS_TABLE, Key: { eventId } }));
            if (eventData.Item) eventName = eventData.Item.title;
        } catch(e) { console.error("Could not fetch event name for email:", e); }

        // Adjust string interpolation to include Sub-Event if present
        let displayEventName = selectedSubEvent ? `${eventName} (${selectedSubEvent})` : eventName;

        let participantRowsHTML = '';
        participants.forEach((p, index) => {
            participantRowsHTML += `
                <tr>
                    <td style="padding: 12px; border-bottom: 1px solid #e2e8f0; color: #334155; font-size: 14px;">${index + 1}</td>
                    <td style="padding: 12px; border-bottom: 1px solid #e2e8f0; color: #0f172a; font-size: 14px; font-weight: bold;">${p.fullName} ${index === 0 ? '<span style="color:#00629B; font-size:12px;">(Lead)</span>' : ''}</td>
                    <td style="padding: 12px; border-bottom: 1px solid #e2e8f0; color: #334155; font-size: 14px;">${p.email}</td>
                    <td style="padding: 12px; border-bottom: 1px solid #e2e8f0; color: #334155; font-size: 14px;">${p.organization}</td>
                    <td style="padding: 12px; border-bottom: 1px solid #e2e8f0; color: #334155; font-size: 14px;">${p.isIeee === 'Yes' || p.isIeee === true ? 'Yes' : 'No'}</td>
                </tr>
            `;
        });

        // The HTML body string remains exactly the same, but replace ${eventName} inside your HTML block with ${displayEventName}
        // (You can copy your original HTML string here, just changing line 249 from ${eventName} to ${displayEventName})
        // Example portion to change:
        // <p>Thank you for registering for <span class="event-name">${displayEventName}</span>. Your payment has been successfully processed...</p>

        // *** I have shortened the HTML string block below for readability, use your full existing HTML string and replace the variable ***
        
        const emailHtmlBody = `
            <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <!-- Tell email clients not to force dark mode inverted colors -->
    <meta name="color-scheme" content="light">
    <meta name="supported-color-schemes" content="light">
    <title>UDGAMA 2026 Registration Confirmation</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
    
    <style>
        /* Reset and base styles */
        body { 
            font-family: 'Inter', 'Helvetica Neue', Helvetica, Arial, sans-serif; 
            background-color: #f3f4f6; 
            margin: 0; 
            padding: 20px; 
            color: #374151;
            -webkit-font-smoothing: antialiased;
        }
        
        /* Main container styling */
        .container { 
            max-width: 650px; 
            margin: 0 auto; 
            background-color: #ffffff; 
            border-radius: 12px; 
            overflow: hidden; 
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1); 
        }

        /* Header styling */
        .header { 
            background: linear-gradient(135deg, #002855 0%, #004d99 100%);
            padding: 40px 30px; 
            text-align: center;
        }
        
        .logo-container { margin-bottom: 20px; }
        .ieee-logo {
            height: 60px;
            width: auto;
            border-radius: 4px;
            background-color: #ffffff;
            padding: 5px 10px;
            max-width: 100%;
        }

        .header h1 { 
            color: #ffffff; 
            margin: 0; 
            font-size: 28px; 
            font-weight: 700;
            letter-spacing: 1.5px; 
            text-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }
        .header p { 
            color: #93c5fd; 
            margin: 8px 0 0 0; 
            font-size: 13px; 
            font-weight: 600;
            text-transform: uppercase; 
            letter-spacing: 2px; 
        }

        /* Content area styling */
        .content { padding: 40px 30px; }
        
        .success-msg { 
            text-align: center; 
            margin-bottom: 35px; 
        }
        
        .success-icon {
            width: 60px;
            height: 60px;
            background-color: #10b981;
            border-radius: 50%;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 15px;
            box-shadow: 0 4px 6px rgba(16, 185, 129, 0.2);
        }
        .success-icon::after {
            content: '';
            width: 14px;
            height: 24px;
            border: solid white;
            border-width: 0 4px 4px 0;
            transform: rotate(45deg);
            margin-top: -6px;
        }

        .success-msg h2 { 
            color: #111827; 
            margin: 0 0 12px 0; 
            font-size: 24px; 
            font-weight: 700;
        }
        .success-msg p { 
            color: #4b5563; 
            font-size: 16px; 
            line-height: 1.6; 
            margin: 0; 
        }
        
        .event-name {
            color: #0056b3;
            font-weight: 700;
        }

        /* Details box styling - Replaced Flexbox with Table for Email Client Support */
        .details-box { 
            background-color: #f8fafc; 
            border-left: 5px solid #0056b3; 
            padding: 20px 25px; 
            margin-bottom: 35px; 
            border-radius: 6px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        
        .details-table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .details-table td {
            padding: 5px 15px 5px 0;
            vertical-align: top;
            border-bottom: none; /* Override standard td border */
        }

        .detail-label {
            font-size: 12px;
            text-transform: uppercase;
            color: #64748b;
            font-weight: 600;
            display: block; /* Ensure it stays above the value */
            margin-bottom: 4px;
        }
        
        .detail-value {
            font-size: 16px;
            color: #1e293b;
            font-weight: 700;
            display: block;
        }
        
        .status-success {
            color: #10b981;
        }

        /* Table styling for Participants */
        .section-title {
            color: #111827; 
            font-size: 20px; 
            font-weight: 700;
            margin: 0 0 20px 0; 
            border-bottom: 2px solid #e5e7eb;
            padding-bottom: 10px;
        }
        
        .table-container { 
            width: 100%; 
            overflow-x: auto; 
            -webkit-overflow-scrolling: touch; /* Smooth horizontal scroll on iOS */
            margin-bottom: 30px; 
            border-radius: 8px;
            border: 1px solid #e5e7eb;
            background-color: #ffffff;
        }
        
        table { 
            width: 100%; 
            min-width: 500px; /* Forces table to overflow instead of squishing columns on mobile */
            border-collapse: collapse; 
            text-align: left; 
        }
        th { 
            background-color: #f9fafb; 
            padding: 14px 16px; 
            font-size: 13px; 
            text-transform: uppercase; 
            color: #6b7280; 
            font-weight: 600;
            border-bottom: 2px solid #e5e7eb; 
            white-space: nowrap;
        }
        td {
            padding: 14px 16px;
            font-size: 14px;
            color: #374151;
            border-bottom: 1px solid #e5e7eb;
        }
        tr:last-child td { border-bottom: none; }
        tr:nth-child(even) { background-color: #f8fafc; }

        .important-note {
            background-color: #fffbeb;
            border: 1px solid #fde68a;
            color: #92400e;
            padding: 15px;
            border-radius: 6px;
            font-size: 14px;
            line-height: 1.5;
            text-align: center;
            margin-top: 30px;
        }

        .footer { 
            background-color: #1f2937;
            padding: 25px 20px; 
            text-align: center; 
        }
        .footer p { 
            color: #9ca3af; 
            font-size: 13px; 
            margin: 6px 0; 
        }
        .footer a { 
            color: #60a5fa; 
            text-decoration: none; 
            font-weight: 600; 
            transition: color 0.2s ease;
        }
        .footer a:hover { color: #93c5fd; text-decoration: underline; }

        /* Comprehensive Responsive Adjustments */
        @media only screen and (max-width: 600px) {
            body { 
                padding: 10px; /* Maximize screen space on mobile */
            }
            .header { 
                padding: 30px 15px; 
            }
            .header h1 {
                font-size: 24px; /* Slightly smaller title */
            }
            .header p {
                font-size: 12px;
            }
            .content { 
                padding: 25px 15px; 
            }
            .success-icon {
                width: 50px;
                height: 50px;
            }
            .success-icon::after {
                width: 12px;
                height: 20px;
                margin-top: -4px;
            }
            .success-msg h2 {
                font-size: 22px;
            }
            .success-msg p {
                font-size: 15px;
            }
            
            /* Stack details table vertically on small screens */
            .details-box {
                padding: 15px;
            }
            .details-table td {
                display: block;
                width: 100%;
                padding: 10px 0;
                border-bottom: 1px solid #e2e8f0; /* Optional: add separator between stacked items */
            }
            .details-table td:last-child {
                border-bottom: none;
            }
            
            /* Adjust table padding for smaller screens while allowing scroll */
            th, td { 
                padding: 12px 10px; 
                font-size: 13px; 
            }
            
            .important-note {
                padding: 12px;
                font-size: 13px;
                text-align: left; /* Better readability for long text on mobile */
            }
        }
    </style>
</head>
<body>
    <div class="container">
        
        <!-- Header Section with Logo -->
        <div class="header">
            <div class="logo-container">
                <img src="https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQRQUOVTVuLAWuWWCkcSow3IBBsUkVKziDB3e5VpyN02Q&s=10" alt="IEEE Logo" class="ieee-logo">
            </div>
            <h1>UDGAMA 2026</h1>
            <p>IEEE Guntur Subsection Student Congress</p>
        </div>
        
        <!-- Main Content Section -->
        <div class="content">
            
            <div class="success-msg">
                <div class="success-icon"></div>
                <h2>Registration Confirmed!</h2>
                <p>Thank you for registering for <span class="event-name">${eventName}</span>. Your payment has been successfully processed and your spots are secured.</p>
            </div>
            
            <!-- Details Table - Robust for Email -->
            <div class="details-box">
                <table class="details-table" role="presentation">
                    <tr>
                        <td width="33%">
                            <span class="detail-label">Registration ID</span>
                            <span class="detail-value">${registrationId}</span>
                        </td>
                        <td width="33%">
                            <span class="detail-label">Total Amount</span>
                            <span class="detail-value">₹${totalPaid}</span>
                        </td>
                        <td width="33%">
                            <span class="detail-label">Payment Status</span>
                            <span class="detail-value status-success">Success ✓</span>
                        </td>
                    </tr>
                </table>
            </div>

            <!-- Participant Table -->
            <h3 class="section-title">Participant Details</h3>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Name</th>
                            <th>Email</th>
                            <th>Institution</th>
                            <th>IEEE Member</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- Assuming the rows are injected here securely -->
                        ${participantRowsHTML}
                    </tbody>
                </table>
            </div>
            
            <div class="important-note">
                <strong>Important:</strong> Please keep this email for your records.
                <br><br>
                <strong>Note:</strong> If you are an IEEE Member please carry your IEEE Membership card (E-card is also acceptable) during the day of the Event.
            </div>
            
        </div>
        
        <!-- Footer Section -->
        <div class="footer">
            <p>© 2026 UDGAMA IEEE Guntur Sub-Section Student Congress.</p>
            <p>Designed & Developed by <a href="https://xetasolutions.in" target="_blank">Xeta Tech Solutions</a></p>
        </div>
        
    </div>
</body>
</html>
        `;

        for (const email of allEmails) {
             const emailParams = {
                Destination: { ToAddresses: [email] },
                Message: {
                    Subject: { Data: `Confirmed: Your UDGAMA 2026 Registration - ${registrationId}` },
                    Body: { Html: { Data: emailHtmlBody } } // Be sure to put the full HTML here like before
                },
                Source: senderSource
            };
            await sesClient.send(new SendEmailCommand(emailParams)).catch(err => console.error(`Failed to send email to ${email}:`, err));
        }

        res.json({ message: 'Registration confirmed', registrationId });
    } catch (error) {
        console.error('Guest Register Verify Error:', error);
        res.status(500).json({ error: 'Failed to process final registration' });
    }
});
// Update Event Display Order (Master Admin Only)
app.put('/api/admin/events/:eventId/order', requireAdmin, async (req, res) => {
    try {
        const { eventId } = req.params;
        const { displayOrder } = req.body;

        if (typeof displayOrder !== 'number') {
            return res.status(400).json({ error: 'displayOrder must be a valid number' });
        }

        await docClient.send(new UpdateCommand({
            TableName: EVENTS_TABLE,
            Key: { eventId },
            UpdateExpression: 'SET displayOrder = :order',
            ExpressionAttributeValues: { ':order': displayOrder }
        }));

        res.json({ message: 'Event display order updated successfully' });
    } catch (error) {
        console.error('Update Event Order Error:', error);
        res.status(500).json({ error: 'Failed to update event order' });
    }
});

// Update Organization Display Order (Master Admin Only)
app.put('/api/admin/organizations/:orgId/order', requireAdmin, async (req, res) => {
    try {
        const { orgId } = req.params;
        const { displayOrder } = req.body;

        if (typeof displayOrder !== 'number') {
            return res.status(400).json({ error: 'displayOrder must be a valid number' });
        }

        await docClient.send(new UpdateCommand({
            TableName: ORGS_TABLE, // Ensure this matches your dynamo table name constant
            Key: { orgId },
            UpdateExpression: 'SET displayOrder = :order',
            ExpressionAttributeValues: { ':order': displayOrder }
        }));

        res.json({ message: 'Organization display order updated successfully' });
    } catch (error) {
        console.error('Update Org Order Error:', error);
        res.status(500).json({ error: 'Failed to update organization order' });
    }
});

// Catch-all for unresolved routes
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

app.listen(PORT, () => {
    console.log(`UDGAMA-2026 Engine running on http://localhost:${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});
