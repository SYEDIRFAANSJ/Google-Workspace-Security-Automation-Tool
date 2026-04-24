/**
 * index.js
 * GWS CISO Dashboard Backend — Hardened & Upgraded
 * 
 * Security Upgrades:
 * - Helmet CSP headers
 * - Rate limiting on all API routes
 * - Admin password on setup page
 * - Input validation
 * - Audit logging
 * - httpOnly + sameSite cookies
 * - Fixed static file serving order
 * - Retry logic for Google API calls
 * - Graceful error handling with partial results
 * - Configurable timezone
 * - Scan history tracking
 * - Email notifications for critical findings
 * - CIS Benchmark compliance mapping
 */

const fs = require('fs');
const path = require('path');
const express = require('express');
const crypto = require('crypto');
const session = require('express-session');
const pino = require('pino');
const cron = require('node-cron');
const dns = require('dns').promises;
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const { google } = require('googleapis');
const { BigQuery } = require('@google-cloud/bigquery');
const OpenAI = require('openai');

const LOG = pino({ level: process.env.LOG_LEVEL || 'info' });

// --- Environment Validation ---
const PORT = parseInt(process.env.PORT || '3000', 10);
const APP_SECRET = process.env.APP_SECRET;
if (!APP_SECRET || APP_SECRET.length < 32) {
    LOG.error('APP_SECRET is not defined in .env or is too short. Please set a long, random string.');
    process.exit(1);
}

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 8) {
    LOG.error('ADMIN_PASSWORD is not defined in .env or is too short (min 8 chars). Required to protect the setup page.');
    process.exit(1);
}

const TIMEZONE = process.env.TIMEZONE || 'UTC';

const CONFIG_PATH = path.join(__dirname, 'config.json');
const HISTORY_PATH = path.join(__dirname, 'scan-history.json');
const AUDIT_LOG_PATH = path.join(__dirname, 'audit.log');
let appConfig = null;
let cachedData = null;
let cronTask = null;

// --- Groq AI Client (OpenAI-compatible) ---
let groqClient = null;
const GROQ_API_KEY = process.env.GROQ_API_KEY;
if (GROQ_API_KEY) {
    groqClient = new OpenAI({
        apiKey: GROQ_API_KEY,
        baseURL: 'https://api.groq.com/openai/v1',
    });
    LOG.info('Groq AI client initialized successfully.');
} else {
    LOG.warn('GROQ_API_KEY not set in .env — AI features will be disabled.');
}

// --- Email Notification Setup (Optional) ---
let mailTransporter = null;
try {
    if (process.env.SMTP_HOST && process.env.SMTP_USER) {
        const nodemailer = require('nodemailer');
        mailTransporter = nodemailer.createTransport({
            host: process.env.SMTP_HOST,
            port: parseInt(process.env.SMTP_PORT || '587', 10),
            secure: false,
            auth: {
                user: process.env.SMTP_USER,
                pass: process.env.SMTP_PASS,
            },
        });
        LOG.info('Email notification transport configured.');
    }
} catch (err) {
    LOG.warn('Nodemailer not available — email notifications disabled.');
}

// --- Audit Logging ---
function auditLog(action, details = {}, req = null) {
    const entry = {
        timestamp: new Date().toISOString(),
        action,
        ip: req ? (req.headers['x-forwarded-for'] || req.socket.remoteAddress) : 'system',
        userAgent: req ? req.headers['user-agent'] : 'system',
        sessionId: req?.session?.id ? req.session.id.substring(0, 8) + '...' : 'none',
        ...details,
    };
    const line = JSON.stringify(entry) + '\n';
    fs.appendFile(AUDIT_LOG_PATH, line, (err) => {
        if (err) LOG.error('Failed to write audit log', err);
    });
    LOG.info({ audit: entry }, `AUDIT: ${action}`);
}

// --- Configuration & Encryption ---
const ALGORITHM = 'aes-256-cbc';
const IV_LENGTH = 16;
const key = crypto.createHash('sha256').update(String(APP_SECRET)).digest('base64').substr(0, 32);

function encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(key), iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    try {
        const textParts = text.split(':');
        const iv = Buffer.from(textParts.shift(), 'hex');
        const encryptedText = Buffer.from(textParts.join(':'), 'hex');
        const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(key), iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    } catch (error) {
        LOG.error('Decryption failed. The APP_SECRET may have changed or the data is corrupt.');
        return null;
    }
}

function loadConfig() {
    if (!fs.existsSync(CONFIG_PATH)) return null;
    try {
        const fileContent = fs.readFileSync(CONFIG_PATH, 'utf8');
        const config = JSON.parse(fileContent);
        const decryptedKey = decrypt(config.serviceAccountCreds.private_key);
        if (!decryptedKey) return null;
        config.serviceAccountCreds.private_key = decryptedKey;
        return config;
    } catch (err) {
        LOG.error('Failed to load or decrypt config file.', err);
        return null;
    }
}

function saveConfig(configData) {
    try {
        const configToSave = JSON.parse(JSON.stringify(configData));
        configToSave.serviceAccountCreds.private_key = encrypt(configToSave.serviceAccountCreds.private_key);
        fs.writeFileSync(CONFIG_PATH, JSON.stringify(configToSave, null, 2));
        appConfig = configData;
        LOG.info('Configuration saved successfully.');
    } catch (err) {
        LOG.error('Failed to save config file.', err);
    }
}

// --- Scan History Tracking ---
function loadScanHistory() {
    try {
        if (!fs.existsSync(HISTORY_PATH)) return [];
        return JSON.parse(fs.readFileSync(HISTORY_PATH, 'utf8'));
    } catch (err) {
        LOG.warn('Failed to load scan history', err);
        return [];
    }
}

function saveScanSnapshot(scanData) {
    try {
        const history = loadScanHistory();
        const snapshot = {
            timestamp: new Date().toISOString(),
            totalUsers: scanData.users?.length || 0,
            mfaEnabled: scanData.users?.filter(u => u.mfaEnrolled).length || 0,
            suspendedAccounts: scanData.users?.filter(u => u.suspended).length || 0,
            externalForwarding: scanData.users?.filter(u => u.forwardingExternal).length || 0,
            highRiskApps: scanData.users?.filter(u => u.highRiskApps > 0).length || 0,
            legacyProtocols: scanData.users?.filter(u => u.popAccess || u.imapAccess).length || 0,
            totalAlerts: scanData.totalAlertCount || 0,
            securityScore: calculateOrgSecurityScoreValue(scanData.users || []),
        };
        history.push(snapshot);
        // Keep only last 90 snapshots
        const trimmed = history.slice(-90);
        fs.writeFileSync(HISTORY_PATH, JSON.stringify(trimmed, null, 2));
        LOG.info('Scan snapshot saved to history.');
    } catch (err) {
        LOG.warn('Failed to save scan snapshot', err);
    }
}

function calculateOrgSecurityScoreValue(users) {
    if (!users || users.length === 0) return 0;
    const total = users.length;
    const mfaRate = users.filter(u => u.mfaEnrolled).length / total;
    const noExternalForwarding = users.filter(u => !u.forwardingExternal).length / total;
    const noHighRiskApps = users.filter(u => u.highRiskApps === 0).length / total;
    const noLegacyProtocols = users.filter(u => !u.popAccess && !u.imapAccess).length / total;
    const lowFailedLogins = users.filter(u => (u.failedLogins || 0) <= 5).length / total;
    const weights = { mfa: 0.35, forwarding: 0.20, apps: 0.20, protocols: 0.15, logins: 0.10 };
    return Math.round(
        (mfaRate * weights.mfa +
            noExternalForwarding * weights.forwarding +
            noHighRiskApps * weights.apps +
            noLegacyProtocols * weights.protocols +
            lowFailedLogins * weights.logins) * 100
    );
}

// --- Email Notifications ---
async function sendCriticalAlert(subject, htmlBody) {
    if (!mailTransporter || !process.env.ALERT_EMAIL_TO) return;
    try {
        await mailTransporter.sendMail({
            from: `"GWS Security Dashboard" <${process.env.SMTP_USER}>`,
            to: process.env.ALERT_EMAIL_TO,
            subject: `🚨 GWS Alert: ${subject}`,
            html: htmlBody,
        });
        LOG.info(`Critical alert email sent: ${subject}`);
    } catch (err) {
        LOG.error('Failed to send alert email', err);
    }
}

function checkAndNotifyCriticalFindings(scanData) {
    if (!mailTransporter) return;
    const users = scanData.users || [];
    const criticalFindings = [];

    const adminsWithoutMfa = users.filter(u => u.isAdmin && !u.mfaEnrolled);
    if (adminsWithoutMfa.length > 0) {
        criticalFindings.push(`<li><strong>${adminsWithoutMfa.length} admin account(s) without MFA:</strong> ${adminsWithoutMfa.map(u => u.primaryEmail).join(', ')}</li>`);
    }

    const externalForwarding = users.filter(u => u.forwardingExternal);
    if (externalForwarding.length > 0) {
        criticalFindings.push(`<li><strong>${externalForwarding.length} user(s) with external forwarding:</strong> ${externalForwarding.map(u => u.primaryEmail).join(', ')}</li>`);
    }

    const highFailedLogins = users.filter(u => (u.failedLogins || 0) > 10);
    if (highFailedLogins.length > 0) {
        criticalFindings.push(`<li><strong>${highFailedLogins.length} user(s) with >10 failed logins:</strong> ${highFailedLogins.map(u => u.primaryEmail).join(', ')}</li>`);
    }

    if (criticalFindings.length > 0) {
        const html = `
            <h2>GWS Security Dashboard — Critical Findings</h2>
            <p>A security scan completed at ${new Date().toISOString()} found the following critical issues:</p>
            <ul>${criticalFindings.join('')}</ul>
            <p>Please review and remediate these findings immediately.</p>
            <hr>
            <p style="color: #888; font-size: 12px;">This is an automated alert from GWS Security Dashboard.</p>
        `;
        sendCriticalAlert(`${criticalFindings.length} Critical Finding(s) Detected`, html);
    }
}

// --- Retry Wrapper for API Calls ---
async function withRetry(fn, retries = 3, delayMs = 1000, label = 'API call') {
    for (let attempt = 1; attempt <= retries; attempt++) {
        try {
            return await fn();
        } catch (err) {
            const isRetryable = err.code === 'ECONNRESET' ||
                err.code === 'ETIMEDOUT' ||
                (err.response && err.response.status >= 500) ||
                (err.response && err.response.status === 429);

            if (attempt < retries && isRetryable) {
                const wait = delayMs * Math.pow(2, attempt - 1);
                LOG.warn(`${label} failed (attempt ${attempt}/${retries}), retrying in ${wait}ms: ${err.message}`);
                await new Promise(r => setTimeout(r, wait));
            } else {
                throw err;
            }
        }
    }
}

// --- Input Validation Helpers ---
function validateEmail(email) {
    if (!email || typeof email !== 'string') return false;
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

function validateDomain(domain) {
    if (!domain || typeof domain !== 'string') return false;
    return /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$/.test(domain) && domain.length <= 253;
}

function sanitizeString(str, maxLen = 500) {
    if (!str || typeof str !== 'string') return '';
    return str.replace(/<[^>]*>?/gm, '').substring(0, maxLen).trim();
}

// --- Express App Setup ---
const app = express();

// Security headers via Helmet
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: [
                "'self'",
                "'unsafe-inline'",
                "https://cdn.tailwindcss.com",
                "https://cdn.jsdelivr.net",
                "https://cdnjs.cloudflare.com",
                "https://code.jquery.com",
                "https://cdn.datatables.net",
                "https://unpkg.com",
            ],
            styleSrc: [
                "'self'",
                "'unsafe-inline'",
                "https://fonts.googleapis.com",
                "https://cdn.datatables.net",
            ],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "blob:"],
            connectSrc: ["'self'"],
        },
    },
    crossOriginEmbedderPolicy: false,
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Rate limiters
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    message: { ok: false, error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
});

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 50,
    message: { ok: false, error: 'API rate limit exceeded. Please wait before trying again.' },
});

const aiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: { ok: false, error: 'AI rate limit exceeded. Please wait before trying again.' },
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: 'Too many login attempts. Please try again in 15 minutes.',
});

app.use(generalLimiter);

// Session store
const FileStore = require('session-file-store')(session);
app.use(session({
    store: new FileStore({
        path: path.join(__dirname, '.sessions'),
        ttl: 86400,
        retries: 0
    }),
    secret: APP_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// Auth middleware
const requireLogin = (req, res, next) => {
    if (appConfig && req.session.loggedIn) return next();
    res.redirect('/login');
};

const requireApiLogin = (req, res, next) => {
    if (appConfig && req.session.loggedIn) return next();
    res.status(401).json({ ok: false, error: 'Not authenticated' });
};

// --- Google Auth & API Logic ---
function tempJwtForSubject(config, subject, scopes = []) {
    const creds = config.serviceAccountCreds;
    return new google.auth.JWT({
        email: creds.client_email,
        key: creds.private_key,
        scopes,
        subject
    });
}

function jwtForSubject(subject, scopes = []) {
    if (!appConfig) throw new Error("Application is not configured.");
    return tempJwtForSubject(appConfig, subject, scopes);
}

async function testCredentials(config) {
    try {
        LOG.info('Testing new credentials...');
        const auth = tempJwtForSubject(config, config.adminUser, ['https://www.googleapis.com/auth/admin.directory.user.readonly']);
        const admin = google.admin({ version: 'directory_v1', auth });
        await admin.users.get({ userKey: config.adminUser });
        LOG.info('Credential test successful.');
        return true;
    } catch (err) {
        LOG.error({ msg: 'Credential test failed', error: err.message });
        return false;
    }
}

async function listAllUsers() {
    return withRetry(async () => {
        const auth = jwtForSubject(appConfig.adminUser, ['https://www.googleapis.com/auth/admin.directory.user.readonly']);
        await auth.authorize();
        const admin = google.admin({ version: 'directory_v1', auth });
        let users = [];
        let pageToken = null;
        do {
            const res = await admin.users.list({ customer: 'my_customer', maxResults: 100, orderBy: 'email', projection: 'full', pageToken });
            users = users.concat(res.data.users || []);
            pageToken = res.data.nextPageToken;
        } while (pageToken);
        LOG.info(`Fetched ${users.length} users.`);
        return users;
    }, 3, 2000, 'listAllUsers');
}

async function getAllAlerts(days = 30) {
    return withRetry(async () => {
        const auth = jwtForSubject(appConfig.adminUser, ['https://www.googleapis.com/auth/apps.alerts']);
        await auth.authorize();
        const alertcenter = google.alertcenter({ version: 'v1beta1', auth });
        const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
        const filter = `createTime >= "${since}"`;
        let alerts = [];
        let pageToken = null;
        do {
            const res = await alertcenter.alerts.list({ filter, pageSize: 100, pageToken });
            alerts = alerts.concat(res.data.alerts || []);
            pageToken = res.data.nextPageToken || null;
        } while (pageToken);
        LOG.info(`Fetched ${alerts.length} total alerts for the Alert Center.`);
        return alerts;
    }, 3, 2000, 'getAllAlerts');
}

async function listMobileDevices() {
    return withRetry(async () => {
        const auth = jwtForSubject(appConfig.adminUser, ['https://www.googleapis.com/auth/admin.directory.device.mobile.readonly']);
        await auth.authorize();
        const admin = google.admin({ version: 'directory_v1', auth });
        let devices = [];
        let pageToken = null;
        do {
            const res = await admin.mobiledevices.list({ customerId: 'my_customer', maxResults: 100, pageToken });
            devices = devices.concat(res.data.mobiledevices || []);
            pageToken = res.data.nextPageToken || null;
        } while (pageToken);
        return devices;
    }, 3, 2000, 'listMobileDevices');
}

async function getLoginEventsForUser(userEmail, days = 30) {
    const auth = jwtForSubject(appConfig.adminUser, ['https://www.googleapis.com/auth/admin.reports.audit.readonly']);
    await auth.authorize();
    const reports = google.admin({ version: 'reports_v1', auth });
    try {
        const res = await reports.activities.list({
            userKey: userEmail, applicationName: 'login',
            startTime: new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString(),
            maxResults: 100
        });
        let success = 0, failure = 0;
        (res.data.items || []).forEach(it => {
            (it.events || []).forEach(e => {
                const n = (e.name || '').toLowerCase();
                if (n.includes('login_success')) success++;
                if (n.includes('login_failure')) failure++;
            });
        });
        return { success, failure };
    } catch (err) { return { success: 0, failure: 0 }; }
}

async function getPasswordChangeFromBigQuery(email) {
    if (!appConfig || !appConfig.useBigQuery) return null;
    try {
        const bqClient = new BigQuery({
            projectId: appConfig.bigquery_project_id,
            credentials: appConfig.serviceAccountCreds
        });
        const query = `SELECT timestamp FROM \`${appConfig.bigquery_project_id}.${appConfig.bigquery_dataset_name}.cloudaudit_googleapis_com_activity_*\` WHERE protopayload_auditlog.authenticationInfo.principalEmail = @email AND protopayload_auditlog.methodName LIKE "%UpdateUser" ORDER BY timestamp DESC LIMIT 1`;
        const [rows] = await bqClient.query({ query, params: { email } });
        return rows.length > 0 ? rows[0].timestamp.value : null;
    } catch (err) {
        LOG.warn({ email, err: err.message }, "BigQuery password change query failed.");
        return null;
    }
}

async function getPasswordChangeFromReports(userEmail, days = 365) {
    const auth = jwtForSubject(appConfig.adminUser, ['https://www.googleapis.com/auth/admin.reports.audit.readonly']);
    await auth.authorize();
    const reports = google.admin({ version: 'reports_v1', auth });
    try {
        const res = await reports.activities.list({
            userKey: userEmail, applicationName: 'admin', eventName: 'CHANGE_PASSWORD',
            startTime: new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString(),
            maxResults: 1
        });
        return res.data.items?.[0]?.id?.time || null;
    } catch (err) { return null; }
}

async function getGmailSettingsForUser(userEmail) {
    const auth = jwtForSubject(userEmail, ['https://www.googleapis.com/auth/gmail.settings.basic']);
    await auth.authorize();
    const gmail = google.gmail({ version: 'v1', auth });
    const out = { forwardingEnabled: false, forwardingAddresses: [], forwardingExternal: false, imapEnabled: false, popEnabled: false, smtpAccessPresent: false, _error: null };
    try {
        const [auto, sa, imap, pop] = await Promise.allSettled([
            gmail.users.settings.getAutoForwarding({ userId: 'me' }),
            gmail.users.settings.sendAs.list({ userId: 'me' }),
            gmail.users.settings.getImap({ userId: 'me' }),
            gmail.users.settings.getPop({ userId: 'me' })
        ]);
        if (auto.status === 'fulfilled' && auto.value.data) {
            out.forwardingEnabled = !!auto.value.data.enabled;
        }
        if (sa.status === 'fulfilled' && sa.value.data.sendAs) {
            sa.value.data.sendAs.forEach(s => {
                if (s.smtpMsa) out.smtpAccessPresent = true;
            });
        }
        out.imapEnabled = imap.status === 'fulfilled' && !!imap.value.data.enabled;
        out.popEnabled = pop.status === 'fulfilled' && pop.value.data.accessWindow !== 'disabled';

        const fwdAddrsRes = await gmail.users.settings.forwardingAddresses.list({ userId: 'me' });
        if (fwdAddrsRes.data.forwardingAddresses) {
            out.forwardingAddresses = fwdAddrsRes.data.forwardingAddresses.map(a => a.forwardingEmail);
        }

        out.forwardingExternal = out.forwardingAddresses.some(addr => !addr.toLowerCase().endsWith(`@${appConfig.domain.toLowerCase()}`));
    } catch (err) { out._error = err.message; }
    return out;
}

async function getAdminRolesForUsers() {
    return withRetry(async () => {
        const auth = jwtForSubject(appConfig.adminUser, ['https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly']);
        await auth.authorize();
        const admin = google.admin({ version: 'directory_v1', auth });
        const assignmentsByEmail = {};
        try {
            const res = await admin.roleAssignments.list({ customer: 'my_customer' });
            (res.data.items || []).forEach(item => {
                if (item.scopeType === 'CUSTOMER') {
                    if (!assignmentsByEmail[item.assignedTo]) assignmentsByEmail[item.assignedTo] = [];
                    assignmentsByEmail[item.assignedTo].push('Admin Role');
                }
            });
        } catch (err) { LOG.error(`Failed to fetch role assignments: ${err.message}`); }
        return assignmentsByEmail;
    }, 3, 2000, 'getAdminRolesForUsers');
}

const HIGH_RISK_SCOPES = ['https://www.googleapis.com/auth/drive', 'https://www.googleapis.com/auth/gmail.modify', 'https://www.googleapis.com/auth/gmail.readonly', 'https://mail.google.com/'];
async function getThirdPartyAppsForUser(userEmail) {
    const auth = jwtForSubject(appConfig.adminUser, ['https://www.googleapis.com/auth/admin.directory.user.security']);
    await auth.authorize();
    const admin = google.admin({ version: 'directory_v1', auth });
    try {
        const res = await admin.tokens.list({ userKey: userEmail });
        const items = res.data.items || [];
        const highRiskApps = items.filter(token => (token.scopes || []).some(scope => HIGH_RISK_SCOPES.includes(scope)));
        return {
            appsCount: items.length,
            highRiskAppsCount: highRiskApps.length,
            allAppNames: items.map(app => app.displayText),
            highRiskSummary: highRiskApps.map(app => app.displayText).slice(0, 3).join(', ')
        };
    } catch (err) {
        return { error: err.message, appsCount: 0, highRiskAppsCount: 0, allAppNames: [], highRiskSummary: '' };
    }
}

async function getDomainEmailSettings(usersData) {
    const domain = appConfig.domain;
    const results = [];

    // 1. SPF Check
    try {
        const txtRecords = await dns.resolveTxt(domain);
        const spfRecord = txtRecords.find(r => r.join('').startsWith('v=spf1'))?.join('');
        if (spfRecord) {
            results.push({ name: 'Sender Policy Framework', status: 'Configured', type: 'good', details: `Record Found: ${spfRecord}` });
        } else {
            results.push({ name: 'Sender Policy Framework', status: 'Not Found', type: 'bad', details: 'No SPF record was found for your domain. This is a critical security risk.' });
        }
    } catch (e) {
        results.push({ name: 'Sender Policy Framework', status: 'Error', type: 'bad', details: `Could not perform DNS lookup for SPF: ${e.message}` });
    }

    // 2. DMARC Check
    try {
        const dmarcRecords = await dns.resolveTxt(`_dmarc.${domain}`);
        const dmarcRecord = dmarcRecords.find(r => r.join('').startsWith('v=DMARC1'))?.join('');
        if (dmarcRecord) {
            let status = 'Configured';
            let type = 'good';
            if (dmarcRecord.includes('p=reject')) {
                status = 'p=reject';
            } else if (dmarcRecord.includes('p=quarantine')) {
                status = 'p=quarantine';
                type = 'bad';
            } else {
                status = 'p=none';
                type = 'bad';
            }
            results.push({ name: 'Domain Based Message Authentication, Reporting, and Conformance', status, type, details: `Policy Found: ${dmarcRecord}` });
        } else {
            results.push({ name: 'Domain Based Message Authentication, Reporting, and Conformance', status: 'Not Found', type: 'bad', details: 'No DMARC record was found. This is a critical security risk.' });
        }
    } catch (e) {
        results.push({ name: 'Domain Based Message Authentication, Reporting, and Conformance', status: 'Error', type: 'bad', details: `Could not perform DNS lookup for DMARC: ${e.message}` });
    }

    // 3. DKIM Check
    try {
        await dns.resolveTxt(`google._domainkey.${domain}`);
        results.push({ name: 'DomainKeys Identified Mail', status: 'Configured', type: 'good', details: 'A DKIM record for the default Google selector was found.' });
    } catch (e) {
        results.push({ name: 'DomainKeys Identified Mail', status: 'Not Found', type: 'bad', details: `Could not find a DKIM record for the default "google" selector.` });
    }

    // 4. Aggregate user-level data
    const popImapUsers = usersData.filter(u => u.popAccess || u.imapAccess).length;
    const autoForwardingUsers = usersData.filter(u => u.forwardingEnabled).length;

    results.push({ name: 'POP and IMAP Access', status: `${popImapUsers} Users Enabled`, type: popImapUsers > 0 ? 'bad' : 'good', details: 'Live Data: Shows the total number of users with legacy POP or IMAP access enabled.' });
    results.push({ name: 'Automatic Forwarding', status: `${autoForwardingUsers} Users Forwarding`, type: autoForwardingUsers > 0 ? 'bad' : 'good', details: 'Live Data: Shows the total number of users with any kind of automatic email forwarding rule.' });

    return results;
}

// --- Data Collection with Graceful Error Handling ---
async function collectAll() {
    LOG.info('Starting full data collection');
    const errors = [];

    // Fetch primary data with individual error handling
    let users = [], allAlerts = [], mobileDevices = [], assignmentsByEmail = {};

    const results = await Promise.allSettled([
        listAllUsers(),
        getAllAlerts(),
        listMobileDevices(),
        getAdminRolesForUsers()
    ]);

    if (results[0].status === 'fulfilled') {
        users = results[0].value;
    } else {
        errors.push(`Failed to fetch users: ${results[0].reason?.message}`);
        LOG.error('listAllUsers failed', results[0].reason);
    }

    if (results[1].status === 'fulfilled') {
        allAlerts = results[1].value;
    } else {
        errors.push(`Failed to fetch alerts: ${results[1].reason?.message}`);
        LOG.error('getAllAlerts failed', results[1].reason);
    }

    if (results[2].status === 'fulfilled') {
        mobileDevices = results[2].value;
    } else {
        errors.push(`Failed to fetch mobile devices: ${results[2].reason?.message}`);
        LOG.error('listMobileDevices failed', results[2].reason);
    }

    if (results[3].status === 'fulfilled') {
        assignmentsByEmail = results[3].value;
    } else {
        errors.push(`Failed to fetch admin roles: ${results[3].reason?.message}`);
        LOG.error('getAdminRolesForUsers failed', results[3].reason);
    }

    if (users.length === 0) {
        throw new Error('Critical failure: Could not fetch any users. ' + errors.join('; '));
    }

    const securityAlerts = allAlerts.filter(a => a.type === 'Suspicious login' || a.type === 'Phishing');
    const alertsByEmail = securityAlerts.reduce((acc, a) => {
        (a.data?.affectedUserEmails || []).forEach(email => { (acc[email] = acc[email] || []).push({ type: a.type }); });
        return acc;
    }, {});

    const mobileByEmail = mobileDevices.reduce((acc, d) => {
        (d.email || []).forEach(email => { acc[email] = true; });
        return acc;
    }, {});

    const userResults = [];
    for (const [i, u] of users.entries()) {
        const email = u.primaryEmail;
        LOG.info({ i, email }, 'Processing user');

        try {
            const [gmailSettings, appsData, loginStats, twoFaEnrollmentDate] = await Promise.all([
                getGmailSettingsForUser(email),
                getThirdPartyAppsForUser(email),
                getLoginEventsForUser(email, 30),
                (async () => {
                    const auth = jwtForSubject(appConfig.adminUser, ['https://www.googleapis.com/auth/admin.reports.audit.readonly']);
                    try {
                        await auth.authorize();
                        const reports = google.admin({ version: 'reports_v1', auth });
                        const res = await reports.activities.list({ userKey: email, eventName: 'ENROLL_2SV', maxResults: 1 });
                        return res.data.items?.[0]?.id?.time || null;
                    } catch { return null; }
                })()
            ]);

            let passwordLastChanged = await getPasswordChangeFromBigQuery(email);
            if (!passwordLastChanged) {
                passwordLastChanged = await getPasswordChangeFromReports(email);
            }

            const userAlerts = alertsByEmail[email] || [];
            const userRoles = assignmentsByEmail[email] || [];

            const phones = u.phones || [];
            const recoveryPhone = phones.find(p => p.type === 'recovery')?.value || 'Not Set';
            const contactPhone = phones.find(p => p.type !== 'recovery')?.value || 'N/A';

            const record = {
                primaryEmail: email, name: u.name?.fullName || '', accountCreated: u.creationTime,
                lastLogin: u.lastLoginTime, isAdmin: !!u.isAdmin, adminRoles: u.isAdmin ? 'Super Admin' : userRoles.join(', ') || 'User',
                suspended: !!u.suspended,
                recoveryPhone: recoveryPhone,
                contactPhone: contactPhone,
                alertsEnabled: allAlerts.length > 0,
                mfaEnrolled: !!u.isEnrolledIn2Sv, mfaEnrollmentDate: twoFaEnrollmentDate, passwordLastChanged: passwordLastChanged,
                phishingAlerts: userAlerts.filter(a => a.type === 'Phishing').length, alertSummary: userAlerts.slice(0, 3).map(a => a.type).join(', '),
                unusualLogins: (loginStats.failure || 0) > 5, successfulLogins: loginStats.success || 0, failedLogins: loginStats.failure || 0,
                phishingSpamReports: null, authorizedApps: appsData.appsCount, appNames: appsData.allAppNames, highRiskApps: appsData.highRiskAppsCount,
                highRiskSummary: appsData.highRiskSummary, forwardingEnabled: gmailSettings.forwardingEnabled, forwardingAddresses: gmailSettings.forwardingAddresses.join(', '),
                forwardingExternal: gmailSettings.forwardingExternal, configError: gmailSettings._error || null, smtpAccess: gmailSettings.smtpAccessPresent,
                imapAccess: gmailSettings.imapEnabled, popAccess: gmailSettings.popEnabled, mobileAccess: !!mobileByEmail[email],
            };
            userResults.push(record);
        } catch (userErr) {
            LOG.error({ email, err: userErr.message }, 'Failed to process user, adding partial record');
            errors.push(`Failed to fully process ${email}: ${userErr.message}`);
            userResults.push({
                primaryEmail: email, name: u.name?.fullName || '', accountCreated: u.creationTime,
                lastLogin: u.lastLoginTime, isAdmin: !!u.isAdmin, adminRoles: 'Error',
                suspended: !!u.suspended, recoveryPhone: 'Error', contactPhone: 'Error',
                alertsEnabled: false, mfaEnrolled: !!u.isEnrolledIn2Sv, mfaEnrollmentDate: null,
                passwordLastChanged: null, phishingAlerts: 0, alertSummary: '', unusualLogins: false,
                successfulLogins: 0, failedLogins: 0, phishingSpamReports: null, authorizedApps: 0,
                appNames: [], highRiskApps: 0, highRiskSummary: '', forwardingEnabled: false,
                forwardingAddresses: '', forwardingExternal: false, configError: userErr.message,
                smtpAccess: false, imapAccess: false, popAccess: false, mobileAccess: false,
            });
        }
    }

    const domainEmailSettings = await getDomainEmailSettings(userResults);

    return {
        users: userResults, alerts: allAlerts, totalAlertCount: allAlerts.length,
        domainEmailSettings, errors: errors.length > 0 ? errors : undefined
    };
}

// --- Risk Scoring Engine ---
function calculateUserRiskScore(user) {
    let score = 0;
    const factors = [];

    if (!user.mfaEnrolled) {
        const weight = user.isAdmin ? 30 : 20;
        score += weight;
        factors.push({ factor: `MFA not enabled${user.isAdmin ? ' (ADMIN account)' : ''}`, weight, severity: 'critical' });
    }

    if (user.forwardingExternal) {
        score += 20;
        factors.push({ factor: `External email forwarding active to: ${user.forwardingAddresses || 'unknown'}`, weight: 20, severity: 'high' });
    } else if (user.forwardingEnabled) {
        score += 5;
        factors.push({ factor: 'Internal forwarding enabled', weight: 5, severity: 'low' });
    }

    if (user.highRiskApps > 0) {
        const weight = Math.min(user.highRiskApps * 5, 15);
        score += weight;
        factors.push({ factor: `${user.highRiskApps} high-risk OAuth apps connected`, weight, severity: user.highRiskApps >= 3 ? 'high' : 'medium' });
    }

    if (user.failedLogins > 10) {
        score += 15;
        factors.push({ factor: `High failed login attempts: ${user.failedLogins}`, weight: 15, severity: 'high' });
    } else if (user.failedLogins > 5) {
        score += 8;
        factors.push({ factor: `Elevated failed login attempts: ${user.failedLogins}`, weight: 8, severity: 'medium' });
    }

    if (user.popAccess || user.imapAccess) {
        score += 10;
        factors.push({ factor: `Legacy protocols enabled (POP: ${user.popAccess ? 'Yes' : 'No'}, IMAP: ${user.imapAccess ? 'Yes' : 'No'})`, weight: 10, severity: 'medium' });
    }

    if (user.phishingAlerts > 0) {
        const weight = Math.min(user.phishingAlerts * 5, 15);
        score += weight;
        factors.push({ factor: `${user.phishingAlerts} phishing alert(s) in last 30 days`, weight, severity: 'high' });
    }

    if (user.passwordLastChanged) {
        const daysSinceChange = Math.floor((Date.now() - new Date(user.passwordLastChanged).getTime()) / (1000 * 60 * 60 * 24));
        if (daysSinceChange > 180) {
            score += 10;
            factors.push({ factor: `Password unchanged for ${daysSinceChange} days`, weight: 10, severity: 'medium' });
        } else if (daysSinceChange > 90) {
            score += 5;
            factors.push({ factor: `Password unchanged for ${daysSinceChange} days`, weight: 5, severity: 'low' });
        }
    }

    if (user.suspended) {
        score = Math.max(score - 20, 0);
        factors.push({ factor: 'Account is suspended (risk reduced)', weight: -20, severity: 'info' });
    }

    score = Math.min(score, 100);

    let riskLevel = 'LOW';
    if (score >= 70) riskLevel = 'CRITICAL';
    else if (score >= 50) riskLevel = 'HIGH';
    else if (score >= 25) riskLevel = 'MEDIUM';

    return { riskScore: score, riskLevel, factors };
}

function calculateOrgSecurityScore(users) {
    if (!users || users.length === 0) return { score: 0, grade: 'N/A', breakdown: {} };

    const total = users.length;
    const mfaRate = users.filter(u => u.mfaEnrolled).length / total;
    const noExternalForwarding = users.filter(u => !u.forwardingExternal).length / total;
    const noHighRiskApps = users.filter(u => u.highRiskApps === 0).length / total;
    const noLegacyProtocols = users.filter(u => !u.popAccess && !u.imapAccess).length / total;
    const lowFailedLogins = users.filter(u => (u.failedLogins || 0) <= 5).length / total;

    const weights = { mfa: 0.35, forwarding: 0.20, apps: 0.20, protocols: 0.15, logins: 0.10 };
    const score = Math.round(
        (mfaRate * weights.mfa +
            noExternalForwarding * weights.forwarding +
            noHighRiskApps * weights.apps +
            noLegacyProtocols * weights.protocols +
            lowFailedLogins * weights.logins) * 100
    );

    let grade = 'F';
    if (score >= 90) grade = 'A';
    else if (score >= 80) grade = 'B';
    else if (score >= 70) grade = 'C';
    else if (score >= 60) grade = 'D';

    return {
        score, grade,
        breakdown: {
            mfaAdoption: Math.round(mfaRate * 100),
            forwardingSecurity: Math.round(noExternalForwarding * 100),
            appSecurity: Math.round(noHighRiskApps * 100),
            protocolSecurity: Math.round(noLegacyProtocols * 100),
            loginSecurity: Math.round(lowFailedLogins * 100),
        },
        criticalUsers: users.filter(u => calculateUserRiskScore(u).riskLevel === 'CRITICAL').length,
        highRiskUsers: users.filter(u => calculateUserRiskScore(u).riskLevel === 'HIGH').length,
    };
}

// --- CIS Benchmark Compliance Mapping ---
function generateCISCompliance(users) {
    if (!users || users.length === 0) return [];
    const total = users.length;

    return [
        {
            id: 'CIS-1.1',
            benchmark: 'CIS Google Workspace Benchmark v1.0',
            control: 'Ensure MFA is enforced for all users',
            category: 'Identity & Access',
            status: users.every(u => u.mfaEnrolled || u.suspended) ? 'PASS' : 'FAIL',
            compliant: users.filter(u => u.mfaEnrolled || u.suspended).length,
            total,
            percentage: Math.round(users.filter(u => u.mfaEnrolled || u.suspended).length / total * 100),
            violators: users.filter(u => !u.mfaEnrolled && !u.suspended).map(u => u.primaryEmail),
            severity: 'CRITICAL',
            remediation: 'Enable 2-Step Verification enforcement in Admin Console > Security > Authentication > 2-Step Verification',
        },
        {
            id: 'CIS-1.2',
            benchmark: 'CIS Google Workspace Benchmark v1.0',
            control: 'Ensure MFA is enforced for all admin users',
            category: 'Identity & Access',
            status: users.filter(u => u.isAdmin).every(u => u.mfaEnrolled) ? 'PASS' : 'FAIL',
            compliant: users.filter(u => u.isAdmin && u.mfaEnrolled).length,
            total: users.filter(u => u.isAdmin).length,
            percentage: users.filter(u => u.isAdmin).length > 0 ? Math.round(users.filter(u => u.isAdmin && u.mfaEnrolled).length / users.filter(u => u.isAdmin).length * 100) : 100,
            violators: users.filter(u => u.isAdmin && !u.mfaEnrolled).map(u => u.primaryEmail),
            severity: 'CRITICAL',
            remediation: 'Immediately enforce MFA for all admin accounts. Go to Admin Console > Directory > Users > Select admin user > Security > Turn on 2-Step Verification',
        },
        {
            id: 'CIS-2.1',
            benchmark: 'CIS Google Workspace Benchmark v1.0',
            control: 'Ensure email auto-forwarding to external domains is disabled',
            category: 'Email Security',
            status: users.every(u => !u.forwardingExternal) ? 'PASS' : 'FAIL',
            compliant: users.filter(u => !u.forwardingExternal).length,
            total,
            percentage: Math.round(users.filter(u => !u.forwardingExternal).length / total * 100),
            violators: users.filter(u => u.forwardingExternal).map(u => u.primaryEmail),
            severity: 'HIGH',
            remediation: 'Disable auto-forwarding: Admin Console > Apps > Google Workspace > Gmail > Compliance > Auto-forwarding',
        },
        {
            id: 'CIS-2.2',
            benchmark: 'CIS Google Workspace Benchmark v1.0',
            control: 'Ensure POP and IMAP access is disabled for all users',
            category: 'Email Security',
            status: users.every(u => !u.popAccess && !u.imapAccess) ? 'PASS' : 'FAIL',
            compliant: users.filter(u => !u.popAccess && !u.imapAccess).length,
            total,
            percentage: Math.round(users.filter(u => !u.popAccess && !u.imapAccess).length / total * 100),
            violators: users.filter(u => u.popAccess || u.imapAccess).map(u => u.primaryEmail),
            severity: 'MEDIUM',
            remediation: 'Disable POP/IMAP: Admin Console > Apps > Google Workspace > Gmail > End User Access > POP and IMAP access',
        },
        {
            id: 'CIS-3.1',
            benchmark: 'CIS Google Workspace Benchmark v1.0',
            control: 'Ensure no high-risk third-party apps have OAuth access',
            category: 'Application Security',
            status: users.every(u => u.highRiskApps === 0) ? 'PASS' : 'FAIL',
            compliant: users.filter(u => u.highRiskApps === 0).length,
            total,
            percentage: Math.round(users.filter(u => u.highRiskApps === 0).length / total * 100),
            violators: users.filter(u => u.highRiskApps > 0).map(u => u.primaryEmail),
            severity: 'HIGH',
            remediation: 'Review and revoke risky apps: Admin Console > Security > API Controls > App Access Control',
        },
        {
            id: 'CIS-4.1',
            benchmark: 'CIS Google Workspace Benchmark v1.0',
            control: 'Ensure failed login attempts are below threshold',
            category: 'Monitoring & Detection',
            status: users.every(u => (u.failedLogins || 0) <= 5) ? 'PASS' : 'FAIL',
            compliant: users.filter(u => (u.failedLogins || 0) <= 5).length,
            total,
            percentage: Math.round(users.filter(u => (u.failedLogins || 0) <= 5).length / total * 100),
            violators: users.filter(u => (u.failedLogins || 0) > 5).map(u => u.primaryEmail),
            severity: 'MEDIUM',
            remediation: 'Investigate users with high failed logins. Consider enabling account lockout policies. Review Alert Center for suspicious login alerts.',
        },
    ];
}

// --- Groq AI Service Functions ---
async function askGroq(systemPrompt, userMessage) {
    if (!groqClient) {
        return { error: 'AI is not configured. Please add GROQ_API_KEY to your .env file.' };
    }
    try {
        const completion = await groqClient.chat.completions.create({
            model: 'llama-3.3-70b-versatile',
            messages: [
                { role: 'system', content: systemPrompt },
                { role: 'user', content: userMessage },
            ],
            temperature: 0.3,
            max_tokens: 2048,
        });
        return { response: completion.choices[0].message.content };
    } catch (err) {
        LOG.error({ msg: 'Groq AI request failed', error: err.message });
        return { error: `AI request failed: ${err.message}` };
    }
}

function buildSecurityContext(users) {
    if (!users || users.length === 0) return 'No user data available.';
    const orgScore = calculateOrgSecurityScore(users);
    const usersWithRisk = users.map(u => {
        const risk = calculateUserRiskScore(u);
        return {
            email: u.primaryEmail, isAdmin: u.isAdmin, mfaEnrolled: u.mfaEnrolled,
            riskScore: risk.riskScore, riskLevel: risk.riskLevel,
            forwardingExternal: u.forwardingExternal, highRiskApps: u.highRiskApps,
            failedLogins: u.failedLogins, popAccess: u.popAccess, imapAccess: u.imapAccess,
            suspended: u.suspended,
        };
    });
    return JSON.stringify({ organizationScore: orgScore, totalUsers: users.length, users: usersWithRisk }, null, 2);
}

// --- Cron Job Management ---
function scheduleCronJob(scheduleString) {
    if (cronTask) {
        cronTask.stop();
        LOG.info('Stopped existing cron job.');
    }
    if (scheduleString && cron.validate(scheduleString)) {
        cronTask = cron.schedule(scheduleString, runAndCacheData, {
            timezone: TIMEZONE
        });
        LOG.info(`New cron job scheduled with pattern: ${scheduleString} in timezone ${TIMEZONE}`);
    } else {
        LOG.warn('Cron job not scheduled due to invalid or missing schedule string.');
    }
}

async function runAndCacheData() {
    if (!appConfig) {
        LOG.warn('Cannot run scheduled check, application is not configured.');
        return;
    }
    LOG.info('Executing scheduled data collection...');
    auditLog('SCHEDULED_SCAN_START');
    try {
        const data = await collectAll();
        cachedData = { ok: true, ts: new Date().toISOString(), currentUser: appConfig.adminUser, ...data };
        saveScanSnapshot(data);
        checkAndNotifyCriticalFindings(data);
        LOG.info(`Cache updated successfully. Found ${data.users.length} users.`);
        auditLog('SCHEDULED_SCAN_COMPLETE', { usersFound: data.users.length });
    } catch (err) {
        LOG.error('Failed to run scheduled check:', err);
        auditLog('SCHEDULED_SCAN_FAILED', { error: err.message });
    }
}

// --- Routes ---

// Login page — publicly accessible
app.get('/login', (req, res) => {
    if (appConfig && req.session.loggedIn) {
        return res.redirect('/');
    }
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Login POST — rate limited + admin password required
app.post('/login', loginLimiter, async (req, res) => {
    const {
        adminPassword, adminUser, domain, project_id, private_key_id, private_key,
        client_email, client_id, useBigQuery,
        bigquery_project_id, bigquery_dataset_name
    } = req.body;

    // Validate admin password
    if (!adminPassword || adminPassword !== ADMIN_PASSWORD) {
        auditLog('LOGIN_FAILED', { reason: 'Invalid admin password' }, req);
        return res.redirect('/login?error=password');
    }

    // Input validation
    if (!validateEmail(adminUser)) {
        auditLog('LOGIN_FAILED', { reason: 'Invalid admin email' }, req);
        return res.redirect('/login?error=validation');
    }
    if (!validateDomain(domain)) {
        auditLog('LOGIN_FAILED', { reason: 'Invalid domain' }, req);
        return res.redirect('/login?error=validation');
    }
    if (!client_email || !private_key || !project_id) {
        auditLog('LOGIN_FAILED', { reason: 'Missing required fields' }, req);
        return res.redirect('/login?error=validation');
    }

    const formattedPrivateKey = private_key.replace(/\\n/g, '\n');

    const serviceAccountCreds = {
        type: "service_account", project_id, private_key_id,
        private_key: formattedPrivateKey, client_email, client_id,
        auth_uri: "https://accounts.google.com/o/oauth2/auth",
        token_uri: "https://oauth2.googleapis.com/token",
        auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
        client_x509_cert_url: `https://www.googleapis.com/robot/v1/metadata/x509/${encodeURIComponent(client_email)}`,
        universe_domain: "googleapis.com"
    };

    const tempConfig = {
        adminUser, domain, serviceAccountCreds,
        useBigQuery: !!useBigQuery,
        bigquery_project_id: useBigQuery ? bigquery_project_id : null,
        bigquery_dataset_name: useBigQuery ? bigquery_dataset_name : null
    };

    const isValid = await testCredentials(tempConfig);

    if (isValid) {
        saveConfig(tempConfig);
        req.session.loggedIn = true;
        auditLog('LOGIN_SUCCESS', { adminUser }, req);
        res.redirect('/');
    } else {
        auditLog('LOGIN_FAILED', { reason: 'Credential validation failed', adminUser }, req);
        res.redirect('/login?error=1');
    }
});

app.get('/logout', (req, res) => {
    auditLog('LOGOUT', {}, req);
    req.session.destroy(err => {
        if (err) return res.redirect('/');
        res.clearCookie('connect.sid');
        res.redirect('/login');
    });
});

// Protected routes — auth check BEFORE static files
app.get('/', requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Static files — login page assets are public, dashboard assets require auth
app.use('/login.html', express.static(path.join(__dirname, 'public', 'login.html')));
app.use('/sop steps', express.static(path.join(__dirname, 'public', 'sop steps')));
app.use('/sop%20steps', express.static(path.join(__dirname, 'public', 'sop steps')));
app.use('/images', express.static(path.join(__dirname, 'public', 'images')));
app.use(requireLogin, express.static(path.join(__dirname, 'public')));

// --- API Routes (rate limited) ---
app.get('/api/run', apiLimiter, requireApiLogin, async (req, res) => {
    auditLog('MANUAL_SCAN_START', {}, req);
    try {
        const out = await collectAll();
        cachedData = { ok: true, ts: new Date().toISOString(), currentUser: appConfig.adminUser, ...out };
        saveScanSnapshot(out);
        checkAndNotifyCriticalFindings(out);
        auditLog('MANUAL_SCAN_COMPLETE', { usersFound: out.users.length }, req);
        res.json(cachedData);
    } catch (err) {
        LOG.error(err);
        auditLog('MANUAL_SCAN_FAILED', { error: err.message }, req);
        res.status(500).json({ ok: false, error: err.message || String(err) });
    }
});

app.get('/api/latest', requireApiLogin, (req, res) => {
    if (cachedData) return res.json(cachedData);
    res.status(404).json({ ok: false, error: 'No data has been cached yet. Please run a scan.' });
});

// --- Scan History API ---
app.get('/api/history', requireApiLogin, (req, res) => {
    const history = loadScanHistory();
    res.json({ ok: true, history });
});

// --- CIS Compliance API ---
app.get('/api/cis-compliance', requireApiLogin, (req, res) => {
    if (!cachedData || !cachedData.users) {
        return res.status(404).json({ ok: false, error: 'No scan data available. Please run a scan first.' });
    }
    const compliance = generateCISCompliance(cachedData.users);
    const passCount = compliance.filter(c => c.status === 'PASS').length;
    res.json({
        ok: true,
        framework: 'CIS Google Workspace Benchmark v1.0',
        overallCompliance: Math.round(passCount / compliance.length * 100),
        passCount,
        failCount: compliance.length - passCount,
        totalControls: compliance.length,
        controls: compliance,
    });
});

// --- Settings API Endpoints ---
app.get('/api/config/view', requireApiLogin, (req, res) => {
    if (!appConfig) return res.status(404).json({ error: 'Config not found' });
    res.json({
        adminUser: appConfig.adminUser,
        domain: appConfig.domain,
        projectId: appConfig.serviceAccountCreds.project_id,
        clientEmail: appConfig.serviceAccountCreds.client_email,
        useBigQuery: appConfig.useBigQuery,
        bigQueryProjectId: appConfig.bigquery_project_id,
        bigQueryDatasetName: appConfig.bigquery_dataset_name,
        timezone: TIMEZONE,
    });
});

app.get('/api/schedule', requireApiLogin, (req, res) => {
    res.json({
        enabled: !!appConfig.schedule?.enabled,
        time: appConfig.schedule?.time || '02:00',
        timezone: TIMEZONE,
    });
});

app.post('/api/schedule', apiLimiter, requireApiLogin, (req, res) => {
    const { enabled, time } = req.body;
    if (typeof enabled !== 'boolean' || (enabled && typeof time !== 'string')) {
        return res.status(400).json({ error: 'Invalid schedule data' });
    }

    appConfig.schedule = { enabled, time };

    let cronPattern = null;
    if (enabled && time) {
        const parts = time.split(':');
        if (parts.length !== 2 || isNaN(parts[0]) || isNaN(parts[1])) {
            return res.status(400).json({ error: 'Invalid time format. Use HH:MM.' });
        }
        const [hour, minute] = parts;
        cronPattern = `${minute} ${hour} * * *`;
    }

    scheduleCronJob(cronPattern);
    saveConfig(appConfig);
    auditLog('SCHEDULE_UPDATED', { enabled, time }, req);
    res.json({ ok: true, message: 'Schedule updated' });
});

// --- AI API Endpoints (rate limited) ---
app.get('/api/ai/status', requireApiLogin, (req, res) => {
    res.json({ enabled: !!groqClient, model: 'llama-3.3-70b-versatile', provider: 'Groq' });
});

app.get('/api/security-score', requireApiLogin, (req, res) => {
    if (!cachedData || !cachedData.users) {
        return res.status(404).json({ ok: false, error: 'No scan data available. Please run a scan first.' });
    }
    const users = cachedData.users;
    const orgScore = calculateOrgSecurityScore(users);
    const userScores = users.map(u => {
        const risk = calculateUserRiskScore(u);
        return {
            email: u.primaryEmail, name: u.name, isAdmin: u.isAdmin,
            riskScore: risk.riskScore, riskLevel: risk.riskLevel, factors: risk.factors,
        };
    }).sort((a, b) => b.riskScore - a.riskScore);

    res.json({ ok: true, orgScore, userScores });
});

app.post('/api/ai/chat', aiLimiter, requireApiLogin, express.json(), async (req, res) => {
    const { message } = req.body;
    if (!message) return res.status(400).json({ ok: false, error: 'Message is required.' });

    // Input validation
    const sanitizedMessage = sanitizeString(message, 2000);
    if (sanitizedMessage.length === 0) {
        return res.status(400).json({ ok: false, error: 'Message cannot be empty.' });
    }

    auditLog('AI_CHAT', { messageLength: sanitizedMessage.length }, req);

    const securityContext = cachedData ? buildSecurityContext(cachedData.users) : 'No scan data available yet.';
    const systemPrompt = `You are an AI security analyst for Google Workspace. You have access to real-time security data from the organization's GWS environment. Respond concisely and helpfully. Use the security data provided to answer questions accurately. Format your responses with markdown for readability. When listing users, use tables or bullet points.

CURRENT SECURITY DATA:
${securityContext}`;

    const result = await askGroq(systemPrompt, sanitizedMessage);
    if (result.error) return res.status(500).json({ ok: false, error: result.error });
    res.json({ ok: true, response: result.response });
});

app.post('/api/ai/analyze', aiLimiter, requireApiLogin, async (req, res) => {
    if (!cachedData || !cachedData.users) {
        return res.status(404).json({ ok: false, error: 'No scan data. Run a scan first.' });
    }
    auditLog('AI_ANALYSIS_START', {}, req);
    const securityContext = buildSecurityContext(cachedData.users);
    const systemPrompt = `You are a Chief Information Security Officer (CISO) AI assistant specialized in Google Workspace security. Analyze the complete security posture data provided and generate a comprehensive security analysis report.`;
    const userMessage = `Analyze this Google Workspace security data and provide:
1. **Executive Summary** - A brief 2-3 sentence overview of the security posture
2. **Critical Findings** - Top security issues that need immediate attention
3. **Risk Assessment** - Breakdown of risks by category (Identity, Email, Apps, Protocols)
4. **Top 5 Recommendations** - Prioritized actionable recommendations
5. **Compliance Gaps** - Any policy violations or compliance concerns

SECURITY DATA:
${securityContext}`;

    const result = await askGroq(systemPrompt, userMessage);
    if (result.error) return res.status(500).json({ ok: false, error: result.error });
    res.json({ ok: true, analysis: result.response, timestamp: new Date().toISOString() });
});

app.post('/api/ai/compliance', aiLimiter, requireApiLogin, async (req, res) => {
    if (!cachedData || !cachedData.users) {
        return res.status(404).json({ ok: false, error: 'No scan data. Run a scan first.' });
    }
    auditLog('AI_COMPLIANCE_CHECK', {}, req);
    const securityContext = buildSecurityContext(cachedData.users);
    const systemPrompt = `You are a compliance auditor AI for Google Workspace. Check compliance against industry best practices and security policies.`;
    const userMessage = `Based on this security data, generate a compliance report checking against these policies:

**Policy 1: MFA Enforcement** - All users, especially admins, must have MFA enabled
**Policy 2: No External Forwarding** - Email auto-forwarding to external domains should be disabled
**Policy 3: Legacy Protocol Restriction** - POP3 and IMAP should be disabled for all users
**Policy 4: App Access Control** - No high-risk third-party apps should be authorized
**Policy 5: Login Security** - Users with more than 5 failed logins should be flagged

For each policy, report:
- Compliance status (percentage compliant)
- List of violating users
- Recommended remediation actions

SECURITY DATA:
${securityContext}`;

    const result = await askGroq(systemPrompt, userMessage);
    if (result.error) return res.status(500).json({ ok: false, error: result.error });
    res.json({ ok: true, complianceReport: result.response, timestamp: new Date().toISOString() });
});

app.get('/api/ai/recommendations', aiLimiter, requireApiLogin, async (req, res) => {
    if (!cachedData || !cachedData.users) {
        return res.status(404).json({ ok: false, error: 'No scan data. Run a scan first.' });
    }
    auditLog('AI_RECOMMENDATIONS', {}, req);
    const securityContext = buildSecurityContext(cachedData.users);
    const systemPrompt = `You are a Google Workspace security advisor AI. Generate actionable, prioritized security recommendations.`;
    const userMessage = `Based on this security data, provide the top 10 security recommendations. For each recommendation:
- **Priority**: Critical / High / Medium / Low
- **Category**: Identity, Email, Apps, or Infrastructure
- **Action**: What specifically needs to be done
- **Impact**: What risk this mitigates
- **Affected Users**: Which users this applies to (list emails)

SECURITY DATA:
${securityContext}`;

    const result = await askGroq(systemPrompt, userMessage);
    if (result.error) return res.status(500).json({ ok: false, error: result.error });
    res.json({ ok: true, recommendations: result.response, timestamp: new Date().toISOString() });
});

// --- Audit Log Viewer API ---
app.get('/api/audit-log', requireApiLogin, (req, res) => {
    try {
        if (!fs.existsSync(AUDIT_LOG_PATH)) {
            return res.json({ ok: true, entries: [] });
        }
        const raw = fs.readFileSync(AUDIT_LOG_PATH, 'utf8');
        const entries = raw.trim().split('\n')
            .filter(line => line.trim())
            .map(line => {
                try { return JSON.parse(line); } catch { return null; }
            })
            .filter(Boolean)
            .reverse()
            .slice(0, 100); // Last 100 entries
        res.json({ ok: true, entries });
    } catch (err) {
        res.status(500).json({ ok: false, error: 'Failed to read audit log.' });
    }
});

// --- Server Start ---
app.listen(PORT, () => {
    appConfig = loadConfig();
    if (appConfig) {
        LOG.info(`GWS Dashboard running at http://localhost:${PORT}`);
        if (appConfig.schedule?.enabled && appConfig.schedule.time) {
            const [hour, minute] = appConfig.schedule.time.split(':');
            const cronPattern = `${minute} ${hour} * * *`;
            scheduleCronJob(cronPattern);
        }
    } else {
        LOG.warn(`Configuration not found or APP_SECRET changed. Please set up at http://localhost:${PORT}/login`);
    }
    auditLog('SERVER_START', { port: PORT, configLoaded: !!appConfig });
});