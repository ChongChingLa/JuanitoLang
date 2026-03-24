// index.js
require('dotenv').config();

console.log("EMAIL_USER =", process.env.EMAIL_USER ? "ok" : "missing");
console.log("EMAIL_PASS =", process.env.EMAIL_PASS ? "ok" : "missing");
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');

const app = express();
const port = 3000;
const dbFile = 'expense_credit_tracker.db';

// ---------------- CONFIG & MIDDLEWARE ----------------
app.use(express.json());
app.use(express.static(__dirname));

app.use(session({
    secret: 'your-secret-key-change-this-later-2026',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

// ---------------- DATABASE CONNECTION ----------------
const db = new sqlite3.Database(dbFile, (err) => {
    if (err) {
        console.error('Database connection failed:', err.message);
        process.exit(1);
    }
    console.log('Connected to database.');
});

// ---------------- DATABASE SETUP & SEEDING ----------------
db.serialize(() => {
    // Users table
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            usersID       INTEGER PRIMARY KEY AUTOINCREMENT,
            email         TEXT NOT NULL UNIQUE,
            name          TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user', 'admin')),
            created_at    TEXT DEFAULT (datetime('now'))
        )
    `);

    const adminEmail = "admin@gmail.com";
    const adminPassword = "adminadmin";
    const adminName = "Administrator";

    db.get("SELECT * FROM users WHERE role = 'admin'", async (err, row) => {
        if (err) return console.error("Admin check failed:", err.message);
        if (!row) {
            const hash = await bcrypt.hash(adminPassword, 10);
            db.run(
                "INSERT INTO users (email, name, password_hash, role) VALUES (?, ?, ?, 'admin')",
                [adminEmail, adminName, hash],
                (err) => {
                    if (err) console.error("Failed to create admin:", err.message);
                    else console.log(`Admin seeded: ${adminEmail} / ${adminPassword}`);
                }
            );
        }
    });

    // Expenses table
    db.run(`
        CREATE TABLE IF NOT EXISTS expenses (
            expensesID    INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id       INTEGER NOT NULL,
            description   TEXT NOT NULL,
            category      TEXT NOT NULL,
            amount        REAL NOT NULL,
            date          TEXT NOT NULL,
            status        TEXT NOT NULL,
            created_at    TEXT DEFAULT (datetime('now'))
        )
    `);
    db.run(`CREATE INDEX IF NOT EXISTS idx_expenses_user_id ON expenses(user_id)`);

    // Credits table
    db.run(`
        CREATE TABLE IF NOT EXISTS credits (
            creditID        INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id         INTEGER NOT NULL,
            customerName    TEXT NOT NULL,
            description     TEXT NOT NULL,
            originalAmount  REAL NOT NULL,
            remainingAmount REAL NOT NULL,
            dateBorrowed    TEXT NOT NULL,
            dueDate         TEXT NOT NULL,
            status          TEXT NOT NULL,
            paidDate        TEXT
        )
    `);
    db.run(`CREATE INDEX IF NOT EXISTS idx_credits_user_id ON credits(user_id)`);

    // OTP table
    db.run(`
        CREATE TABLE IF NOT EXISTS otps (
            email TEXT PRIMARY KEY,
            otp TEXT,
            expires_at INTEGER
        )
    `);
});

// ---------------- HELPER FUNCTIONS ----------------
function calculateStatus(date) {
    const expenseDate = new Date(date);
    const today = new Date();
    expenseDate.setHours(0,0,0,0);
    today.setHours(0,0,0,0);
    return expenseDate > today ? "Unpaid" : "Overdue";
}

function generateOTP(length = 6) {
    let otp = '';
    for (let i = 0; i < length; i++) otp += Math.floor(Math.random() * 10);
    return otp;
}

// ---------------- MAILER ----------------
const { sendOTP } = require('./mailer'); // Uses your mailer.js

// ---------------- AUTH MIDDLEWARE ----------------
function requireAuth(req, res, next) {
    if (!req.session.userId) return res.status(401).json({ error: 'Please log in' });
    req.userId = req.session.userId;
    next();
}

function requireAdmin(req, res, next) {
    if (!req.session.userId) return res.status(401).json({ error: 'Please log in' });
    db.get("SELECT role FROM users WHERE usersID = ?", [req.session.userId], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row || row.role !== 'admin') return res.status(403).json({ error: 'Admin access only' });
        next();
    });
}

// ---------------- AUTH ROUTES ----------------
app.get('/api/user', (req, res) => {
    if (!req.session.name) return res.sendStatus(401);
    res.json({ name: req.session.name });
});

app.post('/api/register', async (req, res) => {
    const { email, password, name } = req.body;
    if (!email || !password || !name) return res.status(400).json({ error: 'Missing fields' });
    if (password.length < 6) return res.status(400).json({ error: 'Password too short' });

    const hash = await bcrypt.hash(password, 10);

    db.run(
        "INSERT INTO users (email, name, password_hash, role) VALUES (?, ?, ?, 'user')",
        [email, name, hash],
        function(err) {
            if (err) {
                if (err.message.includes('UNIQUE')) return res.status(409).json({ error: 'Email taken' });
                return res.status(500).json({ error: 'Database error' });
            }
            req.session.userId = this.lastID;
            req.session.name = name;
            res.json({ success: true });
        }
    );
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Missing fields' });

    db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
        if (err || !user) return res.status(401).json({ error: 'Wrong e-mail or password' });
        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) return res.status(401).json({ error: 'Wrong e-mail or password' });

        req.session.userId = user.usersID;
        req.session.name = user.name;
        res.json({ success: true });
    });
});

app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.status(500).json({ error: 'Logout failed' });
        res.clearCookie('connect.sid');
        res.sendStatus(200);
    });
});

// ---------------- FORGOT PASSWORD / OTP ----------------
app.post('/api/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: 'Email required' });

        // Check if user exists
        const user = await new Promise((resolve, reject) => {
            db.get("SELECT * FROM users WHERE email = ?", [email], (err, row) => {
                if (err) return reject(err);
                resolve(row);
            });
        });

        if (!user) return res.status(404).json({ error: 'User not found' });

        // Generate OTP and expiration
        const otp = generateOTP();
        const expires = Date.now() + 5 * 60 * 1000; // 5 minutes

        // Insert or update OTP in DB
        await new Promise((resolve, reject) => {
            db.run(
                "INSERT OR REPLACE INTO otps (email, otp, expires_at) VALUES (?, ?, ?)",
                [email, otp, expires],
                (err) => (err ? reject(err) : resolve())
            );
        });

        // Send OTP via SendGrid
        await sendOTP(email, otp);

        console.log(`✅ OTP generated and sent to ${email}`);
        res.json({ success: true });

    } catch (err) {
        console.error("❌ Forgot-password error:", err.message);
        res.status(500).json({ error: 'Failed to send OTP' });
    }
});

app.post('/api/verify-otp', (req, res) => {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ error: 'Email and OTP required' });

    db.get("SELECT * FROM otps WHERE email = ? AND otp = ?", [email, otp], (err, row) => {
        if (err || !row) return res.status(400).json({ error: 'Invalid OTP' });
        if (Date.now() > row.expires_at) return res.status(400).json({ error: 'OTP expired' });
        res.json({ success: true });
    });
});

app.post('/api/update-password', async (req, res) => {
    const { email, newPassword } = req.body;
    if (!email || !newPassword) return res.status(400).json({ error: 'Email and password required' });

    const hash = await bcrypt.hash(newPassword, 10);
    db.run("UPDATE users SET password_hash = ? WHERE email = ?", [hash, email], function(err) {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (this.changes === 0) return res.status(404).json({ error: 'User not found' });
        res.json({ success: true });
    });
});

// ---------------- STATIC PAGES ----------------
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'expenses.html')));
app.get('/history.html', (req, res) => res.sendFile(path.join(__dirname, 'history.html')));

// ---------------- START SERVER ----------------
app.listen(port, '0.0.0.0', () => {
    console.log(`Server running at http://localhost:${port}`);
});