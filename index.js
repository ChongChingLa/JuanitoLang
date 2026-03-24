const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const axios = require('axios');

const app = express();
const port = 3000;
const dbFile = 'expense_credit_tracker.db';


//  CONFIG & MIDDLEWARE

app.use(express.json());
app.use(express.static(__dirname));

app.use(session({
    secret: 'your-secret-key-change-this-later-2026',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

// Database connection
const db = new sqlite3.Database(dbFile, (err) => {
    if (err) {
        console.error('Database connection failed:', err.message);
        process.exit(1);
    }
    console.log('Connected to database.');
});

//  DATABASE SETUP & SEEDING

db.serialize(() => {
    // Users table + default admin
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            usersID       INTEGER PRIMARY KEY AUTOINCREMENT,
            email         TEXT NOT NULL UNIQUE,
            name          TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL DEFAULT 'user'
                CHECK(role IN ('user', 'admin')),
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

    // OTP table (forgot password)
    db.run(`
        CREATE TABLE IF NOT EXISTS otps (
            email TEXT PRIMARY KEY,
            otp TEXT,
            expires_at INTEGER
        )
    `);
});


//  HELPER FUNCTIONS

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

//  AUTHENTICATION MIDDLEWARE

function requireAuth(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Please log in' });
    }
    req.userId = req.session.userId;
    next();
}

function requireAdmin(req, res, next) {
    if (!req.session.userId) return res.status(401).json({ error: 'Please log in' });

    db.get(
        "SELECT role FROM users WHERE usersID = ?",
        [req.session.userId],
        (err, row) => {
            if (err) return res.status(500).json({ error: err.message });
            if (!row || row.role !== 'admin') return res.status(403).json({ error: 'Admin access only' });
            next();
        }
    );
}


//  AUTHENTICATION ROUTES

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


//  FORGOT PASSWORD + OTP 

app.post('/api/forgot-password', (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });

    db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {
        if (err || !user) return res.status(404).json({ error: 'User not found' });

        const otp = generateOTP();
        const expires = Date.now() + 5 * 60 * 1000; // 5 minutes

        db.run(
            "INSERT OR REPLACE INTO otps (email, otp, expires_at) VALUES (?, ?, ?)",
            [email, otp, expires],
            async (err) => {
                if (err) return res.status(500).json({ error: 'Database error' });

                try {
                    await axios.post('http://localhost/phpmailer-service/sendMail.php', {
                        to: email,
                        subject: 'OTP Code',
                        body: `<p>Your OTP code is: <span style="font-weight:bold; color:blue;">${otp}</span></p>
                               <p>This OTP is valid for 5 minutes only. Do not share it with anyone.</p>`
                    });
                    res.json({ success: true });
                } catch (err) {
                    res.status(500).json({ error: 'Failed to send OTP' });
                }
            }
        );
    });
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


//  EXPENSES ROUTES (user only)

app.get('/api/expenses', requireAuth, (req, res) => {
    db.all(
        "SELECT * FROM expenses WHERE user_id = ? AND status != 'Paid' ORDER BY date DESC",
        [req.userId],
        (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        }
    );
});

app.get('/api/expenses/paid', requireAuth, (req, res) => {
    db.all(
        "SELECT * FROM expenses WHERE user_id = ? AND status = 'Paid' ORDER BY date DESC",
        [req.userId],
        (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        }
    );
});

app.post('/api/expenses', requireAuth, (req, res) => {
    const { description, category, amount, date } = req.body;
    if (!description || !category || !amount || !date) return res.status(400).json({ error: 'Missing fields' });

    const status = calculateStatus(date);

    db.run(
        "INSERT INTO expenses (user_id, description, category, amount, date, status) VALUES (?, ?, ?, ?, ?, ?)",
        [req.userId, description, category, amount, date, status],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ expensesID: this.lastID });
        }
    );
});

app.put('/api/expenses/:id', requireAuth, (req, res) => {
    const { description, category, amount, date } = req.body;
    const id = req.params.id;
    if (!description || !category || !amount || !date) return res.status(400).json({ error: 'Missing fields' });

    const status = calculateStatus(date);

    db.run(
        "UPDATE expenses SET description = ?, category = ?, amount = ?, date = ?, status = ? WHERE expensesID = ? AND user_id = ?",
        [description, category, amount, date, status, id, req.userId],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            if (this.changes === 0) return res.status(404).json({ error: 'Not found' });
            res.json({ success: true });
        }
    );
});

app.put('/api/expenses/:id/paid', requireAuth, (req, res) => {
    const id = req.params.id;
    db.run(
        "UPDATE expenses SET status = 'Paid' WHERE expensesID = ? AND user_id = ?",
        [id, req.userId],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            if (this.changes === 0) return res.status(404).json({ error: 'Not found' });
            res.json({ success: true });
        }
    );
});

app.delete('/api/expenses/:id', requireAuth, (req, res) => {
    const id = req.params.id;
    db.run("DELETE FROM expenses WHERE expensesID = ? AND user_id = ?", [id, req.userId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Not found' });
        res.json({ success: true });
    });
});


//  CREDITS ROUTES 

app.post('/api/credits', requireAuth, (req, res) => {
    const { customerName, description, originalAmount, remainingAmount, dateBorrowed, dueDate, status } = req.body;
    if (!customerName || !description || !originalAmount || !remainingAmount || !dateBorrowed || !dueDate || !status)
        return res.status(400).json({ error: 'Missing fields' });

    db.run(
        `INSERT INTO credits (user_id, customerName, description, originalAmount, remainingAmount, dateBorrowed, dueDate, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [req.userId, customerName, description, originalAmount, remainingAmount, dateBorrowed, dueDate, status],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ creditID: this.lastID });
        }
    );
});

app.get('/api/credits', requireAuth, (req, res) => {
    db.all("SELECT * FROM credits WHERE user_id = ? ORDER BY customerName ASC", [req.userId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.put('/api/credits/:id', requireAuth, (req, res) => {
    const id = parseInt(req.params.id, 10);
    const { remainingAmount, status } = req.body;

    if (isNaN(id) || remainingAmount == null || !status)
        return res.status(400).json({ error: 'Invalid input' });

    const paidDate = (status === 'Paid' || remainingAmount === 0) ? new Date().toISOString() : null;

    db.run(
        `UPDATE credits SET remainingAmount = ?, status = ?, paidDate = ? WHERE creditID = ? AND user_id = ?`,
        [remainingAmount, status, paidDate, id, req.userId],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            if (this.changes === 0) return res.status(404).json({ error: 'Credit not found' });
            res.json({ success: true });
        }
    );
});

app.delete('/api/credits/:id', requireAuth, (req, res) => {
    const id = req.params.id;
    db.run(`DELETE FROM credits WHERE creditID = ? AND user_id = ?`, [id, req.userId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Not found' });
        res.json({ success: true });
    });
});

app.get('/api/credits/history', requireAuth, (req, res) => {
    db.all(
        "SELECT * FROM credits WHERE user_id = ? AND (remainingAmount = 0 OR status = 'Paid') ORDER BY paidDate DESC",
        [req.userId],
        (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        }
    );
});


//  ADMIN ROUTES

app.get('/api/users', requireAdmin, (req, res) => {
    db.all(
        "SELECT usersID, name, email, role, created_at FROM users ORDER BY created_at DESC",
        [],
        (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        }
    );
});

app.get('/api/expenses/admin', requireAdmin, (req, res) => {
    db.all("SELECT * FROM expenses", [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.get('/api/credits/admin', requireAdmin, (req, res) => {
    db.all("SELECT * FROM credits", [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.delete('/api/users/:id', requireAdmin, (req, res) => {
    const id = req.params.id;

    if (parseInt(id) === req.session.userId) {
        return res.status(400).json({ error: 'Cannot delete your own admin account' });
    }

    db.run(
        "DELETE FROM users WHERE usersID = ?",
        [id],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            if (this.changes === 0) return res.status(404).json({ error: 'User not found' });
            res.json({ success: true });
        }
    );
});

//  STATIC PAGES

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'expenses.html')));
app.get('/history.html', (req, res) => res.sendFile(path.join(__dirname, 'history.html')));


//  START SERVER

app.listen(port, '0.0.0.0', () => {
    console.log(`Server running at http://localhost:${port}`);
});