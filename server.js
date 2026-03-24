const express = require('express');
const path = require('path');
const db = require('./db'); // Importing your db.js

const app = express();
const PORT = 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files (CSS, JS, Images) from the current directory
app.use(express.static(__dirname));

// --- ROUTES ---

// 1. Serve the HTML file
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'main.html'));
});

// 2. Fetch all expenses for the table
app.get('/expenses', (req, res) => {
    const query = "SELECT * FROM expenses ORDER BY date ASC"; // Ensure your table name is 'expenses'

    db.query(query, (err, results) => {
        if (err) {
            console.error("Error fetching data:", err);
            return res.status(500).json({ error: "Database query failed" });
        }
        res.json(results);
    });
});

// Start the server
app.listen(PORT, () => {
    console.log(`🚀 Server running at http://localhost:${PORT}`);
});