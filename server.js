// server.js

// -------------------
// Dependencies
// -------------------

const express = require('express');
const mysql = require('mysql');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const ejs = require('ejs');

// -------------------
// Express App Setup
// -------------------

const app = express();
const port = 3000;

// -------------------
// MySQL Connection
// -------------------

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root', // Replace with your MySQL username
    password: '', // Replace with your MySQL password
    database: 'scouting_app' // Replace with your database name
});

db.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL database:', err);
        return;
    }
    console.log('Connected to MySQL database');
});

// -------------------
// Middleware
// -------------------

app.use(session({
    secret: 'your_secret_key', // Replace with a strong secret key
    resave: false,
    saveUninitialized: true,
}));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Set the view engine to EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// -------------------
// Routes
// -------------------

// --- Authentication ---

app.get('/', (req, res) => {
    res.render('login', { error: null });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (username && password) {
        db.query('SELECT * FROM users WHERE username = ? AND password = ?', [username, password], (err, results) => {
            if (err) throw err;
            if (results.length > 0) {
                req.session.loggedin = true;
                req.session.username = username;
                res.redirect('/dashboard');
            } else {
                res.render('login', { error: 'Incorrect Username and/or Password!' });
            }
            res.end();
        });
    } else {
        res.render('login', { error: 'Please enter Username and Password!' });
        res.end();
    }
});

// --- Dashboard ---

app.get('/dashboard', (req, res) => {
    if (req.session.loggedin) {
        res.render('dashboard');
    } else {
        res.redirect('/');
    }
});

// --- Scouting Panel ---

app.get('/scouting-panel', (req, res) => {
    if (req.session.loggedin) {
        res.render('partials/scouting-panel');
    } else {
        res.redirect('/');
    }
});

// --- Reports ---

app.get('/reports', (req, res) => {
    if (req.session.loggedin) {
        db.query('SELECT * FROM reports WHERE username = ?', [req.session.username], (err, reports) => {
            if (err) throw err;
            res.render('partials/reports', { reports: reports });
        });
    } else {
        res.redirect('/');
    }
});

app.post('/generate-report', (req, res) => {
    if (req.session.loggedin) {
        const { reportData, teamName } = req.body;
        const reportContent = generateReportText(reportData, teamName);
        const reportTitle = `${teamName} - ${new Date().toLocaleDateString()}`;

        db.query('INSERT INTO reports SET ?', { username: req.session.username, title: reportTitle, content: reportContent }, (err, result) => {
            if (err) throw err;
            res.json({ success: true, reportId: result.insertId });
        });
    } else {
        res.status(401).send('Unauthorized');
    }
});

app.get('/report/:id', (req, res) => {
    if (req.session.loggedin) {
        const reportId = req.params.id;
        db.query('SELECT * FROM reports WHERE id = ? AND username = ?', [reportId, req.session.username], (err, results) => {
            if (err) throw err;
            if (results.length > 0) {
                res.render('report-view', { report: results[0] });
            } else {
                res.status(404).send('Report not found');
            }
        });
    } else {
        res.redirect('/');
    }
});

// --- Logout ---

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return console.log(err);
        }
        res.redirect('/');
    });
});

// -------------------
// Helper Functions
// -------------------

function generateReportText(players, teamName) {
    let report = `BASKETBALL SCOUTING REPORT\n`;
    report += `Team: ${teamName}\n`;
    report += `Date: ${new Date().toLocaleDateString()}\n`;
    report += "========================================\n\n";

    if (players.length === 0) {
        report += "No players have been added.";
    } else {
        players.forEach(p => {
            const formatTime = (seconds) => {
                const m = Math.floor(seconds / 60).toString().padStart(2, '0');
                const s = (seconds % 60).toString().padStart(2, '0');
                return `${m}:${s}`;
            };

            const fg2_pct = p.fg2a > 0 ? ((p.fg2m / p.fg2a) * 100).toFixed(1) : '0.0';
            const fg3_pct = p.fg3a > 0 ? ((p.fg3m / p.fg3a) * 100).toFixed(1) : '0.0';
            const ft_pct = p.fta > 0 ? ((p.ftm / p.fta) * 100).toFixed(1) : '0.0';

            report += `PLAYER: ${p.name} (#${p.number})\n`;
            report += `----------------------------------------\n`;
            report += `MIN: ${formatTime(p.minutes)} | PTS: ${p.points} | REB: ${p.rebounds} | AST: ${p.assists}\n`;
            report += `STL: ${p.steals} | BLK: ${p.blocks} | TO: ${p.turnovers} | PF: ${p.personalFouls}\n\n`;
            // Add more details as needed from your scouting panel logic
        });
    }
    return report;
}

// -------------------
// Start Server
// -------------------

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
