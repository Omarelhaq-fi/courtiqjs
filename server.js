// server.js

const express = require('express');
const mysql = require('mysql');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const ejs = require('ejs');
const bcrypt = require('bcrypt');
const saltRounds = 10;

const app = express();

// --- MySQL Connection ---
// Your database credentials have been added here directly.
const db = mysql.createConnection({
    host: 'mysql6013.site4now.net',
    user: 'abc901_courtiq',
    password: 'omarreda123',
    database: 'db_abc901_courtiq'
});


db.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL database:', err);
        return;
    }
    console.log('Connected to MySQL database');
});

// --- Middleware ---
app.use(session({
    secret: 'a-very-strong-and-long-secret-key-for-coaches-app',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: process.env.NODE_ENV === 'production' }
}));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// --- Middleware for Authentication and Roles ---
function checkAuth(req, res, next) {
    if (req.session.loggedin) {
        res.locals.user = req.session;
        next();
    } else {
        res.redirect('/');
    }
}

function checkAdmin(req, res, next) {
    if (req.session.role === 'admin') {
        next();
    } else {
        res.status(403).send('Access Denied: Admins only.');
    }
}

// --- ONE-TIME ADMIN SETUP ROUTES ---
// This route will allow creation of the first admin account.
app.get('/setup-admin', (req, res) => {
    db.query('SELECT COUNT(*) as adminCount FROM users WHERE role = "admin"', (err, results) => {
        if (err) {
            return res.status(500).send("Database error during setup check.");
        }
        if (results[0].adminCount > 0) {
            // If an admin already exists, show an error page.
            return res.render('setup', { error: 'An admin account already exists. This setup page is disabled.' });
        }
        // Otherwise, show the setup form.
        res.render('setup', { error: null });
    });
});

app.post('/setup-admin', (req, res) => {
    db.query('SELECT COUNT(*) as adminCount FROM users WHERE role = "admin"', (err, results) => {
        if (err || results[0].adminCount > 0) {
            return res.status(403).send("Admin setup is disabled.");
        }

        const { username, password } = req.body;
        if (!username || !password) {
            return res.render('setup', { error: 'Username and password are required.' });
        }

        bcrypt.hash(password, saltRounds, (hashErr, hashedPassword) => {
            if (hashErr) {
                return res.status(500).send("Error hashing password.");
            }
            const newUser = {
                username,
                password: hashedPassword,
                role: 'admin'
            };
            db.query('INSERT INTO users SET ?', newUser, (insertErr) => {
                if (insertErr) {
                    return res.status(500).send("Error creating admin user.");
                }
                res.redirect('/');
            });
        });
    });
});


// --- Authentication Routes ---
app.get('/', (req, res) => {
    res.render('login', { error: null });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (username && password) {
        db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
            if (err || results.length === 0) {
                return res.render('login', { error: 'Incorrect Username and/or Password!' });
            }
            const user = results[0];
            bcrypt.compare(password, user.password, (bcryptErr, passwordMatch) => {
                if (bcryptErr || !passwordMatch) {
                    return res.render('login', { error: 'Incorrect Username and/or Password!' });
                }
                
                // Password is correct! Set up the session.
                req.session.loggedin = true;
                req.session.username = user.username;
                req.session.userId = user.id;
                req.session.role = user.role;
                
                // Save the session before redirecting to ensure it's written
                req.session.save((err) => {
                    if (err) {
                        // if there's an error saving the session, log it and proceed
                        console.error('Session save error:', err);
                    }
                    res.redirect('/dashboard');
                });
            });
        });
    } else {
        res.render('login', { error: 'Please enter Username and Password!' });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/'));
});


// --- Main Dashboard Route (handles both roles) ---
app.get('/dashboard', checkAuth, (req, res) => {
    res.render('dashboard'); // A single dashboard that shows different content based on role
});


// --- ADMIN-SPECIFIC ROUTES ---

// Route to load the admin panel content
app.get('/admin/panel', checkAuth, checkAdmin, (req, res) => {
    db.query('SELECT teams.id, teams.name, users.username as coach_name FROM teams LEFT JOIN users ON teams.coach_id = users.id', (err, teams) => {
        if (err) return res.status(500).send('Error fetching teams');
        db.query('SELECT players.id, players.name, players.number, teams.name as team_name FROM players JOIN teams ON players.team_id = teams.id', (err, players) => {
            if (err) return res.status(500).send('Error fetching players');
            db.query('SELECT id, username FROM users WHERE role = "coach"', (err, coaches) => {
                if (err) return res.status(500).send('Error fetching coaches');
                res.render('partials/admin-panel', { teams, players, coaches });
            });
        });
    });
});

app.post('/admin/teams', checkAuth, checkAdmin, (req, res) => {
    const { name, coach_id } = req.body;
    const coachId = coach_id === 'null' ? null : coach_id;
    db.query('INSERT INTO teams (name, coach_id) VALUES (?, ?)', [name, coachId], (err) => {
        if (err) return res.status(500).send('Error adding team');
        res.redirect('/dashboard');
    });
});

app.post('/admin/players', checkAuth, checkAdmin, (req, res) => {
    const { name, number, team_id } = req.body;
    db.query('INSERT INTO players (name, number, team_id) VALUES (?, ?, ?)', [name, number, team_id], (err) => {
        if (err) return res.status(500).send('Error adding player');
        res.redirect('/dashboard');
    });
});


// --- COACH-SPECIFIC ROUTES ---

// Route to load the coach's scouting panel
app.get('/coach/scouting-panel', checkAuth, (req, res) => {
    const coachId = req.session.userId;
    db.query('SELECT * FROM teams WHERE coach_id = ?', [coachId], (err, teams) => {
        if (err) return res.status(500).send('Error fetching teams for coach');
        
        if (teams.length === 0) {
            return res.render('partials/scouting-panel', { teams: [], players: [], selectedTeamId: null });
        }
        
        const teamIdToFetch = req.query.team_id || teams[0].id;
        db.query('SELECT * FROM players WHERE team_id = ?', [teamIdToFetch], (err, players) => {
            if (err) return res.status(500).send('Error fetching players');
            res.render('partials/scouting-panel', { teams, players, selectedTeamId: teamIdToFetch });
        });
    });
});


// Route to load the coach's reports
app.get('/coach/reports', checkAuth, (req, res) => {
    db.query('SELECT id, title, created_at FROM reports WHERE coach_username = ? ORDER BY created_at DESC', [req.session.username], (err, reports) => {
        if (err) return res.status(500).send("Database query error");
        res.render('partials/reports', { reports });
    });
});

// Generate and save a report
app.post('/coach/generate-report', checkAuth, (req, res) => {
    const { reportData, teamName, playerId } = req.body;
    if (!playerId) {
        return res.status(400).json({ success: false, message: 'Player ID is required.' });
    }

    const reportContent = generateDetailedReportText(reportData);
    const playerName = reportData.length > 0 ? reportData[0].name : 'Player';
    const reportTitle = `Scouting Report: ${playerName} (${teamName}) - ${new Date().toLocaleDateString()}`;

    const newReport = {
        coach_username: req.session.username,
        player_id: playerId,
        team_name_snapshot: teamName,
        title: reportTitle,
        content: reportContent
    };

    db.query('INSERT INTO reports SET ?', newReport, (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ success: false, message: 'Failed to save report.' });
        }
        res.json({ success: true, reportId: result.insertId });
    });
});

// View a specific report
app.get('/report/:id', checkAuth, (req, res) => {
    const reportId = req.params.id;
    db.query('SELECT * FROM reports WHERE id = ? AND coach_username = ?', [reportId, req.session.username], (err, results) => {
        if (err || results.length === 0) {
            return res.status(404).send('Report not found or access denied.');
        }
        res.render('report-view', { report: results[0] });
    });
});


// --- Helper Function for Report Generation ---
function generateDetailedReportText(players) {
    let report = "";
    if (!players || players.length === 0) {
        return "No player data provided.";
    }
    const p = players[0];

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
    report += `MIN: ${formatTime(p.minutes)} | PTS: ${p.points} | REB: ${p.rebounds} (${p.offensiveRebounds} O, ${p.defensiveRebounds} D) | AST: ${p.assists}\n`;
    report += `STL: ${p.steals} | BLK: ${p.blocks} | SHOT BLOCKED: ${p.timesBlocked} | TO: ${p.turnovers} | PF: ${p.personalFouls}\n`;

    if (p.turnovers > 0) {
        const to_details = Object.entries(p.turnoverDetails).filter(([, val]) => val > 0).map(([key, val]) => `${key}(${val})`).join(', ');
        report += `  - TO Details: ${to_details}\n`;
    }
    if (p.personalFouls > 0) {
        const f_details = Object.entries(p.foulDetails).filter(([, val]) => val > 0).map(([key, val]) => `${key}(${val})`).join(', ');
        report += `  - Foul Details: ${f_details}\n`;
    }
    report += `SHOOTING:\n`;
    report += `  - 2PT: ${p.fg2m}-${p.fg2a} (${fg2_pct}%)\n`;
    report += `  - 3PT: ${p.fg3m}-${p.fg3a} (${fg3_pct}%)\n`;
    report += `  - FT:  ${p.ftm}-${p.fta} (${ft_pct}%)\n`;
    if (p.shots && p.shots.length > 0) {
        report += `SHOT ANALYSIS:\n`;
        const shotLocations = {};
        p.shots.forEach(shot => {
            let key = `${shot.location} (${shot.type})`;
            if (shot.subLocation) key += ` - ${shot.subLocation}`;
            if (!shotLocations[key]) shotLocations[key] = { m: 0, a: 0 };
            shotLocations[key].a++;
            if (shot.made) shotLocations[key].m++;
        });
        for (const [loc, stats] of Object.entries(shotLocations)) {
            report += `  - ${loc}: ${stats.m}/${stats.a}\n`;
        }
    }
    if (p.coachNotes && p.coachNotes.trim()) {
        report += `COACH NOTES:\n${p.coachNotes.trim()}\n`;
    }
    return report;
}

module.exports = app;
