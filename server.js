// server.js

const express = require('express');
const mysql = require('mysql');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const bodyParser = require('body-parser');
const path = require('path');
const ejs = require('ejs');
const bcrypt = require('bcrypt');
const saltRounds = 10;

const app = express();

// --- MySQL Connection ---
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

// --- Session Store Setup ---
const sessionStore = new MySQLStore({}, db);

// --- Middleware ---
app.use(session({
    key: 'courtiq_session',
    secret: 'a-very-strong-and-long-secret-key-for-coaches-app',
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: true,
        httpOnly: true,
        sameSite: 'lax'
    }
}));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// --- Middleware for Authentication ---
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
app.get('/setup-admin', (req, res) => {
    db.query('SELECT COUNT(*) as adminCount FROM admins', (err, results) => {
        if (err) return res.status(500).send("Database error during setup check.");
        if (results[0].adminCount > 0) {
            return res.render('setup', { error: 'An admin account already exists. This setup page is disabled.' });
        }
        res.render('setup', { error: null });
    });
});

app.post('/setup-admin', (req, res) => {
    db.query('SELECT COUNT(*) as adminCount FROM admins', (err, results) => {
        if (err || results[0].adminCount > 0) {
            return res.status(403).send("Admin setup is disabled.");
        }
        const { username, password } = req.body;
        if (!username || !password) {
            return res.render('setup', { error: 'Username and password are required.' });
        }
        bcrypt.hash(password, saltRounds, (hashErr, hashedPassword) => {
            if (hashErr) return res.status(500).send("Error hashing password.");
            db.query('INSERT INTO admins SET ?', { username, password: hashedPassword }, (insertErr) => {
                if (insertErr) return res.status(500).send("Error creating admin user.");
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
    if (!username || !password) {
        return res.render('login', { error: 'Please enter Username and Password!' });
    }

    // 1. Check if the user is an admin
    db.query('SELECT * FROM admins WHERE username = ?', [username], (err, adminResults) => {
        if (err) return res.status(500).send('Database error.');

        if (adminResults.length > 0) {
            const admin = adminResults[0];
            bcrypt.compare(password, admin.password, (bcryptErr, passwordMatch) => {
                if (passwordMatch) {
                    req.session.loggedin = true;
                    req.session.username = admin.username;
                    req.session.userId = admin.id;
                    req.session.role = 'admin';
                    return res.redirect('/dashboard');
                }
                // If password doesn't match, continue to check coaches table
                checkCoach();
            });
        } else {
            // If not found in admins, check coaches
            checkCoach();
        }
    });

    // 2. Function to check if the user is a coach
    function checkCoach() {
        db.query('SELECT * FROM coaches WHERE username = ?', [username], (err, coachResults) => {
            if (err) return res.status(500).send('Database error.');

            if (coachResults.length > 0) {
                const coach = coachResults[0];
                bcrypt.compare(password, coach.password, (bcryptErr, passwordMatch) => {
                    if (passwordMatch) {
                        req.session.loggedin = true;
                        req.session.username = coach.username;
                        req.session.userId = coach.id;
                        req.session.role = 'coach';
                        return res.redirect('/dashboard');
                    }
                    // If password doesn't match here, the login is invalid
                    return res.render('login', { error: 'Incorrect Username and/or Password!' });
                });
            } else {
                // Not found in admins or coaches
                return res.render('login', { error: 'Incorrect Username and/or Password!' });
            }
        });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/'));
});

// --- Main Dashboard Route ---
app.get('/dashboard', checkAuth, (req, res) => {
    res.render('dashboard');
});

// --- ADMIN-SPECIFIC ROUTES ---
app.get('/admin/panel', checkAuth, checkAdmin, (req, res) => {
    db.query('SELECT t.id, t.name, c.username as coach_name FROM teams t LEFT JOIN coaches c ON t.coach_id = c.id', (err, teams) => {
        if (err) return res.status(500).send('Error fetching teams');
        db.query('SELECT p.id, p.name, p.number, t.name as team_name FROM players p JOIN teams t ON p.team_id = t.id', (err, players) => {
            if (err) return res.status(500).send('Error fetching players');
            db.query('SELECT id, username FROM coaches', (err, coaches) => {
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

// In admin panel, you can now also create coaches
app.post('/admin/coaches', checkAuth, checkAdmin, (req, res) => {
    const { username, password } = req.body;
    bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
        if (err) return res.status(500).send('Error hashing password');
        db.query('INSERT INTO coaches SET ?', { username, password: hashedPassword }, (err) => {
            if (err) return res.status(500).send('Error creating coach');
            res.redirect('/dashboard');
        });
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

app.get('/coach/reports', checkAuth, (req, res) => {
    db.query('SELECT id, title, created_at FROM reports WHERE coach_id = ? ORDER BY created_at DESC', [req.session.userId], (err, reports) => {
        if (err) return res.status(500).send("Database query error");
        res.render('partials/reports', { reports });
    });
});

app.post('/coach/generate-report', checkAuth, (req, res) => {
    const { reportData, teamName, playerId } = req.body;
    if (!playerId) return res.status(400).json({ success: false, message: 'Player ID is required.' });
    
    const reportContent = generateDetailedReportText(reportData);
    const playerName = reportData.length > 0 ? reportData[0].name : 'Player';
    const reportTitle = `Scouting Report: ${playerName} (${teamName}) - ${new Date().toLocaleDateString()}`;

    const newReport = {
        coach_id: req.session.userId,
        player_id: playerId,
        team_name_snapshot: teamName,
        title: reportTitle,
        content: reportContent
    };

    db.query('INSERT INTO reports SET ?', newReport, (err) => {
        if (err) return res.status(500).json({ success: false, message: 'Failed to save report.' });
        res.json({ success: true });
    });
});

app.get('/report/:id', checkAuth, (req, res) => {
    const reportId = req.params.id;
    db.query('SELECT * FROM reports WHERE id = ? AND coach_id = ?', [reportId, req.session.userId], (err, results) => {
        if (err || results.length === 0) {
            return res.status(404).send('Report not found or access denied.');
        }
        res.render('report-view', { report: results[0] });
    });
});

// --- Helper Function for Report Generation ---
function generateDetailedReportText(players) {
    let report = "";
    if (!players || players.length === 0) return "No player data provided.";
    const p = players[0];
    const formatTime = (seconds) => `${Math.floor(seconds / 60).toString().padStart(2, '0')}:${(seconds % 60).toString().padStart(2, '0')}`;
    const fg2_pct = p.fg2a > 0 ? ((p.fg2m / p.fg2a) * 100).toFixed(1) : '0.0';
    const fg3_pct = p.fg3a > 0 ? ((p.fg3m / p.fg3a) * 100).toFixed(1) : '0.0';
    const ft_pct = p.fta > 0 ? ((p.ftm / p.fta) * 100).toFixed(1) : '0.0';
    report += `PLAYER: ${p.name} (#${p.number})\n`;
    report += `----------------------------------------\n`;
    report += `MIN: ${formatTime(p.minutes)} | PTS: ${p.points} | REB: ${p.rebounds} (${p.offensiveRebounds} O, ${p.defensiveRebounds} D) | AST: ${p.assists}\n`;
    report += `STL: ${p.steals} | BLK: ${p.blocks} | SHOT BLOCKED: ${p.timesBlocked} | TO: ${p.turnovers} | PF: ${p.personalFouls}\n`;
    if (p.turnovers > 0) report += `  - TO Details: ${Object.entries(p.turnoverDetails).filter(([, val]) => val > 0).map(([key, val]) => `${key}(${val})`).join(', ')}\n`;
    if (p.personalFouls > 0) report += `  - Foul Details: ${Object.entries(p.foulDetails).filter(([, val]) => val > 0).map(([key, val]) => `${key}(${val})`).join(', ')}\n`;
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
    if (p.coachNotes && p.coachNotes.trim()) report += `COACH NOTES:\n${p.coachNotes.trim()}\n`;
    return report;
}

module.exports = app;
