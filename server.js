// server.js
const express = require('express');
const mysql = require('mysql2/promise');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000; // Hosting will provide the port

// --- YOUR ACTION: REPLACE THESE VALUES ---
const dbConfig = {
    host: 'sql112.infinityfree.com', 
    user: 'if0_39626865',
    password: 'mp6VQ6URz6E76',
    database: 'if0_39626865_courtiq'
};
// -----------------------------------------

// Middleware
app.use(bodyParser.json());
app.use(session({
    secret: 'your-very-secret-key-change-this', // Change this to a random string
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set to true if you are using HTTPS
}));

// Serve static files from the root directory (for index.html)
app.use(express.static(__dirname));

let pool;

async function initializeDatabase() {
    try {
        pool = await mysql.createPool(dbConfig);
        console.log("Successfully connected to the database.");
    } catch (error) {
        console.error("Failed to connect to the database:", error);
        process.exit(1); // Exit if we can't connect
    }
}

// --- API ROUTES ---

// Check Session
app.get('/api/check_session', (req, res) => {
    if (req.session.loggedin) {
        res.json({
            loggedin: true,
            username: req.session.username,
            role: req.session.role
        });
    } else {
        res.json({ loggedin: false });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username and password are required.' });
    }
    
    try {
        const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
        if (rows.length > 0) {
            const user = rows[0];
            const passwordIsValid = await bcrypt.compare(password, user.password_hash);

            if (passwordIsValid) {
                req.session.loggedin = true;
                req.session.user_id = user.id;
                req.session.username = user.username;
                req.session.role = user.role;
                res.json({ success: true, role: user.role });
            } else {
                res.json({ success: false, message: 'Invalid credentials' });
            }
        } else {
            res.json({ success: false, message: 'Invalid credentials' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Database error' });
    }
});

// Logout
app.get('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// Middleware to check if user is an admin
const isAdmin = (req, res, next) => {
    if (req.session.loggedin && req.session.role === 'admin') {
        next();
    } else {
        res.status(403).json({ success: false, message: 'Unauthorized' });
    }
};

// Create User (Admin only)
app.post('/api/create_user', isAdmin, async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username and password are required.' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)', [username, hashedPassword, 'coach']);
        res.json({ success: true });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            res.json({ success: false, message: 'Username already exists.' });
        } else {
            res.status(500).json({ success: false, message: 'Database error' });
        }
    }
});

// Get Users (Admin only)
app.get('/api/get_users', isAdmin, async (req, res) => {
    try {
        const [users] = await pool.query("SELECT id, username, role FROM users WHERE role = 'coach'");
        res.json({ success: true, users });
    } catch (error) {
        res.status(500).json({ success: false, message: 'Database error' });
    }
});

// Save Report
app.post('/api/save-report', async (req, res) => {
    if (!req.session.loggedin) {
        return res.status(403).json({ success: false, message: 'Unauthorized' });
    }
    
    const data = req.body;
    const user_id = req.session.user_id;
    const connection = await pool.getConnection();

    try {
        await connection.beginTransaction();
        
        const [gameResult] = await connection.query(
            "INSERT INTO games (user_id, home_team_name, home_team_color, away_team_name, away_team_color) VALUES (?, ?, ?, ?, ?)",
            [user_id, data.teams.home.name, data.teams.home.color, data.teams.away.name, data.teams.away.color]
        );
        const game_id = gameResult.insertId;

        for (const teamKey of ['home', 'away']) {
            if (data.teams[teamKey] && data.teams[teamKey].players) {
                for (const player_data of data.teams[teamKey].players) {
                    const [playerResult] = await connection.query(
                        "INSERT INTO players (game_id, team, player_name, player_number) VALUES (?, ?, ?, ?)",
                        [game_id, teamKey, player_data.name, player_data.number]
                    );
                    const player_id = playerResult.insertId;

                    await connection.query(
                        "INSERT INTO stats (player_id, minutes, points, rebounds, offensive_rebounds, defensive_rebounds, assists, steals, blocks, times_blocked, turnovers, personal_fouls, coach_notes, fg2a, fg2m, fg3a, fg3m, fta, ftm) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        [
                            player_id, player_data.minutes, player_data.points, player_data.rebounds, player_data.offensiveRebounds, player_data.defensiveRebounds,
                            player_data.assists, player_data.steals, player_data.blocks, player_data.timesBlocked, player_data.turnovers, player_data.personalFouls,
                            player_data.coachNotes, player_data.fg2a, player_data.fg2m, player_data.fg3a, player_data.fg3m, player_data.fta, player_data.ftm
                        ]
                    );
                }
            }
        }
        
        await connection.commit();
        res.json({ success: true, report_url: `/report.php?id=${game_id}` }); // Kept .php for compatibility with your existing file
    } catch (error) {
        await connection.rollback();
        console.error(error);
        res.status(500).json({ success: false, message: 'Error saving report' });
    } finally {
        connection.release();
    }
});

// Serve the main page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Start the server
initializeDatabase().then(() => {
    app.listen(port, () => {
        console.log(`Server running on port ${port}`);
    });
});
