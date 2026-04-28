const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');

const app = express();

// Middleware
// TIP: Once your Netlify site is live, you can replace '*' with your Netlify URL for better security
app.use(cors({ origin: '*' })); 
app.use(express.json());

// Database Connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
    max: 10, // Recommended for free tiers to prevent connection exhaustion
    idleTimeoutMillis: 30000
});

// Gmail Transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'ridhwanahmed68@gmail.com',
        pass: 'erbsvkgimwlcxuau' 
    }
});

// Create tables automatically
const initDb = async () => {
    try {
        // Verification of Tables
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS grades (
                id SERIAL PRIMARY KEY,
                user_id TEXT,
                module VARCHAR(255),
                title VARCHAR(255),
                weight DECIMAL,
                value DECIMAL,
                created_at TIMESTAMP DEFAULT NOW()
            );
        `);
        console.log('✅ Database Tables Verified (Users & Grades)');
    } catch (err) {
        console.error('❌ DB Init Error:', err.message);
    }
};
initDb();

// 1. REGISTER
app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            'INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3)',
            [name, email.toLowerCase().trim(), hashedPassword]
        );
        res.status(201).json({ success: true, message: "Account created!" });
    } catch (error) {
        console.error('Registration Error:', error.message);
        res.status(400).json({ error: "Email already exists" });
    }
});

// 2. LOGIN
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase().trim()]);
        if (result.rows.length === 0) return res.status(404).json({ error: "User not found" });

        const valid = await bcrypt.compare(password, result.rows[0].password_hash);
        if (!valid) return res.status(401).json({ error: "Incorrect password" });

        res.json({ 
            success: true, 
            user: { uid: result.rows[0].id, name: result.rows[0].name, email: result.rows[0].email } 
        });
    } catch (error) {
        console.error('Login Error:', error.message);
        res.status(500).json({ error: "Login failed" });
    }
});

// 3. FORGOT PASSWORD
app.post('/api/forgot-password', async (req, res) => {
    const { email } = req.body;
    const em = email.toLowerCase().trim();
    
    try {
        // First check if user exists
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [em]);
        if (result.rows.length === 0) return res.status(404).json({ error: "User not found" });

        const code = Math.floor(100000 + Math.random() * 900000).toString();
        
        await transporter.sendMail({
            from: '"FlowGrade Support" <ridhwanahmed68@gmail.com>',
            to: em,
            subject: '🔐 FlowGrade Recovery Code',
            html: `<div style="font-family:sans-serif; text-align:center; padding:20px; border:1px solid #eee; border-radius:10px;">
                    <h2 style="color:#333;">Account Recovery</h2>
                    <p style="color:#666;">Enter the following code to reset your password:</p>
                    <h1 style="font-size:40px; color:#4f46e5; letter-spacing:5px;">${code}</h1>
                    <p style="font-size:12px; color:#999;">If you did not request this, please ignore this email.</p>
                   </div>`
        });
        
        res.json({ success: true, code: code });
    } catch (error) {
        console.error('Email Error:', error.message);
        res.status(500).json({ error: "Failed to send email" });
    }
});

// 4. RESET PASSWORD
app.post('/api/reset-password', async (req, res) => {
    const { email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query('UPDATE users SET password_hash = $1 WHERE email = $2', [hashedPassword, email.toLowerCase().trim()]);
        
        if (result.rowCount === 0) return res.status(404).json({ error: "User not found" });
        
        res.json({ success: true });
    } catch (error) {
        console.error('Reset Error:', error.message);
        res.status(500).json({ error: "Update failed" });
    }
});

// 5. SAVE GRADE
app.post('/api/grades', async (req, res) => {
    const { userId, module, title, weight, value } = req.body;
    try {
        await pool.query(
            'INSERT INTO grades (user_id, module, title, weight, value) VALUES ($1, $2, $3, $4, $5)',
            [userId, module, title, weight, value]
        );
        res.json({ success: true });
    } catch (error) {
        console.error('Grade Save Error:', error.message);
        res.status(500).json({ error: "Failed to save grade" });
    }
});

// Health check route for Render
app.get('/', (req, res) => res.send('✅ FlowGrade Backend is Live'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`========================================`);
    console.log(`✅ FlowGrade Server Running on port ${PORT}`);
    console.log(`📧 Email Service: Ready`);
    console.log(`========================================`);
});