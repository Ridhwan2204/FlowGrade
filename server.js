const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');

const app = express();

// Middleware
// TIP: Once your Netlify site is live, replace '*' with your Netlify URL for better security
app.use(cors({ origin: process.env.FRONTEND_URL || '*' })); 
app.use(express.json());

// Database Connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
    max: 10, // Recommended for free tiers to prevent connection exhaustion
    idleTimeoutMillis: 30000
});

// Email Transporter - NOW USING ENVIRONMENT VARIABLES
const transporter = nodemailer.createTransport({
    service: process.env.EMAIL_SERVICE || 'gmail',
    auth: {
        user: process.env.EMAIL_USER || 'ridhwanahmed68@gmail.com',
        pass: process.env.EMAIL_PASS || 'erbsvkgimwlcxuau'
    }
});

// Verify email configuration on startup
transporter.verify((error, success) => {
    if (error) {
        console.error('❌ Email Service: NOT configured correctly');
        console.error('   Error:', error.message);
        console.error('   Please set EMAIL_USER and EMAIL_PASS environment variables in Render');
    } else {
        console.log('✅ Email Service: Ready to send emails');
    }
});

// Create tables automatically
const initDb = async () => {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                reset_token TEXT,
                reset_token_expiry TIMESTAMP,
                created_at TIMESTAMP DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS grades (
                id SERIAL PRIMARY KEY,
                user_id INTEGER,
                module VARCHAR(255),
                title VARCHAR(255),
                weight DECIMAL,
                value DECIMAL,
                created_at TIMESTAMP DEFAULT NOW(),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
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
    
    // Validation
    if (!name || !email || !password) {
        return res.status(400).json({ error: "All fields are required" });
    }
    if (password.length < 6) {
        return res.status(400).json({ error: "Password must be at least 6 characters" });
    }
    
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            'INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3)',
            [name, email.toLowerCase().trim(), hashedPassword]
        );
        res.status(201).json({ success: true, message: "Account created successfully!" });
    } catch (error) {
        console.error('Registration Error:', error.message);
        if (error.code === '23505') { // Unique violation
            res.status(400).json({ error: "Email already exists" });
        } else {
            res.status(500).json({ error: "Registration failed. Please try again." });
        }
    }
});

// 2. LOGIN
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ error: "Email and password required" });
    }
    
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase().trim()]);
        if (result.rows.length === 0) {
            return res.status(404).json({ error: "User not found" });
        }

        const valid = await bcrypt.compare(password, result.rows[0].password_hash);
        if (!valid) {
            return res.status(401).json({ error: "Incorrect password" });
        }

        res.json({ 
            success: true, 
            user: { 
                id: result.rows[0].id, 
                name: result.rows[0].name, 
                email: result.rows[0].email 
            } 
        });
    } catch (error) {
        console.error('Login Error:', error.message);
        res.status(500).json({ error: "Login failed. Please try again." });
    }
});

// 3. FORGOT PASSWORD - Sends reset code via email
app.post('/api/forgot-password', async (req, res) => {
    const { email } = req.body;
    
    if (!email) {
        return res.status(400).json({ error: "Email is required" });
    }
    
    const em = email.toLowerCase().trim();
    
    try {
        // Check if user exists
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [em]);
        if (result.rows.length === 0) {
            return res.status(404).json({ error: "No account found with this email" });
        }

        // Generate 6-digit reset code
        const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
        const resetExpiry = new Date(Date.now() + 3600000); // 1 hour expiry
        
        // Save reset code in database
        await pool.query(
            'UPDATE users SET reset_token = $1, reset_token_expiry = $2 WHERE email = $3',
            [resetCode, resetExpiry, em]
        );
        
        // Send email with reset code
        await transporter.sendMail({
            from: `"FlowGrade Support" <${process.env.EMAIL_USER || 'ridhwanahmed68@gmail.com'}>`,
            to: em,
            subject: '🔐 FlowGrade Password Reset Code',
            html: `
                <div style="font-family: 'Segoe UI', Arial, sans-serif; text-align: center; padding: 30px; border: 1px solid #e0e0e0; border-radius: 10px; max-width: 500px; margin: 0 auto;">
                    <h2 style="color: #4f46e5; margin-bottom: 20px;">Password Reset Request</h2>
                    <p style="color: #333; font-size: 16px;">You requested to reset your password. Use the code below to continue:</p>
                    <div style="background: #f3f4f6; padding: 15px; border-radius: 8px; margin: 25px 0;">
                        <h1 style="font-size: 48px; color: #4f46e5; letter-spacing: 8px; margin: 0;">${resetCode}</h1>
                    </div>
                    <p style="color: #666; font-size: 14px;">This code will expire in <strong>1 hour</strong>.</p>
                    <hr style="margin: 25px 0; border-color: #e0e0e0;">
                    <p style="color: #999; font-size: 12px;">If you didn't request this, please ignore this email. Your password won't change.</p>
                </div>
            `
        });
        
        console.log(`✅ Reset code sent to ${em}`);
        res.json({ 
            success: true, 
            message: "Reset code sent to your email",
            code: resetCode // Only include for testing, remove in production
        });
        
    } catch (error) {
        console.error('Email Sending Error:', error.message);
        res.status(500).json({ error: "Failed to send reset email. Please try again later." });
    }
});

// 4. VERIFY RESET CODE
app.post('/api/verify-reset-code', async (req, res) => {
    const { email, code } = req.body;
    
    if (!email || !code) {
        return res.status(400).json({ error: "Email and code are required" });
    }
    
    try {
        const result = await pool.query(
            'SELECT * FROM users WHERE email = $1 AND reset_token = $2 AND reset_token_expiry > NOW()',
            [email.toLowerCase().trim(), code]
        );
        
        if (result.rows.length === 0) {
            return res.status(400).json({ error: "Invalid or expired reset code" });
        }
        
        res.json({ success: true, message: "Code verified" });
    } catch (error) {
        console.error('Verify Code Error:', error.message);
        res.status(500).json({ error: "Verification failed" });
    }
});

// 5. RESET PASSWORD (after code verification)
app.post('/api/reset-password', async (req, res) => {
    const { email, code, newPassword } = req.body;
    
    if (!email || !code || !newPassword) {
        return res.status(400).json({ error: "All fields are required" });
    }
    
    if (newPassword.length < 6) {
        return res.status(400).json({ error: "Password must be at least 6 characters" });
    }
    
    try {
        // Verify code is valid and not expired
        const result = await pool.query(
            'SELECT * FROM users WHERE email = $1 AND reset_token = $2 AND reset_token_expiry > NOW()',
            [email.toLowerCase().trim(), code]
        );
        
        if (result.rows.length === 0) {
            return res.status(400).json({ error: "Invalid or expired reset code" });
        }
        
        // Update password and clear reset token
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await pool.query(
            'UPDATE users SET password_hash = $1, reset_token = NULL, reset_token_expiry = NULL WHERE email = $2',
            [hashedPassword, email.toLowerCase().trim()]
        );
        
        console.log(`✅ Password reset for ${email}`);
        res.json({ success: true, message: "Password reset successful!" });
        
    } catch (error) {
        console.error('Reset Password Error:', error.message);
        res.status(500).json({ error: "Failed to reset password" });
    }
});

// 6. SAVE GRADE
app.post('/api/grades', async (req, res) => {
    const { userId, module, title, weight, value } = req.body;
    
    if (!userId || !module || !title) {
        return res.status(400).json({ error: "Missing required fields" });
    }
    
    try {
        await pool.query(
            'INSERT INTO grades (user_id, module, title, weight, value) VALUES ($1, $2, $3, $4, $5)',
            [userId, module, title, weight || 0, value || 0]
        );
        res.json({ success: true, message: "Grade saved successfully" });
    } catch (error) {
        console.error('Grade Save Error:', error.message);
        res.status(500).json({ error: "Failed to save grade" });
    }
});

// 7. GET GRADES for a user
app.get('/api/grades/:userId', async (req, res) => {
    const { userId } = req.params;
    
    try {
        const result = await pool.query(
            'SELECT * FROM grades WHERE user_id = $1 ORDER BY created_at DESC',
            [userId]
        );
        res.json({ success: true, grades: result.rows });
    } catch (error) {
        console.error('Fetch Grades Error:', error.message);
        res.status(500).json({ error: "Failed to fetch grades" });
    }
});

// 8. Health check route for Render
app.get('/', (req, res) => res.send('✅ FlowGrade Backend is Live'));

app.get('/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        emailConfigured: !!process.env.EMAIL_USER
    });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`========================================`);
    console.log(`✅ FlowGrade Server Running on port ${PORT}`);
    console.log(`📧 Email Service: ${process.env.EMAIL_USER ? 'Configured' : 'Using default'}`);
    console.log(`========================================`);
});
