// ======= Setup =======
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const app = express();

// ======= Constants =======
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

// ======= MongoDB Connection =======
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('✅ Connected to MongoDB'))
    .catch(err => console.error('❌ MongoDB connection error:', err));

// ======= Middlewares =======
app.use(cookieParser());
app.use(express.json());
app.use(cors({
    origin: 'http://localhost:3000', // origin: FRONTEND_URL
    credentials: true
}));

// ======= Mongoose Schemas =======
const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String,
    securityQuestion1: String,
    securityAnswer1: String,
    securityQuestion2: String,
    securityAnswer2: String
});

const itemSchema = new mongoose.Schema({
    name: String,
    completed: { type: Boolean, default: false },
    initials: { type: String, default: '' },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
});

const User = mongoose.model('User', userSchema);
const Item = mongoose.model('Item', itemSchema);

// ======= Authentication Middleware =======
function authenticateToken(req, res, next) {
    let token = req.cookies.token;

    // If not in cookies, check Authorization header
    if (!token && req.headers.authorization) {
        const authHeader = req.headers.authorization;
        if (authHeader.startsWith('Bearer ')) {
            token = authHeader.split(' ')[1];
        }
    }

    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// ======= Environment Log =======
if (process.env.NODE_ENV === 'production') {
    console.log('🚀 Running in PRODUCTION mode');
} else {
    console.log('🔧 Running in DEVELOPMENT mode');
}

// ======= User Routes =======

// Sign Up

app.put('/signup', async (req, res) => {
    try {
        const { name, email, password, securityQuestion1, securityAnswer1, securityQuestion2, securityAnswer2 } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await User.create({
            name,
            email,
            password: hashedPassword,
            securityQuestion1,
            securityAnswer1,
            securityQuestion2,
            securityAnswer2
        });
        res.status(201).json({ message: 'User created successfully', user: { id: user._id, email: user.email } });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});



app.post('/signup', async (req, res) => {
    try {
        const { name, email, password, securityQuestion1, securityAnswer1, securityQuestion2, securityAnswer2 } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await User.create({
            name,
            email,
            password: hashedPassword,
            securityQuestion1,
            securityAnswer1,
            securityQuestion2,
            securityAnswer2
        });
        res.status(201).json({ message: 'User created successfully', user: { id: user._id, email: user.email } });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// Login
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ error: "User not found" });

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(401).json({ error: "Invalid password" });

        const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
       

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Lax',
            maxAge: 3600000
        });
        
        res.json({ message: "Login successful", token }); // <-- also return token if needed
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Logout
app.post('/logout', (req, res) => {
    res.clearCookie('token', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'Lax'
    });
    res.json({ message: 'Logged out' });
});

// Forgot Password
app.post('/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ error: "User not found" });

        res.json({
            email: user.email,
            securityQuestion1: user.securityQuestion1,
            securityQuestion2: user.securityQuestion2
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Verify Security Answers and Reset Password
app.post('/verify-security-answers', async (req, res) => {
    try {
        const { email, answer1, answer2, newPassword } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ error: "User not found" });

        if (user.securityAnswer1 === answer1 && user.securityAnswer2 === answer2) {
            const hashedPassword = await bcrypt.hash(newPassword, 10);
            await User.updateOne({ email }, { password: hashedPassword });
            res.json({ message: "Password reset successful" });
        } else {
            res.status(401).json({ error: "Security answers do not match" });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ======= Checklist CRUD Routes =======

// Get All Items
app.get('/items', authenticateToken, async (req, res) => {
    try {
        const items = await Item.find({ userId: req.user.id });
        res.json(items);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Create Item
app.post('/items', authenticateToken, async (req, res) => {
    try {
        const { name } = req.body;
        const item = await Item.create({ name, userId: req.user.id });
        res.status(201).json(item);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Update Item
app.put('/items/:id', authenticateToken, async (req, res) => {
    try {
        const { name, completed, initials } = req.body;
        const item = await Item.findOneAndUpdate(
            { _id: req.params.id, userId: req.user.id },
            { name, completed, initials },
            { new: true }
        );
        if (!item) return res.status(404).json({ error: "Item not found" });
        res.json(item);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Delete Item
app.delete('/items/:id', authenticateToken, async (req, res) => {
    try {
        const result = await Item.deleteOne({ _id: req.params.id, userId: req.user.id });
        if (result.deletedCount === 0) return res.status(404).json({ error: "Item not found" });
        res.json({ message: "Item deleted" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ======= Start Server =======
app.listen(PORT, () => {
    console.log(`✅ Server running on port ${PORT}`);
});
