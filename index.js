require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

// ===== MongoDB Connection =====
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB connection error:', err));

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

app.use(cors());
app.use(express.json());

// ===== JWT Auth Middleware =====
function authenticateToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// ===== User Routes =====

app.post('/signup', async (req, res) => {
    const { name, email, password, securityQuestion1, securityAnswer1, securityQuestion2, securityAnswer2 } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    try {
        const user = await User.create({ name, email, password: hashedPassword, securityQuestion1, securityAnswer1, securityQuestion2, securityAnswer2 });
        res.json({ id: user._id, name, email });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "User not found" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: "Invalid password" });

    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ message: "Login successful", token });
      
});

app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "User not found" });

    res.json({
        email: user.email,
        securityQuestion1: user.securityQuestion1,
        securityQuestion2: user.securityQuestion2
    });
});

app.post('/verify-security-answers', async (req, res) => {
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
});

// ===== Checklist CRUD Routes =====

app.get('/items', authenticateToken, async (req, res) => {
    const items = await Item.find({ userId: req.user.id });
    res.json(items);
});

app.post('/items', authenticateToken, async (req, res) => {
    const { name } = req.body;
    const item = await Item.create({ name, userId: req.user.id });
    res.json(item);
});

app.put('/items/:id', authenticateToken, async (req, res) => {
    const { name, completed, initials } = req.body;
    const item = await Item.findOneAndUpdate(
        { _id: req.params.id, userId: req.user.id },
        { name, completed, initials },
        { new: true }
    );
    if (!item) return res.status(404).json({ error: "Item not found" });
    res.json(item);
});

app.delete('/items/:id', authenticateToken, async (req, res) => {
    const result = await Item.deleteOne({ _id: req.params.id, userId: req.user.id });
    if (result.deletedCount === 0) return res.status(404).json({ error: "Item not found" });
    res.json({ message: "Item deleted" });
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});


