const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const User = require('./models/User');
const jwt = require('jsonwebtoken');
const JWT_SECRET = 'jnvoidavianladnvana'; 

const app = express();
const PORT = 5000;

app.use(cors());
app.use(express.json());

// MongoDB connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/striverpod';
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  console.log('Connected to MongoDB');
}).catch(err => {
  console.error('MongoDB connection error:', err);
});

function auth(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'No token' });
    try {
      req.user = jwt.verify(token, JWT_SECRET);
      next();
    } catch {
      res.status(401).json({ message: 'Invalid token' });
    }
}

app.post('/api/complete-problem', auth, async (req, res) => {
    const { problemId, completed } = req.body;
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ message: 'User not found' });
  
    if (completed) {
      if (!user.completedProblems.includes(problemId)) {
        user.completedProblems.push(problemId);
      }
    } else {
      user.completedProblems = user.completedProblems.filter(id => id !== problemId);
    }
    await user.save();
    res.json({ completedProblems: user.completedProblems });
  });

// Get completed problems for the logged-in user
app.get('/api/completed-problems', auth, async (req, res) => {
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ completedProblems: user.completedProblems || [] });
  });


// Signup endpoint
app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ message: 'All fields are required.' });
  }
  try {
    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(409).json({ message: 'User already exists.' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword });
    await user.save();
    res.json({ message: 'Signup successful.' });
  } catch (err) {
    if (err.code === 11000) {
      return res.status(409).json({ message: 'User already exists.' });
    }
    res.status(500).json({ message: 'Server error.' });
  }
});
 // Use env variable in production

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: 'Invalid credentials.' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: 'Invalid credentials.' });

    // Create JWT token, expires in 7 days
    const token = jwt.sign({ userId: user._id, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ message: 'Login successful.', name: user.name, token });
  } catch (err) {
    res.status(500).json({ message: 'Server error.' });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
}); 