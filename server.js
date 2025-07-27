const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const User = require('./models/User');
const jwt = require('jsonwebtoken');
const { authLimiter, apiLimiter } = require('./middleware/rateLimiter');

const JWT_SECRET = process.env.JWT_SECRET || 'jnvoidavianladnvana';

const app = express();
const PORT = process.env.PORT || 5000;

// Apply rate limiting to all requests
app.use(apiLimiter);

// Configure CORS properly for development and production
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = [
      'http://localhost:3000',
      'http://localhost:5173', // Vite default port
      'http://localhost:5174', // Vite alternative port
      'http://localhost:5175', // Vite alternative port
      'http://127.0.0.1:3000',
      'http://127.0.0.1:5173',
      'http://127.0.0.1:5174',
      'http://127.0.0.1:5175',
      'https://striver-pod-frontend.vercel.app',
      'https://striver-pod-frontend-git-main-alecxender1402s-projects.vercel.app',
      'https://striver-pod-frontend-alecxender1402s-projects.vercel.app',
      process.env.FRONTEND_URL
    ].filter(Boolean);
    
    // Allow any localhost port for development
    if (origin.startsWith('http://localhost:') || origin.startsWith('http://127.0.0.1:')) {
      return callback(null, true);
    }
    
    // Allow any Vercel deployment for production
    if (origin.endsWith('.vercel.app')) {
      return callback(null, true);
    }
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.log('CORS blocked origin:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Origin', 
    'X-Requested-With', 
    'Content-Type', 
    'Accept', 
    'Authorization',
    'Cache-Control',
    'Pragma'
  ],
  exposedHeaders: ['Authorization'],
  optionsSuccessStatus: 200 // Some legacy browsers choke on 204
};

app.use(cors(corsOptions));

// Handle preflight requests explicitly
app.options('*', cors(corsOptions));

// Body parser middleware with size limit
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// MongoDB connection with better error handling
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/striverpod';
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  maxPoolSize: 10, // Maintain up to 10 socket connections
  serverSelectionTimeoutMS: 5000, // Keep trying to send operations for 5 seconds
  socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
}).then(() => {
  console.log('Connected to MongoDB');
}).catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

// Handle MongoDB connection errors after initial connection
mongoose.connection.on('error', (err) => {
  console.error('MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
  console.log('MongoDB disconnected');
});

// Input validation helper
const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

const validatePassword = (password) => {
  // At least 6 characters
  return password && password.length >= 6;
};

const sanitizeInput = (input) => {
  if (typeof input !== 'string') return input;
  return input.trim();
};

// Enhanced authentication middleware with better error handling
function auth(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'No token provided' });
    }
    
    const token = authHeader.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expired' });
    } else if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ message: 'Invalid token' });
    } else {
      return res.status(401).json({ message: 'Token verification failed' });
    }
  }
}

// Complete problem endpoint with enhanced error handling
app.post('/api/complete-problem', auth, async (req, res) => {
  try {
    const { problemId, completed } = req.body;
    
    // Validate input
    if (typeof problemId !== 'number' || typeof completed !== 'boolean') {
      return res.status(400).json({ message: 'Invalid input data' });
    }
    
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (completed) {
      if (!user.completedProblems.includes(problemId)) {
        user.completedProblems.push(problemId);
      }
    } else {
      user.completedProblems = user.completedProblems.filter(id => id !== problemId);
    }
    
    await user.save();
    res.json({ completedProblems: user.completedProblems });
  } catch (error) {
    console.error('Error completing problem:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get completed problems for the logged-in user with enhanced error handling
app.get('/api/completed-problems', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ completedProblems: user.completedProblems || [] });
  } catch (error) {
    console.error('Error fetching completed problems:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get daily POD data for the logged-in user
app.get('/api/daily-pod', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ dailyPOD: user.dailyPOD || {} });
  } catch (error) {
    console.error('Error fetching daily POD:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Save daily POD data for the logged-in user
app.post('/api/save-daily-pod', auth, async (req, res) => {
  try {
    const { dailyPOD } = req.body;
    
    // Validate input
    if (!dailyPOD || typeof dailyPOD !== 'object') {
      return res.status(400).json({ message: 'Invalid daily POD data' });
    }
    
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.dailyPOD = dailyPOD;
    await user.save();
    
    res.json({ message: 'Daily POD saved successfully', dailyPOD: user.dailyPOD });
  } catch (error) {
    console.error('Error saving daily POD:', error);
    res.status(500).json({ message: 'Server error' });
  }
});


// Signup endpoint with enhanced validation and rate limiting
app.post('/api/signup', authLimiter, async (req, res) => {
  try {
    let { name, email, password } = req.body;
    
    // Sanitize inputs
    name = sanitizeInput(name);
    email = sanitizeInput(email);
    
    // Validate required fields
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'All fields are required.' });
    }
    
    // Validate email format
    if (!validateEmail(email)) {
      return res.status(400).json({ message: 'Invalid email format.' });
    }
    
    // Validate password strength
    if (!validatePassword(password)) {
      return res.status(400).json({ message: 'Password must be at least 6 characters long.' });
    }
    
    // Check if user already exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(409).json({ message: 'User already exists.' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);
    
    // Create user
    const user = new User({ 
      name, 
      email: email.toLowerCase(), 
      password: hashedPassword 
    });
    
    await user.save();
    res.json({ message: 'Signup successful.' });
  } catch (error) {
    console.error('Signup error:', error);
    if (error.code === 11000) {
      return res.status(409).json({ message: 'User already exists.' });
    }
    res.status(500).json({ message: 'Server error.' });
  }
});
// Login endpoint with enhanced validation, security, and rate limiting
app.post('/api/login', authLimiter, async (req, res) => {
  try {
    let { email, password } = req.body;
    
    // Sanitize inputs
    email = sanitizeInput(email);
    
    // Validate required fields
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required.' });
    }
    
    // Validate email format
    if (!validateEmail(email)) {
      return res.status(400).json({ message: 'Invalid email format.' });
    }
    
    // Find user
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }
    
    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    // Create JWT token with expiration
    const token = jwt.sign(
      { userId: user._id, name: user.name }, 
      JWT_SECRET, 
      { expiresIn: '7d' }
    );
    
    res.json({ 
      message: 'Login successful.', 
      name: user.name, 
      token 
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error.' });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// Search problems endpoint with filtering
app.get('/api/search-problems', auth, async (req, res) => {
  try {
    const { 
      query = '', 
      difficulty = '', 
      completed = '', 
      page = 1, 
      limit = 50 
    } = req.query;

    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Load problems from file with proper CSV parsing
    const fs = require('fs');
    const path = require('path');
    const problemsFile = path.join(__dirname, '../striver_pod_frontend/public/striver_problems.txt');
    
    let problems = [];
    try {
      const data = fs.readFileSync(problemsFile, 'utf8');
      const lines = data.trim().split('\n').slice(1); // Skip header
      
      problems = lines.map(line => {
        // Proper CSV parsing that handles quoted fields with commas
        const fields = [];
        let current = '';
        let inQuotes = false;
        
        for (let i = 0; i < line.length; i++) {
          const char = line[i];
          
          if (char === '"' && (i === 0 || line[i-1] === ',')) {
            inQuotes = true;
          } else if (char === '"' && inQuotes && (i === line.length - 1 || line[i+1] === ',')) {
            inQuotes = false;
          } else if (char === ',' && !inQuotes) {
            fields.push(current.trim());
            current = '';
          } else {
            current += char;
          }
        }
        fields.push(current.trim()); // Add the last field
        
        // Clean up the fields (remove extra quotes)
        const cleanFields = fields.map(field => field.replace(/^"|"$/g, ''));
        
        if (cleanFields.length >= 3) {
          const idx = parseInt(cleanFields[0], 10);
          const problem_name = cleanFields[1];
          const difficulty = cleanFields[2];
          
          return {
            idx,
            problem_name,
            difficulty
          };
        }
        return null;
      }).filter(problem => problem && problem.idx && problem.problem_name && problem.difficulty);
      
      console.log(`Loaded ${problems.length} problems from file`);
    } catch (fileError) {
      console.error('Error reading problems file:', fileError);
      return res.status(500).json({ message: 'Error loading problems data' });
    }

    // Filter by search query (case-insensitive)
    let filteredProblems = problems;
    if (query.trim()) {
      const searchTerm = query.toLowerCase().trim();
      filteredProblems = problems.filter(problem => 
        problem.problem_name.toLowerCase().includes(searchTerm) ||
        problem.idx.toString().includes(searchTerm)
      );
    }

    // Filter by difficulty
    if (difficulty && ['Easy', 'Medium', 'Hard'].includes(difficulty)) {
      filteredProblems = filteredProblems.filter(problem => 
        problem.difficulty === difficulty
      );
    }

    // Filter by completion status
    if (completed !== '') {
      const isCompleted = completed === 'true';
      const completedProblems = user.completedProblems || [];
      
      if (isCompleted) {
        filteredProblems = filteredProblems.filter(problem => 
          completedProblems.includes(problem.idx)
        );
      } else {
        filteredProblems = filteredProblems.filter(problem => 
          !completedProblems.includes(problem.idx)
        );
      }
    }

    // Pagination
    const pageNum = Math.max(1, parseInt(page));
    const limitNum = Math.min(100, Math.max(1, parseInt(limit))); // Cap at 100
    const startIndex = (pageNum - 1) * limitNum;
    const endIndex = startIndex + limitNum;
    
    const paginatedProblems = filteredProblems.slice(startIndex, endIndex);

    // Add completion status to each problem
    const completedProblems = user.completedProblems || [];
    const enrichedProblems = paginatedProblems.map(problem => ({
      ...problem,
      isCompleted: completedProblems.includes(problem.idx)
    }));

    res.json({
      problems: enrichedProblems,
      totalResults: filteredProblems.length,
      totalPages: Math.ceil(filteredProblems.length / limitNum),
      currentPage: pageNum,
      hasMore: endIndex < filteredProblems.length,
      filters: {
        query: query.trim(),
        difficulty,
        completed,
        page: pageNum,
        limit: limitNum
      }
    });

  } catch (error) {
    console.error('Search problems error:', error);
    res.status(500).json({ message: 'Failed to search problems' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ message: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ message: 'Route not found' });
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully');
  await mongoose.connection.close();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('SIGINT received, shutting down gracefully');
  await mongoose.connection.close();
  process.exit(0);
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
}); 