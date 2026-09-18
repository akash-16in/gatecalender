require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'gate-planner-secret-key-2026-2028';

const app = express();
const path = require('path');

app.use(cors()); 
app.use(express.json()); 
app.use(express.static(__dirname));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'gate2026_final.html'));
});

/* ── DATABASE CONNECTION ── */
const DEFAULT_ATLAS_URI = 'mongodb+srv://gateadmin:Sm9Rr6lnsyMdw1Jo@cluster0.7v2hhyu.mongodb.net/gate_planner?retryWrites=true&w=majority&appName=Cluster0';
const MONGO_URI = process.env.MONGO_URI || DEFAULT_ATLAS_URI;

const mongoOptions = {
  serverSelectionTimeoutMS: 10000,
  socketTimeoutMS: 45000,
  family: 4, // Force IPv4 to prevent IPv6 DNS timeout delays on Windows/ISPs
  maxPoolSize: 10,
  minPoolSize: 2
};

mongoose.connect(MONGO_URI, mongoOptions)
  .then(() => console.log('✅ Connected to MongoDB Atlas (gate_planner)'))
  .catch(err => console.error('❌ MongoDB Connection Error:', err.message));

mongoose.connection.on('error', (err) => {
  console.error('⚠️ MongoDB Connection Error:', err.message);
});

mongoose.connection.on('disconnected', () => {
  console.log('⚠️ MongoDB Disconnected. Attempting automatic reconnection...');
});

mongoose.connection.on('reconnected', () => {
  console.log('✅ MongoDB Reconnected successfully.');
});

async function ensureDbConnected() {
  if (mongoose.connection.readyState === 1) return true;
  if (mongoose.connection.readyState === 2) {
    await new Promise((resolve) => {
      const timer = setTimeout(() => resolve(), 6000);
      mongoose.connection.once('connected', () => {
        clearTimeout(timer);
        resolve();
      });
      mongoose.connection.once('error', () => {
        clearTimeout(timer);
        resolve();
      });
    });
    return mongoose.connection.readyState === 1;
  }
  if (mongoose.connection.readyState === 0 || mongoose.connection.readyState === 3) {
    try {
      await mongoose.connect(MONGO_URI, mongoOptions);
      return true;
    } catch(e) {
      console.error('Reconnection error:', e.message);
      return false;
    }
  }
  return true;
}

/* ── USER MODEL ── */
const UserSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  sem: { type: String, required: true, trim: true },
  collegeName: { type: String, required: true, trim: true },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);

/* ── DAY SCHEMA (User-Scoped) ── */
const DaySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  dateKey: { type: String, required: true }, 
  subjects: [{ n: String, h: String }],
  distractions: [{ n: String, h: String }],
  note: { type: String, default: '' },
  mood: { type: Number, default: -1 },
  test: { category: String, name: String, score: String }
});

// Compound unique index so each user has their own calendar entries per date
DaySchema.index({ userId: 1, dateKey: 1 }, { unique: true });

const Day = mongoose.model('Day', DaySchema);

/* ── AUTH MIDDLEWARE ── */
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Authentication required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Session expired or invalid token' });
    req.user = user;
    next();
  });
}

/* ── AUTH ROUTES ── */
app.post('/api/auth/register', async (req, res) => {
  try {
    await ensureDbConnected();

    const { name, email, password, sem, collegeName } = req.body;
    if (!name || !email || !password || !sem || !collegeName) {
      return res.status(400).json({ error: 'Please fill in all required fields (Name, Email, Password, Sem, College).' });
    }

    const cleanEmail = email.trim().toLowerCase();
    const existingUser = await User.findOne({ email: cleanEmail });
    if (existingUser) {
      return res.status(400).json({ error: 'An account with this email already exists. Please log in.' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      name: name.trim(),
      email: cleanEmail,
      password: hashedPassword,
      sem: sem.trim(),
      collegeName: collegeName.trim()
    });

    await user.save();

    const token = jwt.sign(
      { userId: user._id, email: user.email, name: user.name },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.status(201).json({
      message: 'Registration successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        sem: user.sem,
        collegeName: user.collegeName
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: error.message || 'Registration failed. Please check your network and try again.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    await ensureDbConnected();

    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Please provide email and password' });
    }

    const cleanEmail = email.trim().toLowerCase();
    const user = await User.findOne({ email: cleanEmail });
    if (!user) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { userId: user._id, email: user.email, name: user.name },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({
      message: 'Logged in successfully',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        sem: user.sem,
        collegeName: user.collegeName
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: error.message || 'Login failed. Please check your network and try again.' });
  }
});

app.get('/api/health', (req, res) => {
  const isConnected = mongoose.connection.readyState === 1;
  res.json({
    status: 'ok',
    database: isConnected ? 'connected' : 'disconnected',
    timestamp: new Date().toISOString()
  });
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    await ensureDbConnected();
    const user = await User.findById(req.user.userId).select('-password');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        sem: user.sem,
        collegeName: user.collegeName
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Error fetching user profile' });
  }
});

/* ── USER-SCOPED CALENDAR DAYS API ── */
app.get('/api/days', authenticateToken, async (req, res) => {
  try {
    await ensureDbConnected();
    const days = await Day.find({ userId: req.user.userId });
    const map = {};
    days.forEach(d => {
      map[d.dateKey] = {
        subjects: d.subjects,
        distractions: d.distractions,
        note: d.note,
        mood: d.mood,
        test: d.test
      };
    });
    res.json(map);
  } catch (error) {
    console.error('Fetch days error:', error);
    res.status(500).json({ error: 'Error loading calendar days' });
  }
});

app.post('/api/days/:dateKey', authenticateToken, async (req, res) => {
  try {
    await ensureDbConnected();
    const updateData = {
      userId: req.user.userId,
      dateKey: req.params.dateKey,
      subjects: req.body.subjects || [],
      distractions: req.body.distractions || [],
      note: req.body.note || '',
      mood: req.body.mood,
      test: req.body.test
    };

    await Day.findOneAndUpdate(
      { userId: req.user.userId, dateKey: req.params.dateKey },
      updateData,
      { upsert: true, returnDocument: 'after', setDefaultsOnInsert: true }
    );
    res.json({ message: 'Saved' });
  } catch (error) {
    console.error('Save day error:', error);
    res.status(500).json({ error: 'Error saving day' });
  }
});

const PORT = process.env.PORT || 5000;
if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
}

module.exports = app;