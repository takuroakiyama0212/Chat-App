const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Pool } = require('pg');
const { OAuth2Client } = require('google-auth-library');
const fs = require('fs');
const admin = require('firebase-admin');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server);
const messageSenders = new Map(); // track who sent a message id so we can send read receipts back
const memoryUsers = new Map(); // username -> { password_hash, created_at }
const DATABASE_URL = process.env.DATABASE_URL;
const pool = DATABASE_URL ? new Pool({ connectionString: DATABASE_URL }) : null;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || null;
const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

// Firebase (optional) - for Firebase Auth Google Sign-In
const FIREBASE_API_KEY = process.env.FIREBASE_API_KEY || null;
const FIREBASE_AUTH_DOMAIN = process.env.FIREBASE_AUTH_DOMAIN || null;
const FIREBASE_PROJECT_ID = process.env.FIREBASE_PROJECT_ID || null;
const FIREBASE_APP_ID = process.env.FIREBASE_APP_ID || null;
const FIREBASE_SERVICE_ACCOUNT_JSON = process.env.FIREBASE_SERVICE_ACCOUNT_JSON || null;
const FIREBASE_SERVICE_ACCOUNT_PATH = process.env.FIREBASE_SERVICE_ACCOUNT_PATH || null;
let firebaseEnabled = false;

function initFirebaseAdmin() {
  try {
    if (admin.apps.length > 0) {
      firebaseEnabled = true;
      return;
    }

    if (FIREBASE_SERVICE_ACCOUNT_JSON) {
      const svc = JSON.parse(FIREBASE_SERVICE_ACCOUNT_JSON);
      admin.initializeApp({ credential: admin.credential.cert(svc) });
      firebaseEnabled = true;
      return;
    }

    if (FIREBASE_SERVICE_ACCOUNT_PATH) {
      const svc = JSON.parse(fs.readFileSync(FIREBASE_SERVICE_ACCOUNT_PATH, 'utf8'));
      admin.initializeApp({ credential: admin.credential.cert(svc) });
      firebaseEnabled = true;
      return;
    }

    // If GOOGLE_APPLICATION_CREDENTIALS is set, admin.initializeApp() can work via ADC.
    if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
      admin.initializeApp();
      firebaseEnabled = true;
      return;
    }
  } catch (err) {
    console.warn('Firebase Admin init failed (Firebase login disabled):', err?.message || err);
    firebaseEnabled = false;
  }
}

async function initDB() {
  if (!pool) {
    console.warn('DATABASE_URL not set; running without Postgres (in-memory users, non-persistent).');
    return;
  }
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(255) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
  console.log('Database initialized');
}

app.use(express.static('public'));
app.use(express.json());

const SECRET = process.env.JWT_SECRET || 'secret';
const ENC_KEY = crypto.createHash('sha256').update(process.env.ENCRYPTION_KEY || 'default-dev-key').digest();
const IV_LENGTH = 16;
const MESSAGE_ID_BYTES = 8;

app.get('/config', (req, res) => {
  res.json({
    googleClientId: GOOGLE_CLIENT_ID,
    firebase: {
      enabled: firebaseEnabled,
      webConfig: (FIREBASE_API_KEY && FIREBASE_AUTH_DOMAIN && FIREBASE_PROJECT_ID)
        ? {
            apiKey: FIREBASE_API_KEY,
            authDomain: FIREBASE_AUTH_DOMAIN,
            projectId: FIREBASE_PROJECT_ID,
            appId: FIREBASE_APP_ID
          }
        : null
    }
  });
});

function encrypt(text) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', ENC_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(data) {
  const [ivHex, encryptedHex] = data.split(':');
  const iv = Buffer.from(ivHex, 'hex');
  const encryptedText = Buffer.from(encryptedHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', ENC_KEY, iv);
  const decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()]);
  return decrypted.toString('utf8');
}

function generateMessageId() {
  return crypto.randomBytes(MESSAGE_ID_BYTES).toString('hex');
}

async function ensureUserExists(username) {
  // For Google sign-in users we need a placeholder hash to satisfy schema constraints.
  const placeholderHash = await bcrypt.hash(crypto.randomBytes(24).toString('hex'), 10);

  if (pool) {
    const existing = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
    if (existing.rows.length > 0) return;
    await pool.query('INSERT INTO users (username, password_hash) VALUES ($1, $2)', [username, placeholderHash]);
    return;
  }

  if (!memoryUsers.has(username)) {
    memoryUsers.set(username, { password_hash: placeholderHash, created_at: Date.now(), provider: 'google' });
  }
}

app.post('/auth/google', async (req, res) => {
  const { credential } = req.body || {};
  if (!credential) {
    return res.status(400).json({ error: 'Missing credential' });
  }
  if (!googleClient) {
    return res.status(500).json({ error: 'Google sign-in not configured on server' });
  }

  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID
    });
    const payload = ticket.getPayload();
    if (!payload) {
      return res.status(401).json({ error: 'Invalid Google token' });
    }
    if (payload.email_verified === false) {
      return res.status(401).json({ error: 'Google email not verified' });
    }

    const username = payload.email || payload.sub;
    if (!username) {
      return res.status(400).json({ error: 'Google account missing email' });
    }

    await ensureUserExists(username);
    const token = jwt.sign({ username }, SECRET, { expiresIn: '1h' });
    return res.json({ token, username, provider: 'google' });
  } catch (err) {
    console.error('Google auth error:', err);
    return res.status(401).json({ error: 'Google authentication failed' });
  }
});

app.post('/auth/firebase', async (req, res) => {
  const { idToken } = req.body || {};
  if (!idToken) {
    return res.status(400).json({ error: 'Missing idToken' });
  }
  if (!firebaseEnabled) {
    return res.status(500).json({ error: 'Firebase login not configured on server' });
  }

  try {
    const decoded = await admin.auth().verifyIdToken(idToken);
    const username = decoded.email || decoded.uid;
    if (!username) {
      return res.status(400).json({ error: 'Firebase token missing email/uid' });
    }
    await ensureUserExists(username);
    const token = jwt.sign({ username }, SECRET, { expiresIn: '1h' });
    return res.json({ token, username, provider: 'firebase' });
  } catch (err) {
    console.error('Firebase auth error:', err);
    return res.status(401).json({ error: 'Firebase authentication failed' });
  }
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }
  try {
    if (pool) {
      const existing = await pool.query('SELECT id FROM users WHERE username = $1', [username]);
      if (existing.rows.length > 0) {
        return res.status(400).json({ error: 'User exists' });
      }
      const hash = await bcrypt.hash(password, 10);
      await pool.query('INSERT INTO users (username, password_hash) VALUES ($1, $2)', [username, hash]);
      return res.json({ success: true });
    }

    if (memoryUsers.has(username)) {
      return res.status(400).json({ error: 'User exists' });
    }
    const hash = await bcrypt.hash(password, 10);
    memoryUsers.set(username, { password_hash: hash, created_at: Date.now() });
    return res.json({ success: true, mode: 'memory' });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    if (pool) {
      const result = await pool.query('SELECT password_hash FROM users WHERE username = $1', [username]);
      if (result.rows.length === 0) {
        return res.status(400).json({ error: 'User not found' });
      }
      const valid = await bcrypt.compare(password, result.rows[0].password_hash);
      if (!valid) {
        return res.status(401).json({ error: 'Invalid password' });
      }
      const token = jwt.sign({ username }, SECRET, { expiresIn: '1h' });
      return res.json({ token });
    }

    const record = memoryUsers.get(username);
    if (!record) {
      return res.status(400).json({ error: 'User not found' });
    }
    const valid = await bcrypt.compare(password, record.password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid password' });
    }
    const token = jwt.sign({ username }, SECRET, { expiresIn: '1h' });
    return res.json({ token, mode: 'memory' });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  try {
    const decoded = jwt.verify(token, SECRET);
    socket.username = decoded.username;
    next();
  } catch (err) {
    next(new Error('Unauthorized'));
  }
});

io.on('connection', (socket) => {
  console.log(`${socket.username} connected`);

  socket.on('chat message', (msg) => {
    const message = {
      id: generateMessageId(),
      from: socket.username,
      message: msg,
      timestamp: Date.now()
    };
    messageSenders.set(message.id, socket.username);
    io.emit('chat message', message);
  });

  socket.on('message read', ({ messageId }) => {
    const senderUsername = messageSenders.get(messageId);
    if (!senderUsername) return;
    // notify only the original sender that someone has read their message
    io.sockets.sockets.forEach((s) => {
      if (s.username === senderUsername) {
        s.emit('message read', { messageId, reader: socket.username });
      }
    });
  });

  socket.on('disconnect', () => {
    console.log(`${socket.username} disconnected`);
  });
});

const PORT = process.env.PORT || 3000;
initFirebaseAdmin();
initDB().then(() => {
  // Binding explicitly to 0.0.0.0 can fail in some sandboxed environments.
  // Default to localhost unless overridden.
  const HOST = process.env.HOST || '127.0.0.1';
  server.listen(PORT, HOST, () => console.log(`Server running on http://${HOST}:${PORT}`));
}).catch(err => {
  console.error('Failed to initialize database:', err);
  process.exit(1);
});
