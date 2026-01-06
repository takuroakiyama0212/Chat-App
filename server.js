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
const cors = require('cors');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const CORS_ORIGINS_RAW = process.env.CORS_ORIGINS || '*'; // comma-separated list or '*'
const CORS_ORIGINS = CORS_ORIGINS_RAW === '*'
  ? '*'
  : CORS_ORIGINS_RAW.split(',').map(s => s.trim()).filter(Boolean);

const io = socketIo(server, {
  cors: {
    origin: CORS_ORIGINS,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: false
  }
});
const messageSenders = new Map(); // track who sent a message id so we can send read receipts back
const memoryUsers = new Map(); // username -> { password_hash, created_at }
const memoryMessages = []; // in-memory fallback when Postgres is not configured
const MAX_MEMORY_MESSAGES = Number(process.env.MAX_MEMORY_MESSAGES || 200);
const HISTORY_LIMIT = Number(process.env.HISTORY_LIMIT || 200);
const DATABASE_URL = process.env.DATABASE_URL;
let pool = DATABASE_URL ? new Pool({ connectionString: DATABASE_URL }) : null;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || null;
const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

// Firebase (optional) - for Firebase Auth Google Sign-In
// If env vars are not set, these fall back to the sample config the user provided.
// Prefer setting them in `.env` in real deployments.
const FIREBASE_API_KEY = process.env.FIREBASE_API_KEY || 'AIzaSyB5vcDxVhSZuNwojIuLV7CzdD2CyjlS_k8';
const FIREBASE_AUTH_DOMAIN = process.env.FIREBASE_AUTH_DOMAIN || 'chat-app-12ed6.firebaseapp.com';
const FIREBASE_PROJECT_ID = process.env.FIREBASE_PROJECT_ID || 'chat-app-12ed6';
const FIREBASE_APP_ID = process.env.FIREBASE_APP_ID || '1:697873574008:web:ad542d50f9e1ec45d6658d';
const FIREBASE_STORAGE_BUCKET = process.env.FIREBASE_STORAGE_BUCKET || 'chat-app-12ed6.firebasestorage.app';
const FIREBASE_MESSAGING_SENDER_ID = process.env.FIREBASE_MESSAGING_SENDER_ID || '697873574008';
const FIREBASE_MEASUREMENT_ID = process.env.FIREBASE_MEASUREMENT_ID || 'G-WJ2CPN9660';
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
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id VARCHAR(64) PRIMARY KEY,
        from_username VARCHAR(255) NOT NULL,
        message TEXT NOT NULL,
        timestamp BIGINT NOT NULL
      )
    `);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages (timestamp)`);
    console.log('Database initialized');
  } catch (err) {
    console.warn('Database init failed; continuing without Postgres (in-memory users/messages).', err?.message || err);
    try { await pool.end(); } catch (_) {}
    pool = null;
  }
}

app.use(express.static('public'));
app.use(cors({
  origin: CORS_ORIGINS,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: false
}));
app.use(express.json());

const SECRET = process.env.JWT_SECRET || 'secret';
const ENC_KEY = crypto.createHash('sha256').update(process.env.ENCRYPTION_KEY || 'default-dev-key').digest();
const IV_LENGTH = 16;
const MESSAGE_ID_BYTES = 8;

app.get('/config', (req, res) => {
  res.json({
    googleClientId: GOOGLE_CLIENT_ID,
    firebase: {
      enabled: firebaseEnabled || Boolean(FIREBASE_PROJECT_ID),
      webConfig: (FIREBASE_API_KEY && FIREBASE_AUTH_DOMAIN && FIREBASE_PROJECT_ID)
        ? {
            apiKey: FIREBASE_API_KEY,
            authDomain: FIREBASE_AUTH_DOMAIN,
            projectId: FIREBASE_PROJECT_ID,
            appId: FIREBASE_APP_ID,
            storageBucket: FIREBASE_STORAGE_BUCKET,
            messagingSenderId: FIREBASE_MESSAGING_SENDER_ID,
            measurementId: FIREBASE_MEASUREMENT_ID
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

async function saveMessage(message) {
  // message: { id, from, message, timestamp }
  if (pool) {
    try {
      await pool.query(
        'INSERT INTO messages (id, from_username, message, timestamp) VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO NOTHING',
        [message.id, message.from, message.message, message.timestamp]
      );
    } catch (err) {
      console.error('Failed to persist message:', err);
    }
    return;
  }

  memoryMessages.push(message);
  if (memoryMessages.length > MAX_MEMORY_MESSAGES) {
    memoryMessages.splice(0, memoryMessages.length - MAX_MEMORY_MESSAGES);
  }
}

async function getRecentMessages(limit = HISTORY_LIMIT) {
  const safeLimit = Math.max(1, Math.min(Number(limit) || HISTORY_LIMIT, 500));
  if (pool) {
    try {
      const result = await pool.query(
        'SELECT id, from_username AS "from", message, timestamp FROM messages ORDER BY timestamp ASC LIMIT $1',
        [safeLimit]
      );
      return result.rows || [];
    } catch (err) {
      console.error('Failed to load message history:', err);
      return [];
    }
  }
  return memoryMessages.slice(-safeLimit);
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

  try {
    let decoded;
    if (firebaseEnabled) {
      decoded = await admin.auth().verifyIdToken(idToken);
    } else if (FIREBASE_PROJECT_ID) {
      // Verify Firebase ID token without service account by validating signature + iss/aud via Google's JWKS.
      const { createRemoteJWKSet, jwtVerify } = await import('jose');
      const JWKS = createRemoteJWKSet(new URL('https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com'));
      const verified = await jwtVerify(idToken, JWKS, {
        issuer: `https://securetoken.google.com/${FIREBASE_PROJECT_ID}`,
        audience: FIREBASE_PROJECT_ID
      });
      decoded = verified.payload;
    } else {
      return res.status(500).json({ error: 'Firebase login not configured on server' });
    }

    const username = decoded.email || decoded.uid;
    if (!username) {
      return res.status(400).json({ error: 'Firebase token missing email/uid' });
    }
    await ensureUserExists(username);
    const token = jwt.sign({ username }, SECRET, { expiresIn: '1h' });
    return res.json({ token, username, provider: 'firebase' });
  } catch (err) {
    console.error('Firebase auth error:', err);
    const debug =
      process.env.DEBUG_AUTH === 'true' ||
      (process.env.NODE_ENV && process.env.NODE_ENV !== 'production');
    return res.status(401).json({
      error: 'Firebase authentication failed',
      ...(debug ? { detail: err?.message || String(err) } : {})
    });
  }
});

app.post('/register', async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = req.body?.password;
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
  const username = String(req.body?.username || '').trim();
  const password = req.body?.password;
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

io.on('connection', async (socket) => {
  console.log(`${socket.username} connected`);

  // Send history to the newly connected client so they can see earlier messages.
  try {
    const history = await getRecentMessages();
    // Populate sender map so read receipts can work for history messages too.
    history.forEach((m) => {
      if (m?.id && m?.from) messageSenders.set(m.id, m.from);
    });
    socket.emit('chat history', history);
  } catch (_) {}

  socket.on('chat message', async (msg) => {
    const message = {
      id: generateMessageId(),
      from: socket.username,
      message: msg,
      timestamp: Date.now()
    };
    messageSenders.set(message.id, socket.username);
    await saveMessage(message);
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
// On serverless platforms (e.g., Vercel), DB initialization often fails and can crash the function.
// Skip init on Vercel, or when explicitly disabled.
const SKIP_DB_INIT =
  process.env.SKIP_DB_INIT === 'true' ||
  process.env.VERCEL === '1' ||
  process.env.VERCEL === 'true';

const startServer = () => {
  // Binding explicitly to 0.0.0.0 can fail in some sandboxed environments.
  // Default to localhost unless overridden.
  const isHosted =
    process.env.RENDER === 'true' ||
    process.env.VERCEL === '1' ||
    process.env.VERCEL === 'true' ||
    process.env.NODE_ENV === 'production';
  const HOST = process.env.HOST || (isHosted ? '0.0.0.0' : '127.0.0.1');
  server.listen(PORT, HOST, () => console.log(`Server running on http://${HOST}:${PORT}`));
};

if (SKIP_DB_INIT) {
  console.warn('Skipping DB initialization (SKIP_DB_INIT/VERCEL enabled).');
  startServer();
} else {
  initDB().then(startServer).catch(err => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
  });
}
