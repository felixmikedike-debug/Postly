// ─────────────────────────────────────────────────────────────────────────
// Marketing Poster Generator API — IMAGE ONLY (no embedded frontend)
// Search query in -> Pexels stock photo -> branded JPEG
// Frontend is hosted in a separate repo; this process is API-only.
//
// Auth & billing:
//   - JWT email/password accounts
//   - Single Telegram bot for 2FA / password-reset codes
//   - Paystack subscription: free tier limited posters/day, paid unlimited
//   - Admin panel at /admin-limits (password protected)
//
// Setup:
//   npm install express bcryptjs jsonwebtoken cors uuid express-rate-limit
//               telegraf mongoose axios node-fetch@2 sharp dotenv
//   .env:
//     PORT=3000
//     MONGODB_URI=mongodb://localhost:27017/postergen
//     JWT_SECRET=...
//     ADMIN_PASSWORD=...
//     DOMAIN=yourdomain.com
//     WEBHOOK_SECRET=...
//     AUTH_BOT_TOKEN=...
//     PAYSTACK_SECRET_KEY=...
//     PEXELS_API_KEY=...
//     PIXABAY_API_KEY=...          (fallback when Pexels is rate-limited / fails)
//   node app.js
//   API root: GET http://localhost:3000/
// ─────────────────────────────────────────────────────────────────────────

require('dotenv').config();

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const { Telegraf } = require('telegraf');
const mongoose = require('mongoose');
const axios = require('axios');
const crypto = require('crypto');
const fetch = require('node-fetch');
const sharp = require('sharp');

const BUILD_TAG = 'poster-app-image-only-2026-08-29-v1';

const app = express();
console.log('=== BUILD TAG: ' + BUILD_TAG + ' ===');
const PORT = process.env.PORT || 3000;
app.set('trust proxy', 3);

app.use(function (req, res, next) {
  res.setHeader('X-App-Build', BUILD_TAG);
  next();
});

// Two separate readiness flags: the auth bot (login/2FA) must never be
// blocked by anything else starting up.
let authBotReady = false;
let serverReady = false;

// ==================== CONFIG & SECRETS ====================
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_weak_secret_change_me_immediately';
const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY || 'sk_test_fallback_change_me';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'changeme';
const DOMAIN = process.env.DOMAIN;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

const PEXELS_API_KEY = process.env.PEXELS_API_KEY;
const PIXABAY_API_KEY = process.env.PIXABAY_API_KEY;

if (!DOMAIN) {
  console.error('ERROR: DOMAIN environment variable is required for the Telegram webhook!');
  process.exit(1);
}
if (!WEBHOOK_SECRET || !WEBHOOK_SECRET.trim()) {
  console.error('ERROR: WEBHOOK_SECRET must be set in env and stable across restarts/instances.');
  process.exit(1);
}
if (JWT_SECRET.includes('fallback')) {
  console.warn('WARNING: JWT_SECRET not set in .env! Using insecure fallback.');
}
if (PAYSTACK_SECRET_KEY.startsWith('sk_test_fallback')) {
  console.warn('WARNING: PAYSTACK_SECRET_KEY not set in .env!');
}
if (ADMIN_PASSWORD === 'changeme') {
  console.warn('WARNING: ADMIN_PASSWORD not set in .env! Using an insecure default.');
}
if (!PEXELS_API_KEY && !PIXABAY_API_KEY) {
  console.warn('WARNING: Neither PEXELS_API_KEY nor PIXABAY_API_KEY is set — image generation will fail.');
} else if (!PEXELS_API_KEY) {
  console.warn('WARNING: PEXELS_API_KEY not set — using Pixabay only.');
} else if (!PIXABAY_API_KEY) {
  console.warn('WARNING: PIXABAY_API_KEY not set — no fallback if Pexels rate-limits.');
}

const MONTHLY_PRICE_KOBO = 500000; // NGN 5,000/mo for unlimited posters — adjust to taste

// ==================== INPUT VALIDATION: LENGTH CAPS & CHARACTER RULES ====================
const NAME_MAX_LENGTH = 80;
const NAME_REGEX = /^[\p{L}\p{M}\s.'-]{1,80}$/u;

const EMAIL_MAX_LENGTH = 254;
const EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,24}$/;

const PASSWORD_MIN_LENGTH = 6;
const PASSWORD_MAX_LENGTH = 72; // bcrypt silently truncates past 72 bytes

const QUERY_MAX_LENGTH = 100;
const HOOK_MAX_LENGTH = 120;
const COPY_MAX_LENGTH = 220;
const CTA_MAX_LENGTH = 40;

function isNonEmptyString(val) {
  return typeof val === 'string' && val.trim().length > 0;
}

function validateName(raw, fieldLabel) {
  if (!isNonEmptyString(raw)) return { ok: false, error: (fieldLabel || 'Name') + ' is required' };
  const trimmed = raw.trim();
  if (trimmed.length > NAME_MAX_LENGTH) {
    return { ok: false, error: (fieldLabel || 'Name') + ' must be ' + NAME_MAX_LENGTH + ' characters or fewer' };
  }
  if (!NAME_REGEX.test(trimmed)) {
    return { ok: false, error: (fieldLabel || 'Name') + ' contains invalid characters' };
  }
  return { ok: true, value: trimmed };
}

function validateEmail(raw) {
  if (!isNonEmptyString(raw)) return { ok: false, error: 'Email is required' };
  const trimmed = raw.trim().toLowerCase();
  if (trimmed.length > EMAIL_MAX_LENGTH) {
    return { ok: false, error: 'Email must be ' + EMAIL_MAX_LENGTH + ' characters or fewer' };
  }
  if (!EMAIL_REGEX.test(trimmed)) {
    return { ok: false, error: 'Please provide a valid email address' };
  }
  return { ok: true, value: trimmed };
}

function validatePasswordLength(raw) {
  if (typeof raw !== 'string' || raw.length < PASSWORD_MIN_LENGTH) {
    return { ok: false, error: 'Password must be at least ' + PASSWORD_MIN_LENGTH + ' characters' };
  }
  if (raw.length > PASSWORD_MAX_LENGTH) {
    return { ok: false, error: 'Password must be ' + PASSWORD_MAX_LENGTH + ' characters or fewer' };
  }
  return { ok: true, value: raw };
}

function validateCapped(raw, fieldLabel, maxLength, required) {
  const trimmed = typeof raw === 'string' ? raw.trim() : '';
  if (required && !trimmed) return { ok: false, error: fieldLabel + ' is required' };
  if (trimmed.length > maxLength) {
    return { ok: false, error: fieldLabel + ' must be ' + maxLength + ' characters or fewer' };
  }
  return { ok: true, value: trimmed };
}

// ==================== MONGODB CONNECTION ====================
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/postergen';
console.log('Connecting to MongoDB:', MONGODB_URI.replace(/:([^:@]+)@/, ':****@'));

mongoose.connect(MONGODB_URI, {
  serverSelectionTimeoutMS: 30000,
  socketTimeoutMS: 45000,
  connectTimeoutMS: 30000,
}).then(function () {
  console.log('MongoDB connected');
}).catch(function (err) {
  console.error('MongoDB connection failed:', err.message);
  process.exit(1);
});

// ==================== SCHEMAS & MODELS ====================
const userSchema = new mongoose.Schema({
  id: { type: String, required: true, unique: true },
  fullName: String,
  email: { type: String, required: true, unique: true, lowercase: true },
  password: String,
  telegramChatId: String,
  isTelegramConnected: { type: Boolean, default: false },
  isSubscribed: { type: Boolean, default: false },
  subscriptionEndDate: Date,
  subscriptionPlan: String,
  pendingPaymentReference: String,
  createdAt: { type: Date, default: Date.now },
}, { timestamps: true });

const posterDailySchema = new mongoose.Schema({
  userId: { type: String, required: true },
  date: { type: String, required: true },
  count: { type: Number, default: 0 },
}, { timestamps: true });
posterDailySchema.index({ userId: 1, date: 1 }, { unique: true });

// Tracks free-tier poster generations per client IP per day, independent of
// which account made the request. This is what stops the "hit my account
// limit -> sign up again" abuse pattern: the cap follows the network, not
// the account, so a fresh account on the same IP inherits the same cap.
const ipDailySchema = new mongoose.Schema({
  ip: { type: String, required: true },
  date: { type: String, required: true },
  count: { type: Number, default: 0 },
}, { timestamps: true });
ipDailySchema.index({ ip: 1, date: 1 }, { unique: true });

// Permanently binds a device fingerprint to the FIRST free-tier account
// that generates on it. Any other account trying to generate on the same
// device is blocked outright — not rate-limited, blocked — until either
// the original account subscribes or an admin clears the binding. This is
// what actually prevents "hit my limit, make a new account" abuse, rather
// than just slowing it down.
const deviceBindingSchema = new mongoose.Schema({
  fingerprint: { type: String, required: true, unique: true },
  userId: { type: String, required: true },
  boundAt: { type: Date, default: Date.now },
}, { timestamps: true });

const adminSettingsSchema = new mongoose.Schema({
  dailyPosterLimit: { type: Number, default: 5, min: 1 },   // free-tier posters/day per account
  ipPosterMultiplier: { type: Number, default: 3, min: 1 }, // free-tier posters/day per IP = dailyPosterLimit * this
});

adminSettingsSchema.statics.getSettings = async function () {
  let settings = await this.findOne();
  if (!settings) settings = await this.create({});
  return settings;
};
adminSettingsSchema.statics.updateSettings = async function (updates) {
  let settings = await this.findOne();
  if (!settings) settings = new this();
  Object.assign(settings, updates);
  await settings.save();
  return settings;
};

const User = mongoose.model('User', userSchema);
const PosterDaily = mongoose.model('PosterDaily', posterDailySchema);
const IpDaily = mongoose.model('IpDaily', ipDailySchema);
const DeviceBinding = mongoose.model('DeviceBinding', deviceBindingSchema);
const AdminSettings = mongoose.model('AdminSettings', adminSettingsSchema);

// ==================== IN-MEMORY (auth-only, small scale) ====================
const resetTokens = new Map(); // resetToken -> { userId, code, expiresAt }

let adminSettingsCache = { dailyPosterLimit: 5, ipPosterMultiplier: 3 };

// Short-lived cache for authenticated user lookups. The dashboard fires
// several authenticated requests back-to-back on page load (me,
// subscription status, telegram connect, device status) — without this,
// each one independently re-fetches the same user from Mongo within the
// same few hundred milliseconds. A short TTL is enough to dedupe that
// burst without meaningfully risking stale reads. Every code path that
// writes to a user document MUST call invalidateUserCache(user.id)
// immediately after saving, or callers can briefly see stale data.
const USER_CACHE_TTL_MS = 5000;
const userCache = new Map(); // userId -> { user, expiresAt }

function cacheUser(user) {
  userCache.set(user.id, { user: user, expiresAt: Date.now() + USER_CACHE_TTL_MS });
}
function getCachedUser(userId) {
  const entry = userCache.get(userId);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    userCache.delete(userId);
    return null;
  }
  return entry.user;
}
function invalidateUserCache(userId) {
  userCache.delete(userId);
}

// ==================== SINGLE TELEGRAM BOT (2FA ONLY) ====================
const botPool = { authBot: null };

async function getMeWithRetry(bot, label, maxAttempts) {
  if (!maxAttempts) maxAttempts = 5;
  let attempts = 0;
  while (attempts < maxAttempts) {
    attempts++;
    try {
      return await bot.telegram.getMe();
    } catch (err) {
      console.warn(label + ' getMe attempt ' + attempts + '/' + maxAttempts + ' failed: ' + err.message);
      if (attempts >= maxAttempts) throw err;
      await new Promise(function (r) { setTimeout(r, 5000); });
    }
  }
}

async function initAuthBot() {
  const authToken = process.env.AUTH_BOT_TOKEN;
  if (!authToken) throw new Error('AUTH_BOT_TOKEN is required - the auth bot is not optional.');

  const authBot = new Telegraf(authToken);
  authBot.webhookReply = false;
  authBot.options.webhookReply = false;
  authBot.catch(function (err) { console.error('Auth bot error:', err.message); });

  const authInfo = await getMeWithRetry(authBot, 'auth bot');
  authBot.username = authInfo.username;
  botPool.authBot = authBot;
  console.log('Auth bot ready: @' + authInfo.username);
}

async function setWebhookWithRetry(bot, url, label, maxAttempts) {
  if (!maxAttempts) maxAttempts = 5;
  let attempts = 0;
  while (attempts < maxAttempts) {
    attempts++;
    try {
      const current = await bot.telegram.getWebhookInfo();
      if (current.url === url && current.pending_update_count < 50) {
        console.log('Webhook already correct for ' + label);
        return;
      }
      await bot.telegram.deleteWebhook({ drop_pending_updates: false });
      const ok = await bot.telegram.setWebhook(url, { allowed_updates: ['message', 'callback_query'] });
      if (ok) {
        console.log('Webhook set for ' + label + ' -> ' + url);
        return;
      }
    } catch (err) {
      if (err.response && err.response.error_code === 429) {
        const retryAfter = (err.response.parameters && err.response.parameters.retry_after) || 30;
        console.warn(label + ' rate limited, waiting ' + (retryAfter + 5) + 's');
        await new Promise(function (r) { setTimeout(r, (retryAfter + 5) * 1000); });
        continue;
      }
      console.error(label + ' webhook attempt ' + attempts + ' failed: ' + err.message);
      if (attempts >= maxAttempts) throw err;
      await new Promise(function (r) { setTimeout(r, 5000); });
    }
  }
  throw new Error('Gave up setting webhook for ' + label + ' after ' + maxAttempts + ' attempts');
}

async function setupAuthWebhook() {
  const authUrl = 'https://' + DOMAIN + '/webhook/auth/' + WEBHOOK_SECRET;
  await setWebhookWithRetry(botPool.authBot, authUrl, 'auth bot');
}

function registerAuthBotHandlers(authBot) {
  authBot.start(async function (ctx) {
    const payload = ctx.startPayload || '';
    const chatId = ctx.chat.id.toString();

    if (!payload) {
      await ctx.replyWithHTML('<b>Poster App Security Bot</b>\n\nUse the connect link from your dashboard to link 2FA.');
      return;
    }

    const user = await User.findOne({ id: payload });
    if (!user) {
      await ctx.replyWithHTML('<b>Invalid or expired link.</b>\n\nPlease generate a new connect link from your dashboard.');
      return;
    }

    user.telegramChatId = chatId;
    user.isTelegramConnected = true;
    await user.save();
    invalidateUserCache(user.id);

    await ctx.replyWithHTML('<b>Telegram 2FA Connected Successfully!</b>\n\nYou will receive login codes here.');
  });

  authBot.command('status', async function (ctx) {
    const chatId = ctx.chat.id.toString();
    const user = await User.findOne({ telegramChatId: chatId, isTelegramConnected: true });
    if (!user) {
      await ctx.replyWithHTML('No account is linked to this chat.');
      return;
    }
    await ctx.replyWithHTML('<b>2FA Status</b>\nAccount: <code>' + user.email + '</code>\nStatus: <b>Connected</b>');
  });
}

function generate2FACode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function send2FACodeViaBot(user, code) {
  if (!user.isTelegramConnected || !user.telegramChatId) return false;
  try {
    await botPool.authBot.telegram.sendMessage(
      user.telegramChatId,
      'Security Alert - Password Reset\n\nYour 6-digit code:\n\n<b>' + code + '</b>\n\nValid for 10 minutes.',
      { parse_mode: 'HTML' }
    );
    return true;
  } catch (err) {
    console.error('Failed to send 2FA code:', err.message);
    return false;
  }
}

// ==================== BILLING HELPERS ====================
function hasActiveSubscription(user) {
  return user.isSubscribed && user.subscriptionEndDate && new Date(user.subscriptionEndDate) > new Date();
}

function getUserLimits(user) {
  if (hasActiveSubscription(user)) return { dailyPosters: Infinity };
  return { dailyPosters: adminSettingsCache.dailyPosterLimit };
}

function getIpDailyLimit() {
  return adminSettingsCache.dailyPosterLimit * (adminSettingsCache.ipPosterMultiplier || 3);
}

function getTodayDateString() {
  return new Date().toISOString().slice(0, 10);
}

// Resolves the real client IP. `trust proxy` is set to 3 above, so Express
// already walks that many hops of X-Forwarded-For before landing on req.ip.
// We just normalize the IPv4-mapped IPv6 form (::ffff:1.2.3.4) so the same
// client doesn't get counted under two different-looking keys.
function getClientIp(req) {
  const ip = req.ip || (req.socket && req.socket.remoteAddress) || '';
  return ip.replace(/^::ffff:/, '');
}

// Reads and validates the X-Client-Fingerprint header sent by fingerprint.js
// (a 64-char lowercase hex SHA-256). Malformed or missing values are
// treated as "no fingerprint" rather than rejected outright, so older
// frontend builds that haven't picked up the header yet keep working —
// they just fall back to the IP-only cap until they update.
const FINGERPRINT_REGEX = /^[a-f0-9]{64}$/;
function getClientFingerprint(req) {
  const fp = req.headers['x-client-fingerprint'];
  if (typeof fp !== 'string' || !FINGERPRINT_REGEX.test(fp)) return null;
  return fp;
}

// Atomically binds a fingerprint to whichever userId first generates a
// poster on it. findOneAndUpdate + upsert is atomic in MongoDB, so two
// simultaneous first-time requests from the same device can't both "win"
// and create conflicting bindings — the second one just reads back the
// first one's binding. Returns the (possibly pre-existing) binding.
async function getOrBindDevice(fingerprint, userId) {
  return DeviceBinding.findOneAndUpdate(
    { fingerprint: fingerprint },
    { $setOnInsert: { fingerprint: fingerprint, userId: userId, boundAt: new Date() } },
    { upsert: true, new: true }
  );
}

async function incrementPosterCount(userId, n) {
  const today = getTodayDateString();
  const record = await PosterDaily.findOneAndUpdate(
    { userId: userId, date: today },
    { $inc: { count: n } },
    { upsert: true, new: true }
  );
  return record.count;
}

async function getTodayPosterCount(userId) {
  const today = getTodayDateString();
  const record = await PosterDaily.findOne({ userId: userId, date: today });
  return record ? record.count : 0;
}

async function incrementIpPosterCount(ip, n) {
  const today = getTodayDateString();
  const record = await IpDaily.findOneAndUpdate(
    { ip: ip, date: today },
    { $inc: { count: n } },
    { upsert: true, new: true }
  );
  return record.count;
}

async function getTodayIpPosterCount(ip) {
  const today = getTodayDateString();
  const record = await IpDaily.findOne({ ip: ip, date: today });
  return record ? record.count : 0;
}

// ==================== MIDDLEWARE ====================
// Frontend is hosted in a separate repo — this server is API-only.
app.use(cors());
// `verify` stashes the exact raw bytes this process received BEFORE JSON
// parsing/re-serialization touches them. Paystack signs those exact raw
// bytes (and when this endpoint receives a FORWARDED webhook from another
// app in the same Paystack account, that other app re-sends those same
// original bytes untouched) - so re-deriving JSON.stringify(req.body) later
// can drift from what was actually signed and cause valid webhooks to fail
// signature verification. Only the webhook route reads req.rawBody; every
// other route is unaffected.
app.use(express.json({
  limit: '2mb',
  verify: function (req, res, buf) { req.rawBody = buf; }
}));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Too many attempts' }
});

// Tighter, dedicated limiter for account creation. Login shares an IP with
// many legitimate users far more often than registration does, so this is
// deliberately stricter than authLimiter above.
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: { error: 'Too many accounts created from this network. Please try again later.' }
});

// ==================== WEBHOOK ROUTE (auth bot only) ====================
app.post('/webhook/auth/:secret', async function (req, res) {
  if (req.params.secret !== WEBHOOK_SECRET) return res.sendStatus(404);
  try {
    const update = Buffer.isBuffer(req.body) ? JSON.parse(req.body.toString('utf8')) : req.body;
    await botPool.authBot.handleUpdate(update);
  } catch (err) {
    console.error('Auth webhook handling error:', err.message);
  }
  res.sendStatus(200);
});

// ==================== JWT AUTH ====================
const authenticateToken = async function (req, res, next) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : req.query.token;

  if (!token) return res.status(401).json({ error: 'Access token required' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    let user = getCachedUser(decoded.userId);
    if (!user) {
      user = await User.findOne({ id: decoded.userId });
      if (!user) return res.status(404).json({ error: 'User not found' });
      cacheUser(user);
    }
    req.user = user;
    next();
  } catch (err) {
    res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// ==================== AUTH ROUTES ====================
app.post('/api/auth/register', registerLimiter, async function (req, res) {
  const nameCheck = validateName(req.body.fullName, 'Full name');
  if (!nameCheck.ok) return res.status(400).json({ error: nameCheck.error });

  const emailCheck = validateEmail(req.body.email);
  if (!emailCheck.ok) return res.status(400).json({ error: emailCheck.error });

  const passwordCheck = validatePasswordLength(req.body.password);
  if (!passwordCheck.ok) return res.status(400).json({ error: passwordCheck.error });

  const fullName = nameCheck.value;
  const email = emailCheck.value;
  const password = passwordCheck.value;

  const existing = await User.findOne({ email: email });
  if (existing) return res.status(409).json({ error: 'Email already exists' });

  const hashed = await bcrypt.hash(password, 12);
  const newUser = await User.create({
    id: uuidv4(),
    fullName: fullName,
    email: email,
    password: hashed,
  });

  const token = jwt.sign({ userId: newUser.id }, JWT_SECRET, { expiresIn: '7d' });
  res.status(201).json({
    success: true,
    token: token,
    user: { id: newUser.id, fullName: newUser.fullName, email: newUser.email, isTelegramConnected: false }
  });
});

app.post('/api/auth/login', authLimiter, async function (req, res) {
  const email = req.body.email;
  const password = req.body.password;
  if (!isNonEmptyString(email) || !isNonEmptyString(password)) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  if (email.length > EMAIL_MAX_LENGTH || password.length > PASSWORD_MAX_LENGTH) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  const user = await User.findOne({ email: email.toLowerCase().trim() });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
  res.json({
    success: true,
    token: token,
    user: { id: user.id, fullName: user.fullName, email: user.email, isTelegramConnected: user.isTelegramConnected }
  });
});

app.get('/api/auth/me', authenticateToken, async function (req, res) {
  const subscribed = hasActiveSubscription(req.user);
  const limits = getUserLimits(req.user);
  const usedToday = await getTodayPosterCount(req.user.id);
  res.json({
    user: {
      id: req.user.id,
      fullName: req.user.fullName,
      email: req.user.email,
      isTelegramConnected: req.user.isTelegramConnected,
      subscribed: subscribed,
      subscriptionEndDate: req.user.subscriptionEndDate || null,
      dailyPosterLimit: limits.dailyPosters === Infinity ? null : limits.dailyPosters,
      postersUsedToday: usedToday
    }
  });
});

// Lets the frontend check, BEFORE calling /generate, whether this device is
// already locked to a different free account — so it can show a clear
// message and disable the form instead of the person burning a request
// into a 403. Takes the fingerprint from the same X-Client-Fingerprint
// header /generate reads. Doesn't create a binding by itself (read-only) —
// binding only happens on an actual successful-path /generate call.
app.get('/api/device/status', authenticateToken, async function (req, res) {
  const subscribed = hasActiveSubscription(req.user);
  const clientFingerprint = getClientFingerprint(req);

  if (subscribed || !clientFingerprint) {
    return res.json({ fingerprintProvided: !!clientFingerprint, blocked: false });
  }

  const existing = await DeviceBinding.findOne({ fingerprint: clientFingerprint });
  const blocked = !!existing && existing.userId !== req.user.id;
  res.json({ fingerprintProvided: true, blocked: blocked });
});

// Bundles everything the dashboard needs on page load — account info,
// subscription status, Telegram connect link, and device-lock status —
// into ONE authenticated round trip instead of four. This is the biggest
// lever on perceived dashboard load time: each separate call pays its own
// network round-trip cost (worse than the DB query itself on a typical
// connection), and req.user is already resolved once by authenticateToken
// (and cached — see userCache above) so none of this needs a second fetch.
app.get('/api/dashboard/bootstrap', authenticateToken, async function (req, res) {
  const subscribed = hasActiveSubscription(req.user);
  const limits = getUserLimits(req.user);
  const clientFingerprint = getClientFingerprint(req);

  const [usedToday, deviceBinding] = await Promise.all([
    getTodayPosterCount(req.user.id),
    (!subscribed && clientFingerprint) ? DeviceBinding.findOne({ fingerprint: clientFingerprint }) : Promise.resolve(null)
  ]);

  const deviceBlocked = !!deviceBinding && deviceBinding.userId !== req.user.id;

  let telegramConnect = null;
  if (!req.user.isTelegramConnected) {
    const bot = botPool.authBot;
    if (bot && bot.username) {
      telegramConnect = { startLink: 'https://t.me/' + bot.username + '?start=' + req.user.id, botUsername: '@' + bot.username };
    }
  }

  res.json({
    user: {
      id: req.user.id,
      fullName: req.user.fullName,
      email: req.user.email,
      isTelegramConnected: req.user.isTelegramConnected,
      subscribed: subscribed,
      subscriptionEndDate: req.user.subscriptionEndDate || null,
      dailyPosterLimit: limits.dailyPosters === Infinity ? null : limits.dailyPosters,
      postersUsedToday: usedToday
    },
    subscription: {
      subscribed: subscribed,
      plan: subscribed ? 'premium-monthly' : 'free',
      endDate: req.user.subscriptionEndDate || null,
      daysLeft: subscribed
        ? Math.ceil((new Date(req.user.subscriptionEndDate) - new Date()) / (1000 * 60 * 60 * 24))
        : 0
    },
    telegramConnect: telegramConnect,
    device: { fingerprintProvided: !!clientFingerprint, blocked: deviceBlocked }
  });
});

app.get('/api/telegram/connect', authenticateToken, function (req, res) {
  const bot = botPool.authBot;
  if (!bot || !bot.username) {
    return res.status(503).json({ error: 'Auth bot not ready yet, try again shortly.' });
  }
  return res.json({
    success: true,
    startLink: 'https://t.me/' + bot.username + '?start=' + req.user.id,
    botUsername: '@' + bot.username
  });
});

app.post('/api/auth/disconnect-telegram', authenticateToken, async function (req, res) {
  req.user.telegramChatId = null;
  req.user.isTelegramConnected = false;
  await req.user.save();
  invalidateUserCache(req.user.id);
  res.json({ success: true, message: 'Telegram 2FA disconnected.' });
});

app.get('/api/auth/bot-status', authenticateToken, function (req, res) {
  res.json({ activated: req.user.isTelegramConnected, chatId: req.user.telegramChatId || null });
});

app.post('/api/auth/forgot-password', async function (req, res) {
  const email = req.body.email;
  if (!isNonEmptyString(email) || email.length > EMAIL_MAX_LENGTH) {
    return res.status(400).json({ error: 'Email required' });
  }

  const user = await User.findOne({ email: email.toLowerCase().trim() });
  if (!user) return res.json({ success: true, message: 'If account exists, code was sent.' });
  if (!user.isTelegramConnected) return res.status(400).json({ error: 'Telegram 2FA not connected' });

  const code = generate2FACode();
  const resetToken = uuidv4();
  resetTokens.set(resetToken, { userId: user.id, code: code, expiresAt: Date.now() + 10 * 60 * 1000 });

  const sent = await send2FACodeViaBot(user, code);
  if (!sent) return res.status(500).json({ error: 'Failed to send code' });

  res.json({ success: true, message: 'Code sent!', resetToken: resetToken });
});

app.post('/api/auth/verify-reset-code', function (req, res) {
  const resetToken = req.body.resetToken;
  const code = req.body.code;
  if (!isNonEmptyString(resetToken) || !isNonEmptyString(code)) {
    return res.status(400).json({ error: 'Token and code required' });
  }
  if (resetToken.length > 200 || code.length > 20) {
    return res.status(400).json({ error: 'Invalid or expired code' });
  }

  const entry = resetTokens.get(resetToken);
  if (!entry || Date.now() > entry.expiresAt) {
    resetTokens.delete(resetToken);
    return res.status(400).json({ error: 'Invalid or expired code' });
  }
  if (entry.code !== code.trim()) return res.status(400).json({ error: 'Wrong code' });

  res.json({ success: true, message: 'Verified', userId: entry.userId });
});

app.post('/api/auth/reset-password', async function (req, res) {
  const resetToken = req.body.resetToken;
  if (!isNonEmptyString(resetToken) || resetToken.length > 200) {
    return res.status(400).json({ error: 'Valid token and password required' });
  }

  const passwordCheck = validatePasswordLength(req.body.newPassword);
  if (!passwordCheck.ok) return res.status(400).json({ error: passwordCheck.error });
  const newPassword = passwordCheck.value;

  const entry = resetTokens.get(resetToken);
  if (!entry || Date.now() > entry.expiresAt) {
    resetTokens.delete(resetToken);
    return res.status(400).json({ error: 'Invalid session' });
  }

  const user = await User.findOne({ id: entry.userId });
  if (!user) return res.status(404).json({ error: 'User not found' });

  user.password = await bcrypt.hash(newPassword, 12);
  await user.save();
  invalidateUserCache(user.id);
  resetTokens.delete(resetToken);

  res.json({ success: true, message: 'Password reset successful' });
});

// ==================== SUBSCRIPTION ROUTES (Paystack) ====================
app.get('/api/subscription/status', authenticateToken, async function (req, res) {
  const subscribed = hasActiveSubscription(req.user);
  res.json({
    subscribed: subscribed,
    plan: subscribed ? 'premium-monthly' : 'free',
    endDate: req.user.subscriptionEndDate || null,
    daysLeft: subscribed
      ? Math.ceil((new Date(req.user.subscriptionEndDate) - new Date()) / (1000 * 60 * 60 * 24))
      : 0
  });
});

app.post('/api/subscription/initiate', authenticateToken, async function (req, res) {
  if (hasActiveSubscription(req.user)) {
    return res.status(400).json({ error: 'You already have an active subscription' });
  }

  try {
    const response = await axios.post(
      'https://api.paystack.co/transaction/initialize',
      {
        email: req.user.email,
        amount: MONTHLY_PRICE_KOBO,
        currency: 'NGN',
        callback_url: req.protocol + '://' + req.get('host') + '/subscription-success',
        metadata: { userId: req.user.id, plan: 'premium-monthly' }
      },
      { headers: { Authorization: 'Bearer ' + PAYSTACK_SECRET_KEY, 'Content-Type': 'application/json' } }
    );

    const authorization_url = response.data.data.authorization_url;
    const reference = response.data.data.reference;

    req.user.pendingPaymentReference = reference;
    await req.user.save();
    invalidateUserCache(req.user.id);

    res.json({ success: true, authorizationUrl: authorization_url, reference: reference });
  } catch (error) {
    console.error('Paystack init error:', error.response ? error.response.data : error.message);
    res.status(500).json({ error: 'Failed to initialize payment' });
  }
});

app.post('/api/subscription/webhook', async function (req, res) {
  try {
    // req.rawBody is the exact byte stream received (see the verify() hook
    // on express.json() above) - whether that came straight from Paystack
    // or was forwarded verbatim by another app sharing this Paystack
    // account. Signing THAT, not a re-serialized JSON.stringify(req.body),
    // is what makes this check reliable either way.
    const rawBody = req.rawBody || Buffer.from(JSON.stringify(req.body));
    const signatureHeader = req.headers['x-paystack-signature'];

    const hash = crypto.createHmac('sha512', PAYSTACK_SECRET_KEY)
      .update(rawBody)
      .digest('hex');

    if (!signatureHeader || hash !== signatureHeader) {
      return res.status(401).send('Invalid signature');
    }

    const event = req.body;

    if (event.event === 'charge.success') {
      const reference = event.data.reference;
      const userId = event.data.metadata && event.data.metadata.userId;
      if (!userId) return res.status(200).send('OK');

      const user = await User.findOne({ id: userId });
      if (!user || user.pendingPaymentReference !== reference) {
        return res.status(200).send('OK');
      }

      const endDate = new Date();
      endDate.setDate(endDate.getDate() + 30);

      user.isSubscribed = true;
      user.subscriptionEndDate = endDate;
      user.subscriptionPlan = 'premium-monthly';
      user.pendingPaymentReference = undefined;
      await user.save();
      invalidateUserCache(user.id);

      console.log('Subscription activated for ' + user.email + ' (ref: ' + reference + ')');
    }

    res.status(200).send('OK');
  } catch (err) {
    console.error('Webhook error:', err);
    res.status(200).send('OK');
  }
});

app.get('/subscription-success', function (req, res) {
  res.send('<!DOCTYPE html>\n<html lang="en">\n<head>\n  <meta charset="UTF-8">\n  <title>Payment Successful</title>\n  <style>\n    body{font-family:system-ui,sans-serif;background:#0a0a0a;color:#4ade80;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;}\n    .box{background:#111;padding:60px;border-radius:20px;text-align:center;box-shadow:0 0 30px rgba(74,222,128,0.2);}\n    h1{margin:0 0 20px;font-size:3em;}\n    p{font-size:1.3em;margin:20px 0;line-height:1.6;color:#e6edf7;}\n    a{display:inline-block;margin-top:30px;padding:14px 32px;background:#2563eb;color:#fff;font-weight:bold;text-decoration:none;border-radius:8px;font-size:1.1em;}\n    a:hover{background:#1d4ed8;}\n  </style>\n</head>\n<body>\n  <div class="box">\n    <h1>Payment Successful!</h1>\n    <p>Your subscription is now <strong>active</strong>.</p>\n    <p>You now have unlimited posters.</p>\n    <p><a href="https://postira.onrender.com">Return to Dashboard</a></p>\n  </div>\n</body>\n</html>');
});

// ==================== ADMIN LIMITS PANEL ====================
function renderAdminLoginForm(errorMsg) {
  return '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Admin Login</title><style>' +
    'body{font-family:"Segoe UI",sans-serif;background:#121212;color:#e0e0e0;display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;}' +
    '.box{background:#1e1e1e;padding:40px;border-radius:12px;width:90%;max-width:360px;}' +
    'h1{color:#ffd700;text-align:center;margin-bottom:20px;font-size:1.4em;}' +
    'input{width:100%;padding:12px;background:#2d2d2d;border:none;border-radius:6px;color:#fff;box-sizing:border-box;margin-bottom:12px;}' +
    'button{width:100%;padding:12px;background:#ffd700;color:#000;font-weight:bold;border:none;border-radius:6px;cursor:pointer;}' +
    '.err{color:#f44336;text-align:center;margin-bottom:12px;}' +
    '</style></head><body><div class="box"><h1>Admin Access</h1>' +
    (errorMsg ? '<div class="err">' + errorMsg + '</div>' : '') +
    '<form method="POST" action="/admin-limits"><input type="password" name="password" placeholder="Admin password" required autofocus><button type="submit">Enter</button></form></div></body></html>';
}

function renderAdminPanel(stats) {
  return '<!DOCTYPE html>\n' +
    '<html lang="en">\n<head>\n<meta charset="UTF-8">\n<meta name="viewport" content="width=device-width, initial-scale=1.0">\n<title>Admin Panel</title>\n' +
    '<style>\n' +
    'body { font-family: "Segoe UI", sans-serif; background: #121212; color: #e0e0e0; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; padding: 20px 0; }\n' +
    '.container { background: #1e1e1e; padding: 40px; border-radius: 12px; box-shadow: 0 8px 32px rgba(0,0,0,0.6); width: 90%; max-width: 600px; }\n' +
    'h1 { text-align: center; color: #ffd700; margin-bottom: 30px; }\n' +
    'h2 { font-size: 1.1em; color: #ffd700; margin: 30px 0 6px; border-top: 1px solid #333; padding-top: 24px; }\n' +
    '.stats { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 15px; margin-bottom: 30px; }\n' +
    '.stat-box { background: #2d2d2d; padding: 16px 10px; border-radius: 10px; text-align: center; }\n' +
    '.stat-number { font-size: 2em; font-weight: bold; color: #00ff41; margin: 8px 0; }\n' +
    '.stat-label { font-size: 0.95em; color: #aaa; }\n' +
    '.pool { text-align: center; margin: 15px 0; padding: 12px; background: #2d2d2d; border-radius: 8px; font-size: 0.95em; color: #8fd; }\n' +
    'label { display: block; margin: 20px 0 8px; font-size: 1.1em; }\n' +
    'input[type="number"], input[type="password"], input[type="text"] { width: 100%; padding: 12px; background: #2d2d2d; border: none; border-radius: 6px; color: white; font-size: 1em; margin-bottom: 15px; box-sizing: border-box; font-family: monospace; }\n' +
    'button { width: 100%; padding: 14px; background: #ffd700; color: black; font-weight: bold; border: none; border-radius: 6px; cursor: pointer; font-size: 1.1em; margin-top: 10px; }\n' +
    'button:hover { background: #e6c200; }\n' +
    'button.danger { background: #dc3545; color: white; }\n' +
    'button.danger:hover { background: #b02a37; }\n' +
    '.hint { font-size: 0.85em; color: #999; margin-top: -10px; margin-bottom: 15px; }\n' +
    '.msg { text-align: center; padding: 10px; border-radius: 8px; margin-bottom: 15px; font-size: 0.9em; }\n' +
    '.msg.ok { background: #17331f; color: #7ee596; }\n' +
    '.msg.err { background: #331717; color: #e57e7e; }\n' +
    '</style>\n</head>\n<body>\n<div class="container">\n<h1>Server Admin Panel</h1>\n' +
    '<div class="pool">Auth bot: ' + (authBotReady ? 'ready' : 'starting') + '</div>\n' +
    (stats.message ? '<div class="msg ' + (stats.messageType || 'ok') + '">' + stats.message + '</div>\n' : '') +
    '<div class="stats">\n' +
    '<div class="stat-box"><div class="stat-number">' + stats.totalUsers + '</div><div class="stat-label">Total Users</div></div>\n' +
    '<div class="stat-box"><div class="stat-number">' + stats.payingUsers + '</div><div class="stat-label">Paying Users</div></div>\n' +
    '<div class="stat-box"><div class="stat-number">' + stats.deviceBindings + '</div><div class="stat-label">Locked Devices</div></div>\n' +
    '</div>\n' +
    '<h2>Limits</h2>\n' +
    '<form method="POST" action="/admin-limits">\n' +
    '<input type="hidden" name="password" value="' + stats.password + '">\n' +
    '<input type="hidden" name="action" value="update_limits">\n' +
    '<label>Daily Posters per Account (Free)</label>\n' +
    '<input type="number" name="daily_posters" min="1" value="' + adminSettingsCache.dailyPosterLimit + '" required>\n' +
    '<label>Daily Posters per IP = per-account limit × this</label>\n' +
    '<div class="hint">Free-tier generations only. Current effective IP cap: ' + getIpDailyLimit() + '/day. Paying subscribers are never counted against this.</div>\n' +
    '<input type="number" name="ip_multiplier" min="1" value="' + adminSettingsCache.ipPosterMultiplier + '" required>\n' +
    '<div class="hint">Device fingerprints are handled separately, below — each device is locked to one free account permanently, not a daily cap.</div>\n' +
    '<button type="submit">Update Limits</button>\n' +
    '</form>\n' +
    '<h2>Locked devices</h2>\n' +
    '<div class="hint">Each fingerprint is permanently tied to the first free account that generated on it. Look up an account by email to see which device(s) it owns, then unlock from there — you never need to already know the raw fingerprint.</div>\n' +
    '<form method="POST" action="/admin-limits">\n' +
    '<input type="hidden" name="password" value="' + stats.password + '">\n' +
    '<input type="hidden" name="action" value="lookup_device">\n' +
    '<label>Find device(s) by account email</label>\n' +
    '<input type="text" name="lookup_email" placeholder="user@example.com" value="' + (stats.lookupEmail ? escapeHtmlAttr(stats.lookupEmail) : '') + '">\n' +
    '<button type="submit">Look up</button>\n' +
    '</form>\n' +
    (renderDeviceLookupResults(stats)) +
    '</div>\n</body>\n</html>';
}

function escapeHtmlAttr(str) {
  return (str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function renderDeviceLookupResults(stats) {
  if (!stats.lookupPerformed) return '';
  if (!stats.lookupUserFound) {
    return '<div class="msg err">No account found for that email.</div>';
  }
  if (!stats.lookupBindings || stats.lookupBindings.length === 0) {
    return '<div class="msg ok">Account found, but it has no locked device yet — it either hasn\'t generated a free poster, or it\'s subscribed (subscribers don\'t bind devices).</div>';
  }
  let html = '<div class="hint">Device(s) bound to this account:</div>';
  stats.lookupBindings.forEach(function (b) {
    html +=
      '<div style="background:#2d2d2d;border-radius:8px;padding:12px;margin-bottom:10px;">' +
      '<div style="font-family:monospace;font-size:0.8em;word-break:break-all;color:#8fd;margin-bottom:6px;">' + b.fingerprint + '</div>' +
      '<div style="font-size:0.8em;color:#999;margin-bottom:10px;">Bound ' + new Date(b.boundAt).toLocaleString() + '</div>' +
      '<form method="POST" action="/admin-limits" style="margin:0;">' +
      '<input type="hidden" name="password" value="' + stats.password + '">' +
      '<input type="hidden" name="action" value="unbind_device">' +
      '<input type="hidden" name="fingerprint" value="' + b.fingerprint + '">' +
      '<button type="submit" class="danger" style="margin-top:0;">Unlock this device</button>' +
      '</form>' +
      '</div>';
  });
  return html;
}

app.get('/admin-limits', function (req, res) {
  res.send(renderAdminLoginForm());
});

app.post('/admin-limits', async function (req, res) {
  const password = req.body.password;
  if (typeof password !== 'string' || password.length > 200 || password !== ADMIN_PASSWORD) {
    return res.status(401).send(renderAdminLoginForm('Wrong password'));
  }

  async function currentStats(extra) {
    const totalUsers = await User.countDocuments({});
    const payingUsers = await User.countDocuments({ isSubscribed: true, subscriptionEndDate: { $gt: new Date() } });
    const deviceBindings = await DeviceBinding.countDocuments({});
    return Object.assign({ totalUsers, payingUsers, deviceBindings, password }, extra || {});
  }

  const action = req.body.action;

  if (action === 'unbind_device') {
    const fingerprint = typeof req.body.fingerprint === 'string' ? req.body.fingerprint.trim().toLowerCase() : '';
    if (!fingerprint || fingerprint.length > 64) {
      return res.status(400).send(renderAdminPanel(await currentStats({ message: 'Enter a fingerprint to unlock.', messageType: 'err' })));
    }
    const result = await DeviceBinding.deleteOne({ fingerprint: fingerprint });
    const message = result.deletedCount > 0 ? 'Device unlocked — a new free account can now generate on it.' : 'No binding found for that fingerprint.';
    return res.send(renderAdminPanel(await currentStats({ message: message, messageType: result.deletedCount > 0 ? 'ok' : 'err' })));
  }

  if (action === 'lookup_device') {
    const lookupEmail = typeof req.body.lookup_email === 'string' ? req.body.lookup_email.trim().toLowerCase() : '';
    if (!lookupEmail || lookupEmail.length > EMAIL_MAX_LENGTH) {
      return res.status(400).send(renderAdminPanel(await currentStats({ message: 'Enter an email to look up.', messageType: 'err' })));
    }
    const user = await User.findOne({ email: lookupEmail });
    if (!user) {
      return res.send(renderAdminPanel(await currentStats({ lookupPerformed: true, lookupUserFound: false, lookupEmail: lookupEmail })));
    }
    const bindings = await DeviceBinding.find({ userId: user.id }).sort({ boundAt: -1 });
    return res.send(renderAdminPanel(await currentStats({
      lookupPerformed: true,
      lookupUserFound: true,
      lookupEmail: lookupEmail,
      lookupBindings: bindings.map(function (b) { return { fingerprint: b.fingerprint, boundAt: b.boundAt }; })
    })));
  }

  if (req.body.daily_posters === undefined) {
    return res.send(renderAdminPanel(await currentStats()));
  }

  const newDaily = parseInt(req.body.daily_posters, 10);
  const newIpMultiplier = req.body.ip_multiplier !== undefined ? parseInt(req.body.ip_multiplier, 10) : adminSettingsCache.ipPosterMultiplier;
  if (isNaN(newDaily) || newDaily < 1 || isNaN(newIpMultiplier) || newIpMultiplier < 1) {
    return res.status(400).send(renderAdminPanel(await currentStats({ message: 'Please enter valid, positive numbers.', messageType: 'err' })));
  }

  await AdminSettings.updateSettings({ dailyPosterLimit: newDaily, ipPosterMultiplier: newIpMultiplier });
  adminSettingsCache = { dailyPosterLimit: newDaily, ipPosterMultiplier: newIpMultiplier };
  console.log('Admin limits updated:', adminSettingsCache);

  res.send(renderAdminPanel(await currentStats({ message: 'Limits updated.', messageType: 'ok' })));
});

// ==================== POSTER GENERATION CORE (image only) ====================
const LAYOUT_POST = { width: 1080, height: 1350, photoHeight: 950 };
const JPEG_QUALITY = 82;

const ACCENT_PALETTE = [
  '#E63946', '#F4A261', '#2A9D8F', '#457B9D', '#8338EC',
  '#FF006E', '#06D6A0', '#FFD60A', '#EF476F', '#118AB2'
];
let paletteIndex = 0;
function nextAccentColor() {
  const color = ACCENT_PALETTE[paletteIndex % ACCENT_PALETTE.length];
  paletteIndex++;
  return color;
}

function PEXELS_BASE_URL(query, orientation) {
  return 'https://api.pexels.com/v1/search?query=' + encodeURIComponent(query) + '&per_page=10&orientation=' + orientation;
}

// Pixabay uses vertical/horizontal/all instead of portrait/landscape/square.
function pixabayOrientation(orientation) {
  if (orientation === 'landscape') return 'horizontal';
  if (orientation === 'portrait') return 'vertical';
  return 'all'; // square or unknown
}

async function searchPexelsPhoto(query, apiKey, opts) {
  const orientation = (opts && opts.orientation) || 'portrait';
  if (!apiKey) throw new Error('Missing PEXELS_API_KEY');
  if (!query) throw new Error('Missing search query');

  const url = PEXELS_BASE_URL(query, orientation);
  const res = await fetch(url, { headers: { Authorization: apiKey } });
  if (!res.ok) {
    const err = new Error('Pexels search failed: ' + res.status);
    err.status = res.status;
    err.provider = 'pexels';
    throw err;
  }

  const data = await res.json();
  const photo = data.photos && data.photos[0];
  if (!photo) throw new Error('No Pexels results for "' + query + '"');

  return {
    id: photo.id,
    photographer: photo.photographer,
    photoUrl: photo.src.large2x || photo.src.large || photo.src.original,
    sourcePageUrl: photo.url,
    provider: 'pexels'
  };
}

async function searchPixabayPhoto(query, apiKey, opts) {
  const orientation = (opts && opts.orientation) || 'portrait';
  if (!apiKey) throw new Error('Missing PIXABAY_API_KEY');
  if (!query) throw new Error('Missing search query');

  const params = new URLSearchParams({
    key: apiKey,
    q: query,
    image_type: 'photo',
    orientation: pixabayOrientation(orientation),
    per_page: '10',
    safesearch: 'true'
  });
  const url = 'https://pixabay.com/api/?' + params.toString();
  const res = await fetch(url);
  if (!res.ok) {
    const err = new Error('Pixabay search failed: ' + res.status);
    err.status = res.status;
    err.provider = 'pixabay';
    throw err;
  }

  const data = await res.json();
  const hit = data.hits && data.hits[0];
  if (!hit) throw new Error('No Pixabay results for "' + query + '"');

  return {
    id: hit.id,
    photographer: hit.user || 'Pixabay',
    photoUrl: hit.largeImageURL || hit.webformatURL,
    sourcePageUrl: hit.pageURL,
    provider: 'pixabay'
  };
}

// Prefer Pexels; on rate-limit (429), network/API failure, or empty results,
// fall back to Pixabay when a key is configured.
async function searchStockPhoto(query, opts) {
  if (!query) throw new Error('Missing search query');

  let pexelsErr = null;
  if (PEXELS_API_KEY) {
    try {
      return await searchPexelsPhoto(query, PEXELS_API_KEY, opts);
    } catch (err) {
      pexelsErr = err;
      const isRateLimit = err.status === 429;
      const isHardFail = err.status && err.status >= 400;
      console.warn(
        'Pexels failed (' + (err.status || err.message) + ')' +
        (isRateLimit ? ' — rate limited' : '') +
        '; trying Pixabay fallback…'
      );
      if (!PIXABAY_API_KEY) {
        throw err;
      }
      // Fall through to Pixabay for rate limits and other failures.
      if (!isRateLimit && !isHardFail && !/No Pexels results/.test(err.message)) {
        // unexpected non-HTTP error still gets fallback if Pixabay is available
      }
    }
  }

  if (PIXABAY_API_KEY) {
    try {
      return await searchPixabayPhoto(query, PIXABAY_API_KEY, opts);
    } catch (err) {
      if (pexelsErr) {
        throw new Error(
          'Both stock providers failed. Pexels: ' + pexelsErr.message +
          '; Pixabay: ' + err.message
        );
      }
      throw err;
    }
  }

  throw pexelsErr || new Error('No stock photo API key configured (PEXELS_API_KEY / PIXABAY_API_KEY)');
}

function escapeXml(str) {
  str = str || '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function wrapText(text, maxCharsPerLine) {
  const words = text.split(' ');
  const lines = [];
  let current = '';
  for (const word of words) {
    if ((current + ' ' + word).trim().length > maxCharsPerLine) {
      lines.push(current.trim());
      current = word;
    } else {
      current += ' ' + word;
    }
  }
  if (current.trim()) lines.push(current.trim());
  return lines;
}

function fitTextBlock(text, opts) {
  const maxWidth = opts.maxWidth, maxHeight = opts.maxHeight;
  let fontSize = opts.startFontSize;
  const minFontSize = opts.minFontSize;
  const weightFactor = opts.weightFactor;
  const lineHeightRatio = opts.lineHeightRatio || 1.22;
  const step = opts.step || 2;

  let lines = [];
  let lineHeight = 0;

  while (fontSize >= minFontSize) {
    const maxCharsPerLine = Math.max(4, Math.floor(maxWidth / (fontSize * weightFactor)));
    lines = wrapText(text || '', maxCharsPerLine);
    lineHeight = fontSize * lineHeightRatio;
    const totalHeight = lines.length * lineHeight;
    if (totalHeight <= maxHeight || fontSize === minFontSize) break;
    fontSize -= step;
  }

  return { fontSize: fontSize, lines: lines, lineHeight: lineHeight, totalHeight: lines.length * lineHeight };
}

const GAP_HOOK_COPY = 22;
const GAP_COPY_CTA = 30;

function buildOverlaySvg(opts) {
  const hook = opts.hook, copy = opts.copy, cta = opts.cta, layout = opts.layout;
  const width = layout.width, height = layout.height, photoHeight = layout.photoHeight;
  const textHeight = height - photoHeight;
  const accentColor = nextAccentColor();
  const usableWidth = width - 160;
  const ctaHeight = 64;

  const hookFit = fitTextBlock(hook, {
    maxWidth: usableWidth, maxHeight: textHeight * 0.55,
    startFontSize: 58, minFontSize: 30, weightFactor: 0.58
  });
  const copyFit = fitTextBlock(copy, {
    maxWidth: usableWidth, maxHeight: textHeight * 0.3,
    startFontSize: 32, minFontSize: 18, weightFactor: 0.5
  });

  let ctaFontSize = 30;
  let ctaText = escapeXml(cta || 'Learn More');
  let ctaWidth = Math.max(240, ctaText.length * (ctaFontSize * 0.62) + 80);
  const maxCtaWidth = width - 160;
  if (ctaWidth > maxCtaWidth) {
    ctaFontSize = Math.max(18, Math.floor(ctaFontSize * (maxCtaWidth / ctaWidth)));
    ctaWidth = maxCtaWidth;
  }

  let stackHeight = hookFit.totalHeight + GAP_HOOK_COPY + copyFit.totalHeight + GAP_COPY_CTA + ctaHeight;
  let gapHookCopy = GAP_HOOK_COPY;
  let gapCopyCta = GAP_COPY_CTA;
  if (stackHeight > textHeight) {
    const overflow = stackHeight - textHeight;
    const shrink = Math.min(overflow / 2, GAP_HOOK_COPY - 8, GAP_COPY_CTA - 8);
    if (shrink > 0) {
      gapHookCopy -= shrink;
      gapCopyCta -= shrink;
      stackHeight -= shrink * 2;
    }
  }

  const TOP_PADDING = 40;
  const lowestFittingTop = photoHeight + Math.max(0, textHeight - stackHeight);
  const stackTop = Math.min(photoHeight + TOP_PADDING, lowestFittingTop);

  const hookBlockTop = stackTop;
  const hookStartY = hookBlockTop + hookFit.fontSize * 0.85;

  const copyBlockTop = hookBlockTop + hookFit.totalHeight + gapHookCopy;
  const copyStartY = copyBlockTop + copyFit.fontSize * 0.85;

  const ctaY = copyBlockTop + copyFit.totalHeight + gapCopyCta;

  const hookTspans = hookFit.lines
    .map(function (line, i) { return '<tspan x="50%" dy="' + (i === 0 ? 0 : hookFit.lineHeight) + '">' + escapeXml(line) + '</tspan>'; })
    .join('');
  const copyTspans = copyFit.lines
    .map(function (line, i) { return '<tspan x="50%" dy="' + (i === 0 ? 0 : copyFit.lineHeight) + '">' + escapeXml(line) + '</tspan>'; })
    .join('');

  const ctaX = (width - ctaWidth) / 2;

  return '\n  <svg width="' + width + '" height="' + height + '">\n' +
    '    <defs>\n      <style>\n' +
    '        .hook { font-weight: 800; font-family: sans-serif; fill: #ffffff; }\n' +
    '        .copy { font-weight: 700; font-family: sans-serif; fill: #ffffff; }\n' +
    '        .cta { font-weight: 800; font-family: sans-serif; fill: #ffffff; }\n' +
    '      </style>\n    </defs>\n' +
    '    <rect x="0" y="' + photoHeight + '" width="' + width + '" height="' + textHeight + '" fill="#0d0d0d"/>\n' +
    '    <rect x="0" y="' + photoHeight + '" width="' + width + '" height="6" fill="' + accentColor + '"/>\n' +
    '    <text x="50%" y="' + hookStartY + '" text-anchor="middle" class="hook" style="font-size:' + hookFit.fontSize + 'px">' + hookTspans + '</text>\n' +
    '    <text x="50%" y="' + copyStartY + '" text-anchor="middle" class="copy" style="font-size:' + copyFit.fontSize + 'px">' + copyTspans + '</text>\n' +
    '    <rect x="' + ctaX + '" y="' + ctaY + '" width="' + ctaWidth + '" height="' + ctaHeight + '" rx="32" fill="' + accentColor + '"/>\n' +
    '    <text x="50%" y="' + (ctaY + ctaHeight / 2 + ctaFontSize * 0.35) + '" text-anchor="middle" class="cta" style="font-size:' + ctaFontSize + 'px">' + ctaText + '</text>\n' +
    '  </svg>';
}

async function generatePosterImage(opts) {
  const photoUrl = opts.photoUrl, hook = opts.hook, copy = opts.copy, cta = opts.cta;
  const layout = opts.layout || LAYOUT_POST;

  const photoRes = await fetch(photoUrl);
  if (!photoRes.ok) throw new Error('Failed to download photo: ' + photoRes.status);
  const photoBuffer = Buffer.from(await photoRes.arrayBuffer());

  const photoResized = await sharp(photoBuffer)
    .resize(layout.width, layout.photoHeight, { fit: 'cover' })
    .toBuffer();

  const overlaySvg = buildOverlaySvg({ hook: hook, copy: copy, cta: cta, layout: layout });

  return sharp({
    create: { width: layout.width, height: layout.height, channels: 3, background: '#0d0d0d' }
  })
    .composite([
      { input: photoResized, top: 0, left: 0 },
      { input: Buffer.from(overlaySvg), top: 0, left: 0 }
    ])
    .jpeg({ quality: JPEG_QUALITY, mozjpeg: true })
    .toBuffer();
}

// ==================== POSTER ROUTES (authenticated) ====================
// Generates and returns the JPEG directly. Counts against the daily quota.
app.get('/generate', authenticateToken, async function (req, res) {
  try {
    const queryCheck = validateCapped(req.query.query, 'query', QUERY_MAX_LENGTH, true);
    if (!queryCheck.ok) return res.status(400).json({ error: queryCheck.error });
    const hookCheck = validateCapped(req.query.hook, 'hook', HOOK_MAX_LENGTH, true);
    if (!hookCheck.ok) return res.status(400).json({ error: hookCheck.error });
    const copyCheck = validateCapped(req.query.copy, 'copy', COPY_MAX_LENGTH, false);
    if (!copyCheck.ok) return res.status(400).json({ error: copyCheck.error });
    const ctaCheck = validateCapped(req.query.cta, 'cta', CTA_MAX_LENGTH, false);
    if (!ctaCheck.ok) return res.status(400).json({ error: ctaCheck.error });

    const subscribed = hasActiveSubscription(req.user);
    const limits = getUserLimits(req.user);
    const usedToday = await getTodayPosterCount(req.user.id);
    if (limits.dailyPosters !== Infinity && usedToday >= limits.dailyPosters) {
      return res.status(403).json({ error: 'Daily poster limit reached. Subscribe for unlimited posters.' });
    }

    // IP-based cap: only counted/enforced for free-tier requests, so paying
    // subscribers sharing a network (offices, campuses, cafes) are never
    // blocked by it. This is what stops "hit my account limit -> sign up
    // again" abuse — the cap follows the network, not the account, so a
    // brand-new free account on an already-capped IP fails immediately.
    const clientIp = getClientIp(req);
    if (!subscribed && clientIp) {
      const ipDailyLimit = getIpDailyLimit();
      const ipUsedToday = await getTodayIpPosterCount(clientIp);
      if (ipUsedToday >= ipDailyLimit) {
        return res.status(403).json({ error: 'Daily poster limit reached for this network. Subscribe for unlimited posters.' });
      }
    }

    // Device binding: hard rule, not a quota. The first free-tier account
    // to generate on this fingerprint owns it. Any other account on the
    // same device is blocked outright, every time, regardless of its own
    // remaining daily allowance — that's what actually stops "make a new
    // account" abuse instead of just slowing it down.
    const clientFingerprint = getClientFingerprint(req);
    if (!subscribed && clientFingerprint) {
      const binding = await getOrBindDevice(clientFingerprint, req.user.id);
      if (binding.userId !== req.user.id) {
        return res.status(403).json({ error: 'This device has already generated posters on a different account. Each device is limited to one free account — subscribe to use additional accounts on this device.' });
      }
    }

    const orientation = req.query.orientation === 'landscape' || req.query.orientation === 'square' ? req.query.orientation : 'portrait';

    const photo = await searchStockPhoto(queryCheck.value, { orientation: orientation });
    const imageBuffer = await generatePosterImage({
      photoUrl: photo.photoUrl, hook: hookCheck.value, copy: copyCheck.value, cta: ctaCheck.value, layout: LAYOUT_POST
    });

    await incrementPosterCount(req.user.id, 1);
    if (!subscribed && clientIp) {
      await incrementIpPosterCount(clientIp, 1);
    }

    res.set('Content-Type', 'image/jpeg');
    res.set('Content-Disposition', 'inline; filename="' + hookCheck.value.replace(/\s+/g, '_').slice(0, 40) + '.jpg"');
    res.send(imageBuffer);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ==================== ROOT (API-only — frontend lives in another repo) ====================
app.get('/', function (req, res) {
  res.json({
    name: 'Marketing Poster Generator API',
    build: BUILD_TAG,
    docs: {
      auth: ['POST /api/auth/register', 'POST /api/auth/login', 'GET /api/auth/me'],
      generate: 'GET /generate?query=&hook=&copy=&cta=&orientation=portrait',
      subscription: ['GET /api/subscription/status', 'POST /api/subscription/initiate'],
      admin: 'GET|POST /admin-limits',
      health: 'GET /ping'
    }
  });
});

// ==================== HEALTH CHECK ====================
app.get('/ping', function (req, res) {
  if (!authBotReady) return res.status(503).type('text/plain').send('auth bot starting up [' + BUILD_TAG + ']');
  if (!serverReady) return res.status(200).type('text/plain').send('auth ok, server starting [' + BUILD_TAG + ']');
  res.status(200).type('text/plain').send('ok [' + BUILD_TAG + ']');
});

app.use(function (req, res) {
  res.status(404).json({ error: 'Not found' });
});

// ==================== STARTUP ====================
async function loadAdminSettings() {
  try {
    const settings = await AdminSettings.getSettings();
    adminSettingsCache = { dailyPosterLimit: settings.dailyPosterLimit, ipPosterMultiplier: settings.ipPosterMultiplier };
    console.log('Admin settings loaded from DB:', adminSettingsCache);
  } catch (err) {
    console.error('Failed to load admin settings:', err);
  }
}

mongoose.connection.once('open', async function () {
  try {
    await loadAdminSettings();

    await initAuthBot();
    registerAuthBotHandlers(botPool.authBot);
    await setupAuthWebhook();
    authBotReady = true;
    console.log('Auth bot fully ready - login/2FA is live.');

    serverReady = true;
    console.log('Startup sequence completed - server is now accepting all requests');

    app.listen(PORT, function () {
      console.log('Marketing poster generator (image only) running on port ' + PORT + ' | Domain: https://' + DOMAIN);
    });
  } catch (err) {
    console.error('FATAL: startup sequence failed, exiting:', err.message);
    process.exit(1);
  }
});

process.on('SIGTERM', function () { console.log('Shutting down...'); process.exit(0); });
process.on('SIGINT', function () { console.log('Shutting down...'); process.exit(0); });
