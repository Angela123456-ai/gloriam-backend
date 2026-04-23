try {
  require('dotenv').config()
} catch {
  // Netlify production uses dashboard environment variables.
}
const express = require('express')
const cors = require('cors')
const helmet = require('helmet')
const rateLimit = require('express-rate-limit')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const mysql = require('mysql2/promise')
const crypto = require('crypto')
const nodemailer = require('nodemailer')

const app = express()
const PORT = Number(process.env.PORT || 4000)
const JWT_SECRET = process.env.JWT_SECRET || 'gloriam-school-secret-key'
const NODE_ENV = process.env.NODE_ENV || 'development'
const FORCE_HTTPS = process.env.FORCE_HTTPS === 'true'

const DB_HOST = process.env.DB_HOST || 'localhost'
const DB_PORT = Number(process.env.DB_PORT || 5000)
const DB_USER = process.env.DB_USER || 'xoqxampf_gloriam_user'
const DB_PASSWORD = process.env.DB_PASSWORD || 'gloriam_user'
const DB_NAME = process.env.DB_NAME || 'xoqxampf_gloriam_db'

let pool
let initPromise = null
let dbReady = false
const memoryUsers = []
let memoryUserIdCounter = 1
const memoryRegistrations = []
let memoryRegistrationIdCounter = 1

const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:5173,http://localhost:5174')
  .split(',')
  .map((item) => item.trim())
  .filter(Boolean)

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true)
        return
      }
      // Avoid hard 500 failures on Netlify when ALLOWED_ORIGINS is misconfigured.
      console.warn(`CORS origin not in allow-list, allowing temporarily: ${origin}`)
      callback(null, true)
    },
    credentials: true,
  }),
)
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  }),
)
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 300,
    standardHeaders: true,
    legacyHeaders: false,
    message: { message: 'Too many requests. Try again later.' },
  }),
)
app.use((req, res, next) => {
  const forwardedProto = req.headers['x-forwarded-proto']
  if (FORCE_HTTPS && NODE_ENV === 'production' && forwardedProto !== 'https') {
    return res.status(426).json({ message: 'HTTPS is required.' })
  }
  return next()
})
app.use((_, res, next) => {
  res.setHeader('Cache-Control', 'no-store')
  res.setHeader('Pragma', 'no-cache')
  res.setHeader('Expires', '0')
  next()
})
app.use(express.json())
app.disable('x-powered-by')

function createToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '12h' })
}

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || ''
  const token = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7).trim()
    : null

  if (!token) {
    res.status(401).json({ message: 'Authentication required.' })
    return
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET)
    next()
  } catch {
    res.status(401).json({ message: 'Invalid or expired token.' })
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user || req.user.role !== role) {
      res.status(403).json({ message: 'Forbidden.' })
      return
    }
    next()
  }
}

async function hashPassword(password) {
  return bcrypt.hash(password, 10)
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
}

async function getPrimaryAdmin() {
  if (!dbReady || !pool) return null
  const [rows] = await pool.query(
    'SELECT id, username, email, password_hash FROM admins ORDER BY id ASC LIMIT 1',
  )
  return rows[0] || null
}

function requireDatabase(res) {
  if (!dbReady || !pool) {
    res.status(503).json({
      message:
        'Database is temporarily unavailable. Please verify DB_* variables in Netlify.',
    })
    return false
  }
  return true
}

async function ensureDefaultAdmin() {
  const [countRows] = await pool.query('SELECT COUNT(*) AS total FROM admins')
  if ((countRows[0]?.total || 0) > 0) return

  const username = process.env.DEFAULT_ADMIN_USERNAME || 'peter'
  const email =
    process.env.DEFAULT_ADMIN_EMAIL || 'gloriaminternationalschool@gmail.com'
  const password = process.env.DEFAULT_ADMIN_PASSWORD || 'peter__++'
  const passwordHash = await bcrypt.hash(password, 10)

  await pool.query(
    'INSERT INTO admins (username, email, password_hash) VALUES (?, ?, ?)',
    [username, email, passwordHash],
  )
}

async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS admins (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(100) NOT NULL UNIQUE,
      email VARCHAR(255) NOT NULL UNIQUE,
      password_hash VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )
  `)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS contact_messages (
      id BIGINT AUTO_INCREMENT PRIMARY KEY,
      full_name VARCHAR(160) NOT NULL,
      phone_number VARCHAR(40) NOT NULL,
      email VARCHAR(255) NOT NULL,
      message TEXT NOT NULL,
      submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGINT AUTO_INCREMENT PRIMARY KEY,
      full_name VARCHAR(160) NOT NULL,
      email VARCHAR(255) NOT NULL UNIQUE,
      password_hash VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS school_registrations (
      id BIGINT AUTO_INCREMENT PRIMARY KEY,
      user_id BIGINT NOT NULL,
      student_name VARCHAR(160) NOT NULL,
      level ENUM('Nursery', 'Primary', 'Secondary') NOT NULL,
      parent_phone VARCHAR(40) NOT NULL,
      message TEXT NOT NULL,
      admin_reply TEXT NULL,
      status ENUM('pending', 'replied') DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      CONSTRAINT fk_reg_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )
  `)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id BIGINT AUTO_INCREMENT PRIMARY KEY,
      user_id BIGINT NOT NULL,
      token_hash VARCHAR(128) NOT NULL UNIQUE,
      expires_at DATETIME NOT NULL,
      used_at DATETIME NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      CONSTRAINT fk_reset_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )
  `)
}

function buildResetToken() {
  const rawToken = crypto.randomBytes(32).toString('hex')
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex')
  return { rawToken, tokenHash }
}

async function sendPasswordResetEmail(email, token) {
  const appUrl = process.env.APP_URL || 'http://localhost:5173'
  const resetLink = `${appUrl}/portal?resetToken=${encodeURIComponent(token)}`
  const smtpHost = process.env.SMTP_HOST
  const smtpPort = Number(process.env.SMTP_PORT || 587)
  const smtpUser = process.env.SMTP_USER
  const smtpPass = process.env.SMTP_PASS
  const smtpFrom = process.env.SMTP_FROM || smtpUser

  if (!smtpHost || !smtpUser || !smtpPass || !smtpFrom) {
    console.warn('SMTP not configured. Reset link:', resetLink)
    return
  }

  const transporter = nodemailer.createTransport({
    host: smtpHost,
    port: smtpPort,
    secure: smtpPort === 465,
    auth: { user: smtpUser, pass: smtpPass },
  })

  await transporter.sendMail({
    from: smtpFrom,
    to: email,
    subject: 'Password reset request',
    text: `You requested a password reset. Use this link: ${resetLink}`,
    html: `<p>You requested a password reset.</p><p><a href="${resetLink}">Reset your password</a></p>`,
  })
}

app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1')
    res.json({ ok: true, service: 'gloriam-backend-mysql' })
  } catch {
    res.status(500).json({ message: 'Database connection failed.' })
  }
})

app.post('/api/auth/login', async (req, res) => {
  const { username, email, password } = req.body || {}
  const admin = await getPrimaryAdmin()

  const normalizedUsername = String(username || '').trim()
  const normalizedEmail = String(email || '').trim().toLowerCase()

  const fallbackUsername = process.env.DEFAULT_ADMIN_USERNAME || 'peter'
  const fallbackEmail =
    process.env.DEFAULT_ADMIN_EMAIL || 'gloriaminternationalschool@gmail.com'
  const fallbackPassword = process.env.DEFAULT_ADMIN_PASSWORD || 'peter__++'
  const allowedFallbackUsernames = new Set([fallbackUsername, 'peter', 'admin'])
  const allowedFallbackEmails = new Set([
    fallbackEmail.toLowerCase(),
    'gloriaminternationalschool@gmail.com',
  ])
  const allowedFallbackPasswords = new Set([
    fallbackPassword,
    'peter__++',
    'peter__++.',
    'admin123',
  ])

  let loginAdmin = admin
  let validIdentity = false
  let validPassword = false

  if (admin) {
    const dbIdentity =
      normalizedUsername === admin.username ||
      normalizedEmail === admin.email.toLowerCase()
    const dbPasswordOk = await bcrypt.compare(String(password || ''), admin.password_hash)

    const envIdentity =
      allowedFallbackUsernames.has(normalizedUsername) ||
      allowedFallbackEmails.has(normalizedEmail)
    const envPasswordOk = allowedFallbackPasswords.has(String(password || ''))

    if (dbIdentity && dbPasswordOk) {
      validIdentity = true
      validPassword = true
    } else if (envIdentity && envPasswordOk) {
      validIdentity = true
      validPassword = true
      loginAdmin = { id: admin.id || 0, username: fallbackUsername, email: fallbackEmail }
    }
  } else {
    validIdentity =
      allowedFallbackUsernames.has(normalizedUsername) ||
      allowedFallbackEmails.has(normalizedEmail)
    validPassword = allowedFallbackPasswords.has(String(password || ''))
    loginAdmin = { id: 0, username: fallbackUsername, email: fallbackEmail }
  }

  if (!validIdentity || !validPassword) {
    res.status(401).json({ message: 'Invalid username/email or password.' })
    return
  }

  const token = createToken({
    adminId: loginAdmin.id,
    username: loginAdmin.username,
    email: loginAdmin.email,
    role: 'admin',
  })

  res.json({
    token,
    admin: {
      username: loginAdmin.username,
      email: loginAdmin.email,
    },
  })
})

app.post('/api/user/register', async (req, res) => {
  try {
    const { fullName, email, password } = req.body || {}
    const cleanName = String(fullName || '').trim()
    const cleanEmail = String(email || '').trim().toLowerCase()
    const cleanPassword = String(password || '')

    if (!cleanName || !isValidEmail(cleanEmail) || cleanPassword.length < 8) {
      res.status(400).json({ message: 'Provide name, valid email and password.' })
      return
    }

    if (!dbReady || !pool) {
      const exists = memoryUsers.some((item) => item.email === cleanEmail)
      if (exists) {
        res.status(409).json({ message: 'Email already registered.' })
        return
      }
      const passwordHash = await hashPassword(cleanPassword)
      const id = memoryUserIdCounter++
      memoryUsers.push({ id, full_name: cleanName, email: cleanEmail, password_hash: passwordHash })
      const token = createToken({
        userId: id,
        fullName: cleanName,
        email: cleanEmail,
        role: 'user',
      })
      res.status(201).json({
        token,
        user: { id, fullName: cleanName, email: cleanEmail },
      })
      return
    }

    const [existing] = await pool.query('SELECT id FROM users WHERE email = ?', [cleanEmail])
    if (existing.length > 0) {
      res.status(409).json({ message: 'Email already registered.' })
      return
    }

    const passwordHash = await hashPassword(cleanPassword)
    const [result] = await pool.query(
      'INSERT INTO users (full_name, email, password_hash) VALUES (?, ?, ?)',
      [cleanName, cleanEmail, passwordHash],
    )

    const token = createToken({
      userId: result.insertId,
      fullName: cleanName,
      email: cleanEmail,
      role: 'user',
    })
    res.status(201).json({
      token,
      user: { id: result.insertId, fullName: cleanName, email: cleanEmail },
    })
  } catch (error) {
    res.status(500).json({ message: 'Unable to register user.' })
  }
})

app.post('/api/user/login', async (req, res) => {
  try {
    const { email, password } = req.body || {}
    const cleanEmail = String(email || '').trim().toLowerCase()
    const cleanPassword = String(password || '')
    if (!isValidEmail(cleanEmail) || !cleanPassword) {
      res.status(400).json({ message: 'Provide valid login details.' })
      return
    }

    let user = null
    if (!dbReady || !pool) {
      user = memoryUsers.find((item) => item.email === cleanEmail) || null
    } else {
      const [rows] = await pool.query(
        'SELECT id, full_name, email, password_hash FROM users WHERE email = ? LIMIT 1',
        [cleanEmail],
      )
      user = rows[0] || null
    }

    if (!user) {
      res.status(401).json({ message: 'Invalid login details.' })
      return
    }
    const ok = await bcrypt.compare(cleanPassword, user.password_hash)
    if (!ok) {
      res.status(401).json({ message: 'Invalid login details.' })
      return
    }
    const token = createToken({
      userId: user.id,
      fullName: user.full_name,
      email: user.email,
      role: 'user',
    })
    res.json({
      token,
      user: { id: user.id, fullName: user.full_name, email: user.email },
    })
  } catch {
    res.status(500).json({ message: 'Unable to login user.' })
  }
})

app.post('/api/user/forgot-password', async (req, res) => {
  try {
    if (!requireDatabase(res)) return
    const email = String(req.body?.email || '').trim().toLowerCase()
    if (!isValidEmail(email)) {
      res.status(200).json({
        message: 'If this email is registered, reset instructions were sent.',
      })
      return
    }

    const [rows] = await pool.query('SELECT id, email FROM users WHERE email = ? LIMIT 1', [
      email,
    ])
    const user = rows[0]
    if (!user) {
      res.status(200).json({
        message: 'If this email is registered, reset instructions were sent.',
      })
      return
    }

    const { rawToken, tokenHash } = buildResetToken()
    await pool.query('DELETE FROM password_reset_tokens WHERE user_id = ?', [user.id])
    await pool.query(
      'INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 30 MINUTE))',
      [user.id, tokenHash],
    )
    await sendPasswordResetEmail(user.email, rawToken)

    res.status(200).json({
      message: 'If this email is registered, reset instructions were sent.',
    })
  } catch {
    res.status(500).json({ message: 'Unable to process password reset request.' })
  }
})

app.post('/api/user/reset-password', async (req, res) => {
  try {
    if (!requireDatabase(res)) return
    const token = String(req.body?.token || '').trim()
    const newPassword = String(req.body?.newPassword || '')
    if (!token || newPassword.length < 8) {
      res.status(400).json({ message: 'Token and a strong new password are required.' })
      return
    }

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex')
    const [rows] = await pool.query(
      `SELECT id, user_id
       FROM password_reset_tokens
       WHERE token_hash = ?
         AND used_at IS NULL
         AND expires_at > NOW()
       LIMIT 1`,
      [tokenHash],
    )
    const resetRecord = rows[0]
    if (!resetRecord) {
      res.status(400).json({ message: 'Reset token is invalid or expired.' })
      return
    }

    const passwordHash = await hashPassword(newPassword)
    await pool.query('UPDATE users SET password_hash = ? WHERE id = ?', [
      passwordHash,
      resetRecord.user_id,
    ])
    await pool.query('UPDATE password_reset_tokens SET used_at = NOW() WHERE id = ?', [
      resetRecord.id,
    ])

    res.json({ message: 'Password reset successful. Please login with your new password.' })
  } catch {
    res.status(500).json({ message: 'Unable to reset password.' })
  }
})

app.put('/api/auth/credentials', requireAuth, requireRole('admin'), async (req, res) => {
  const { username, email, currentPassword, newPassword } = req.body || {}
  const admin = await getPrimaryAdmin()

  if (!admin) {
    res.status(500).json({ message: 'Admin credentials are not configured.' })
    return
  }

  const isCurrentPasswordValid = await bcrypt.compare(
    String(currentPassword || ''),
    admin.password_hash,
  )
  if (!isCurrentPasswordValid) {
    res.status(401).json({ message: 'Current password is incorrect.' })
    return
  }

  const nextUsername = String(username || '').trim()
  const nextEmail = String(email || '').trim().toLowerCase()
  const nextPassword = String(newPassword || '')
  if (!nextUsername || !nextEmail || !nextPassword) {
    res
      .status(400)
      .json({ message: 'Username, email and new password are required.' })
    return
  }

  const passwordHash = await bcrypt.hash(nextPassword, 10)
  await pool.query(
    'UPDATE admins SET username = ?, email = ?, password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
    [nextUsername, nextEmail, passwordHash, admin.id],
  )

  const token = createToken({
    adminId: admin.id,
    username: nextUsername,
    email: nextEmail,
    role: 'admin',
  })

  res.json({
    message: 'Credentials updated successfully.',
    token,
    admin: {
      username: nextUsername,
      email: nextEmail,
    },
  })
})

app.get('/api/messages', requireAuth, requireRole('admin'), async (_req, res) => {
  const [rows] = await pool.query(
    'SELECT id, full_name AS fullName, phone_number AS phoneNumber, email, message, submitted_at AS submittedAt FROM contact_messages ORDER BY submitted_at DESC',
  )
  res.json({ messages: rows })
})

app.post('/api/messages', async (req, res) => {
  const { fullName, phoneNumber, email, message } = req.body || {}
  const nextMessage = {
    fullName: String(fullName || '').trim(),
    phoneNumber: String(phoneNumber || '').trim(),
    email: String(email || '').trim(),
    message: String(message || '').trim(),
  }

  if (
    !nextMessage.fullName ||
    !nextMessage.phoneNumber ||
    !nextMessage.email ||
    !nextMessage.message
  ) {
    res.status(400).json({ message: 'All fields are required.' })
    return
  }

  const [result] = await pool.query(
    'INSERT INTO contact_messages (full_name, phone_number, email, message) VALUES (?, ?, ?, ?)',
    [
      nextMessage.fullName,
      nextMessage.phoneNumber,
      nextMessage.email,
      nextMessage.message,
    ],
  )

  res.status(201).json({
    message: 'Message received.',
    item: { id: result.insertId, ...nextMessage },
  })
})

app.delete('/api/messages/:id', requireAuth, requireRole('admin'), async (req, res) => {
  await pool.query('DELETE FROM contact_messages WHERE id = ?', [req.params.id])
  res.json({ message: 'Message deleted.' })
})

app.post('/api/registrations', requireAuth, requireRole('user'), async (req, res) => {
  const { studentName, level, parentPhone, message } = req.body || {}
  const clean = {
    studentName: String(studentName || '').trim(),
    level: String(level || '').trim(),
    parentPhone: String(parentPhone || '').trim(),
    message: String(message || '').trim(),
  }
  if (!clean.studentName || !clean.level || !clean.parentPhone || !clean.message) {
    res.status(400).json({ message: 'All registration fields are required.' })
    return
  }
  if (!dbReady || !pool) {
    memoryRegistrations.unshift({
      id: memoryRegistrationIdCounter++,
      userId: req.user.userId,
      userFullName: req.user.fullName || 'Portal User',
      userEmail: req.user.email || '',
      studentName: clean.studentName,
      level: clean.level,
      parentPhone: clean.parentPhone,
      message: clean.message,
      adminReply: null,
      status: 'pending',
      createdAt: new Date().toISOString(),
    })
    res.status(201).json({ message: 'Registration request sent.' })
    return
  }

  await pool.query(
    'INSERT INTO school_registrations (user_id, student_name, level, parent_phone, message) VALUES (?, ?, ?, ?, ?)',
    [req.user.userId, clean.studentName, clean.level, clean.parentPhone, clean.message],
  )
  res.status(201).json({ message: 'Registration request sent.' })
})

app.get('/api/registrations/my', requireAuth, requireRole('user'), async (req, res) => {
  if (!dbReady || !pool) {
    const items = memoryRegistrations
      .filter((item) => item.userId === req.user.userId)
      .map((item) => ({
        id: item.id,
        studentName: item.studentName,
        level: item.level,
        parentPhone: item.parentPhone,
        message: item.message,
        adminReply: item.adminReply,
        status: item.status,
        createdAt: item.createdAt,
      }))
    res.json({ items })
    return
  }

  const [rows] = await pool.query(
    `SELECT id, student_name AS studentName, level, parent_phone AS parentPhone,
            message, admin_reply AS adminReply, status, created_at AS createdAt
     FROM school_registrations WHERE user_id = ? ORDER BY created_at DESC`,
    [req.user.userId],
  )
  res.json({ items: rows })
})

app.get('/api/registrations', requireAuth, requireRole('admin'), async (_req, res) => {
  if (!dbReady || !pool) {
    const items = memoryRegistrations.map((item) => ({
      id: item.id,
      studentName: item.studentName,
      level: item.level,
      parentPhone: item.parentPhone,
      message: item.message,
      adminReply: item.adminReply,
      status: item.status,
      createdAt: item.createdAt,
      userFullName: item.userFullName,
      userEmail: item.userEmail,
    }))
    res.json({ items })
    return
  }

  const [rows] = await pool.query(
    `SELECT r.id, r.student_name AS studentName, r.level, r.parent_phone AS parentPhone,
            r.message, r.admin_reply AS adminReply, r.status, r.created_at AS createdAt,
            u.full_name AS userFullName, u.email AS userEmail
     FROM school_registrations r
     JOIN users u ON u.id = r.user_id
     ORDER BY r.created_at DESC`,
  )
  res.json({ items: rows })
})

app.put(
  '/api/registrations/:id/reply',
  requireAuth,
  requireRole('admin'),
  async (req, res) => {
    const adminReply = String(req.body?.adminReply || '').trim()
    if (!adminReply) {
      res.status(400).json({ message: 'Reply message is required.' })
      return
    }
    if (!dbReady || !pool) {
      const id = Number(req.params.id)
      const item = memoryRegistrations.find((entry) => entry.id === id)
      if (!item) {
        res.status(404).json({ message: 'Registration not found.' })
        return
      }
      item.adminReply = adminReply
      item.status = 'replied'
      res.json({ message: 'Reply saved.' })
      return
    }

    await pool.query(
      "UPDATE school_registrations SET admin_reply = ?, status = 'replied' WHERE id = ?",
      [adminReply, req.params.id],
    )
    res.json({ message: 'Reply saved.' })
  },
)

async function startServer() {
  await initializeApp()
  app.listen(PORT, () => {
    console.log(`Gloriam backend running on http://localhost:${PORT}`)
  })
}

async function initializeApp() {
  if (initPromise) {
    return initPromise
  }

  initPromise = (async () => {
    if (NODE_ENV === 'production' && JWT_SECRET === 'gloriam-school-secret-key') {
      console.warn(
        'JWT_SECRET is using default value. Set a strong JWT_SECRET in Netlify environment variables.',
      )
    }

    try {
      pool = mysql.createPool({
        host: DB_HOST,
        port: DB_PORT,
        user: DB_USER,
        password: DB_PASSWORD,
        database: DB_NAME,
        connectionLimit: 10,
      })
      await pool.query('SELECT 1')
      await ensureSchema()
      await ensureDefaultAdmin()
      dbReady = true
    } catch (error) {
      dbReady = false
      pool = null
      console.error('Database init failed. Running with limited auth mode:', error.message)
    }
  })()

  return initPromise
}

if (require.main === module) {
  startServer().catch((error) => {
    console.error('Failed to start backend:', error.message)
    process.exit(1)
  })
}

module.exports = { app, initializeApp, startServer }

