// ====== تحميل المكتبات الأساسية ======
import express from 'express';
import bodyParser from 'body-parser';
import session from 'express-session';
import cors from 'cors';
import morgan from 'morgan';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import pg from 'pg';
import { v4 as uuidv4 } from 'uuid';
import dotenv from 'dotenv';
import nodemailer from 'nodemailer';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcrypt';
import compression from 'compression';
import NodeCache from 'node-cache';
import { body, validationResult } from 'express-validator';
import csurf from 'csurf';

// ====== إعداد __dirname لـ ES Modules ======
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ====== تحميل المتغيرات من .env ======
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// ====== إعداد الكاش ======
const cache = new NodeCache({ stdTTL: 600 }); // 10 دقائق

// ====== إعداد اللوجر البسيط ======
const logger = {
  info: (...msg) => console.log(`[INFO ${new Date().toISOString()}]`, ...msg),
  error: (...msg) => console.error(`[ERROR ${new Date().toISOString()}]`, ...msg),
  warn: (...msg) => console.warn(`[WARN ${new Date().toISOString()}]`, ...msg),
};

// ====== إعداد الاتصال بقاعدة البيانات PostgreSQL ======
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://postgres:password@localhost:5432/educationdb',
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// ====== دالة تنفيذ الاستعلام ======
async function execQuery(query, params = []) {
  const client = await pool.connect();
  try {
    const result = await client.query(query, params);
    return result.rows;
  } catch (err) {
    logger.error('DB Error:', err);
    throw err;
  } finally {
    client.release();
  }
}

// ====== Middleware للتشغيل ======
app.use(compression());
app.use(cors());
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));
app.use(morgan('combined'));
app.use(express.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ====== حماية من السبام ======
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: 'عدد الطلبات كبير جدًا، حاول لاحقًا',
});
app.use(limiter);

// ====== إعداد الجلسات ======
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'supersecretkey',
    resave: false,
    saveUninitialized: false,
    cookie: { 
      secure: process.env.NODE_ENV === 'production',
      maxAge: 24 * 60 * 60 * 1000,
      httpOnly: true,
      sameSite: 'lax'
    },
  })
);

// ====== حماية CSRF ======
const csrfProtection = csurf({
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true
  }
});
app.use(csrfProtection);

// ====== Middleware مخصص ======

// Middleware لتسجيل الطلبات
async function logRequest(req, res, next) {
  const start = Date.now();
  res.on('finish', async () => {
    const duration = Date.now() - start;
    try {
      await execQuery(
        'INSERT INTO request_logs (method, url, ip, user_agent, status_code, response_time, user_id) VALUES ($1, $2, $3, $4, $5, $6, $7)',
        [
          req.method,
          req.url,
          req.ip,
          req.get('User-Agent'),
          res.statusCode,
          duration,
          req.session.user?.id || null
        ]
      );
    } catch (error) {
      logger.error('Request logging error:', error);
    }
  });
  next();
}

app.use(logRequest);

// Middleware للتحقق من الصلاحيات
function checkRole(roles) {
  return (req, res, next) => {
    if (!req.session.user) {
      return res.status(401).json({ message: 'يجب تسجيل الدخول أولاً' });
    }
    
    if (!roles.includes(req.session.user.role)) {
      return res.status(403).json({ message: 'غير مصرح لك بالوصول' });
    }
    
    next();
  };
}

// Middleware للتحقق من الحظر
async function checkBanned(req, res, next) {
  if (!req.session.user) return next();
  
  try {
    const user = await execQuery('SELECT banned FROM users WHERE id = $1', [req.session.user.id]);
    if (user.length > 0 && user[0].banned) {
      logoutUser(req);
      return res.status(403).json({ message: 'تم حظر حسابك' });
    }
    next();
  } catch (error) {
    next(error);
  }
}

app.use(checkBanned);

// Middleware للتحقق من الصحة
function validateInput(validationRules) {
  return async (req, res, next) => {
    await Promise.all(validationRules.map(validation => validation.run(req)));
    
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'بيانات غير صالحة',
        errors: errors.array()
      });
    }
    
    next();
  };
}

// ====== معالج الأخطاء العالمي ======
function errorHandler(err, req, res, next) {
  logger.error('Unhandled error:', err);
  
  // تسجيل الخطأ في قاعدة البيانات
  execQuery(
    'INSERT INTO error_logs (message, stack, url, method, user_id) VALUES ($1, $2, $3, $4, $5)',
    [err.message, err.stack, req.url, req.method, req.session.user?.id || null]
  ).catch(e => logger.error('Error logging failed:', e));

  // إذا كان خطأ CSRF
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ 
      success: false, 
      message: 'رمز الحماية غير صالح' 
    });
  }

  res.status(500).json({ 
    success: false, 
    message: 'حدث خطأ داخلي في السيرفر',
    ...(process.env.NODE_ENV === 'development' && { error: err.message })
  });
}

app.use(errorHandler);

// ====== دوال الأمان ======
function generateToken(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

function maskEmail(email) {
  const [name, domain] = email.split('@');
  return name.slice(0, 2) + '***@' + domain;
}

function isStrongPassword(password) {
  const strongRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  return strongRegex.test(password);
}

function encryptData(data) {
  const algorithm = 'aes-256-gcm';
  const key = crypto.scryptSync(process.env.ENCRYPTION_KEY || 'default-key', 'salt', 32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipher(algorithm, key);
  
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  return {
    iv: iv.toString('hex'),
    data: encrypted,
    authTag: cipher.getAuthTag().toString('hex')
  };
}

function decryptData(encryptedData) {
  const algorithm = 'aes-256-gcm';
  const key = crypto.scryptSync(process.env.ENCRYPTION_KEY || 'default-key', 'salt', 32);
  const decipher = crypto.createDecipher(algorithm, key);
  
  decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
  
  let decrypted = decipher.update(encryptedData.data, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
}

// ====== دوال مساعدة عامة ======
function paginate(page = 1, limit = 10) {
  const offset = (page - 1) * limit;
  return { limit, offset };
}

function generateSlug(text) {
  return text
    .toString()
    .toLowerCase()
    .replace(/\s+/g, '-')     
    .replace(/[^\w\-]+/g, '') 
    .replace(/\-\-+/g, '-')   
    .replace(/^-+/, '')       
    .replace(/-+$/, '');
}

function timeAgo(date) {
  const seconds = Math.floor((new Date() - new Date(date)) / 1000);
  const intervals = {
    سنة: 31536000, شهر: 2592000, يوم: 86400, ساعة: 3600, دقيقة: 60
  };
  for (let [unit, value] of Object.entries(intervals)) {
    const count = Math.floor(seconds / value);
    if (count >= 1) return `منذ ${count} ${unit}${count > 1 ? 'ات' : ''}`;
  }
  return 'الآن';
}

function formatFileSize(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function generateRandomColor() {
  return '#' + Math.floor(Math.random() * 16777215).toString(16);
}

// ====== دوال إرسال البريد الإلكتروني ======
async function sendEmailSafe({ to, subject, html, text }) {
  try {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });
    
    await transporter.sendMail({ 
      from: process.env.EMAIL_USER, 
      to, 
      subject, 
      html,
      text: text || html.replace(/<[^>]*>/g, '')
    });
    
    logger.info(`📧 Email sent to ${maskEmail(to)}`);
    return true;
  } catch (error) {
    logger.error('Email send error:', error.message);
    return false;
  }
}

async function sendBulkEmail(users, subject, html) {
  const results = [];
  for (const user of users) {
    const result = await sendEmailSafe({
      to: user.email,
      subject,
      html: html.replace(/{{name}}/g, user.username)
    });
    results.push({ email: user.email, success: result });
  }
  return results;
}

// ====== دوال المستخدمين ======
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ message: 'يجب تسجيل الدخول أولاً' });
  }
  next();
}

async function hashValue(value) {
  const saltRounds = 12;
  return await bcrypt.hash(value, saltRounds);
}

async function verifyHash(value, hash) {
  return await bcrypt.compare(value, hash);
}

function success(res, data = {}, message = 'تم بنجاح') {
  return res.json({ success: true, message, ...data });
}

function fail(res, message = 'حدث خطأ ما', status = 500) {
  return res.status(status).json({ success: false, message });
}

function currentUser(req) {
  return req.session.user || null;
}

function loginUser(req, user) {
  req.session.user = { 
    id: user.id, 
    email: user.email, 
    role: user.role, 
    username: user.username 
  };
  req.session.save();
}

function logoutUser(req) {
  req.session.destroy((err) => {
    if (err) {
      logger.error('Logout error:', err);
    }
  });
}

function validateEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

function sanitizeInput(input) {
  if (typeof input !== 'string') return input;
  return input.replace(/[<>&'"]/g, (char) => ({
    '<': '&lt;',
    '>': '&gt;',
    '&': '&amp;',
    "'": '&#39;',
    '"': '&quot;'
  }[char]));
}

function getRandomAvatar() {
  const avatars = [
    '/img/avatar1.png',
    '/img/avatar2.png',
    '/img/avatar3.png'
  ];
  return avatars[Math.floor(Math.random() * avatars.length)];
}

function getLevelLabel(level) {
  const levels = { beginner: 'مبتدئ', intermediate: 'متوسط', advanced: 'متقدم' };
  return levels[level] || 'غير محدد';
}

// ====== دوال تسجيل النشاط ======
async function logActivity(userId, action, details = {}) {
  try {
    await execQuery(
      'INSERT INTO activity_logs (user_id, action, details) VALUES ($1, $2, $3)',
      [userId, action, JSON.stringify(details)]
    );
  } catch (error) {
    logger.error('Activity log error:', error);
  }
}

// ====== دوال الكاش ======
function getFromCache(key) {
  return cache.get(key);
}

function setCache(key, data, ttl = 600) {
  return cache.set(key, data, ttl);
}

function deleteFromCache(key) {
  return cache.del(key);
}

function clearCacheByPattern(pattern) {
  const keys = cache.keys();
  const matchingKeys = keys.filter(key => key.includes(pattern));
  cache.del(matchingKeys);
  return matchingKeys.length;
}

// ====== دوال الكورسات ======
async function calculateCourseDuration(courseId) {
  const result = await execQuery(`
    SELECT COALESCE(SUM(duration),0) AS total_duration 
    FROM lessons 
    WHERE course_id = $1
  `, [courseId]);
  return result[0]?.total_duration || 0;
}

async function getCourseRating(courseId) {
  const cacheKey = `course_rating_${courseId}`;
  const cached = getFromCache(cacheKey);
  if (cached) return cached;

  const result = await execQuery(`
    SELECT 
      COALESCE(AVG(rating), 0) AS avg_rating, 
      COUNT(*) AS total_reviews,
      COUNT(CASE WHEN rating = 5 THEN 1 END) as five_star,
      COUNT(CASE WHEN rating = 4 THEN 1 END) as four_star,
      COUNT(CASE WHEN rating = 3 THEN 1 END) as three_star,
      COUNT(CASE WHEN rating = 2 THEN 1 END) as two_star,
      COUNT(CASE WHEN rating = 1 THEN 1 END) as one_star
    FROM course_reviews WHERE course_id = $1
  `, [courseId]);
  
  const ratingData = result[0];
  setCache(cacheKey, ratingData, 300); // 5 دقائق
  
  return ratingData;
}

async function updateCourseStats(courseId) {
  const lessonsCount = await execQuery(
    'SELECT COUNT(*) FROM lessons WHERE course_id = $1', [courseId]
  );
  const studentsCount = await execQuery(
    'SELECT COUNT(*) FROM enrollments WHERE course_id = $1', [courseId]
  );

  await execQuery(`
    UPDATE courses 
    SET lessons_count = $1, students_count = $2, updated_at = NOW()
    WHERE id = $3
  `, [lessonsCount[0].count, studentsCount[0].count, courseId]);
  
  // مسح الكاش
  clearCacheByPattern(`course_${courseId}`);
}

async function getMostPopularCourses(limit = 5) {
  const cacheKey = `popular_courses_${limit}`;
  const cached = getFromCache(cacheKey);
  if (cached) return cached;

  const courses = await execQuery(`
    SELECT c.id, c.title, c.image, c.level, c.price, c.is_free,
           COUNT(e.id) AS enrollments,
           u.username as instructor_name
    FROM courses c
    LEFT JOIN enrollments e ON c.id = e.course_id
    LEFT JOIN users u ON c.instructor_id = u.id
    WHERE c.published = true
    GROUP BY c.id, u.username
    ORDER BY enrollments DESC
    LIMIT $1
  `, [limit]);

  setCache(cacheKey, courses, 600); // 10 دقائق
  return courses;
}

// ====== دوال التقارير ======
async function getUserActivityReport(userId) {
  return await execQuery(`
    SELECT action, COUNT(*) as count, 
           MAX(created_at) as last_activity
    FROM activity_logs 
    WHERE user_id = $1 
    GROUP BY action
    ORDER BY count DESC
  `, [userId]);
}

async function getRevenueTrend(days = 30) {
  return await execQuery(`
    SELECT DATE(created_at) as date, 
           SUM(amount) as total,
           COUNT(*) as transactions
    FROM payment_sessions
    WHERE status = 'completed'
      AND created_at >= NOW() - INTERVAL '${days} days'
    GROUP BY DATE(created_at)
    ORDER BY date ASC
  `);
}

async function getSystemStats() {
  const cacheKey = 'system_stats';
  const cached = getFromCache(cacheKey);
  if (cached) return cached;

  const users = await execQuery('SELECT COUNT(*) as count FROM users');
  const courses = await execQuery('SELECT COUNT(*) as count FROM courses WHERE published = true');
  const enrollments = await execQuery('SELECT COUNT(*) as count FROM enrollments');
  const revenue = await execQuery(`
    SELECT COALESCE(SUM(amount), 0) as total FROM payment_sessions WHERE status = 'completed'
  `);
  const activeUsers = await execQuery(`
    SELECT COUNT(DISTINCT user_id) as count 
    FROM activity_logs 
    WHERE created_at >= NOW() - INTERVAL '7 days'
  `);

  const stats = {
    totalUsers: parseInt(users[0].count),
    totalCourses: parseInt(courses[0].count),
    totalEnrollments: parseInt(enrollments[0].count),
    totalRevenue: parseFloat(revenue[0].total),
    activeUsers: parseInt(activeUsers[0].count)
  };

  setCache(cacheKey, stats, 300); // 5 دقائق
  return stats;
}

// ====== دوال الإشعارات ======
async function createNotification(userId, title, message, type = 'info') {
  const notificationId = uuidv4();
  await execQuery(
    `INSERT INTO notifications (id, user_id, title, message, type, is_read, created_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [notificationId, userId, sanitizeInput(title), sanitizeInput(message), type, false, new Date()]
  );
  
  // مسح كاش الإشعارات
  deleteFromCache(`notifications_${userId}`);
  
  return notificationId;
}

async function markNotificationAsRead(notificationId) {
  await execQuery(
    'UPDATE notifications SET is_read = true, read_at = NOW() WHERE id = $1',
    [notificationId]
  );
}

async function getUnreadNotifications(userId) {
  const cacheKey = `notifications_${userId}`;
  const cached = getFromCache(cacheKey);
  if (cached) return cached;

  const notifications = await execQuery(
    `SELECT * FROM notifications 
     WHERE user_id = $1 AND is_read = false 
     ORDER BY created_at DESC
     LIMIT 50`,
    [userId]
  );

  setCache(cacheKey, notifications, 60); // 1 دقيقة
  return notifications;
}

async function markAllNotificationsAsRead(userId) {
  await execQuery(
    'UPDATE notifications SET is_read = true, read_at = NOW() WHERE user_id = $1 AND is_read = false',
    [userId]
  );
  deleteFromCache(`notifications_${userId}`);
}

// ====== دوال الإدارة ======
async function getAllUsers(limit = 50, page = 1) {
  const { offset } = paginate(page, limit);
  return await execQuery(`
    SELECT id, username, email, role, banned, created_at, 
           (SELECT COUNT(*) FROM enrollments WHERE user_id = users.id) as courses_count,
           (SELECT MAX(created_at) FROM activity_logs WHERE user_id = users.id) as last_activity
    FROM users 
    ORDER BY created_at DESC 
    LIMIT $1 OFFSET $2
  `, [limit, offset]);
}

async function banUser(userId) {
  await execQuery('UPDATE users SET banned = true, updated_at = NOW() WHERE id = $1', [userId]);
  await logActivity(userId, 'USER_BANNED');
  clearCacheByPattern('users');
}

async function unbanUser(userId) {
  await execQuery('UPDATE users SET banned = false, updated_at = NOW() WHERE id = $1', [userId]);
  await logActivity(userId, 'USER_UNBANNED');
  clearCacheByPattern('users');
}

async function getAllPayments(limit = 50, page = 1) {
  const { offset } = paginate(page, limit);
  return await execQuery(`
    SELECT ps.*, u.username, u.email, c.title as course_title
    FROM payment_sessions ps
    JOIN users u ON ps.user_id = u.id
    JOIN courses c ON ps.course_id = c.id
    ORDER BY ps.created_at DESC 
    LIMIT $1 OFFSET $2
  `, [limit, offset]);
}

async function deleteCourse(courseId) {
  await execQuery('DELETE FROM courses WHERE id = $1', [courseId]);
  clearCacheByPattern('course');
  clearCacheByPattern('popular');
}

// ====== دوال الصيانة ======
async function deleteInactiveUsers(days = 180) {
  const result = await execQuery(`
    DELETE FROM users WHERE id IN (
      SELECT u.id FROM users u
      LEFT JOIN activity_logs al ON u.id = al.user_id
      WHERE u.role = 'student'
        AND (u.created_at < NOW() - INTERVAL '${days} days')
        AND (al.created_at IS NULL OR al.created_at < NOW() - INTERVAL '${days} days')
    )
  `);
  return result.rowCount;
}

async function archiveOldLogs(days = 90) {
  // أرشيف سجلات النشاط
  await execQuery(`
    INSERT INTO archived_activity_logs 
    SELECT * FROM activity_logs 
    WHERE created_at < NOW() - INTERVAL '${days} days'
  `);
  
  const deleteResult = await execQuery(`
    DELETE FROM activity_logs WHERE created_at < NOW() - INTERVAL '${days} days'
  `);

  // أرشيف سجلات الطلبات
  await execQuery(`
    INSERT INTO archived_request_logs 
    SELECT * FROM request_logs 
    WHERE created_at < NOW() - INTERVAL '${days} days'
  `);
  
  await execQuery(`
    DELETE FROM request_logs WHERE created_at < NOW() - INTERVAL '${days} days'
  `);

  return deleteResult.rowCount;
}

async function cleanupExpiredTokens() {
  const result = await execQuery(`
    UPDATE users 
    SET reset_token = NULL, reset_expires = NULL 
    WHERE reset_expires < NOW()
  `);
  return result.rowCount;
}

// ====== دوال التصدير ======
async function exportUserData(userId) {
  const userData = await execQuery('SELECT * FROM users WHERE id = $1', [userId]);
  const enrollments = await execQuery(`
    SELECT e.*, c.title, c.description 
    FROM enrollments e
    JOIN courses c ON e.course_id = c.id
    WHERE e.user_id = $1
  `, [userId]);
  
  const reviews = await execQuery('SELECT * FROM course_reviews WHERE user_id = $1', [userId]);
  const activities = await execQuery(`
    SELECT action, details, created_at 
    FROM activity_logs 
    WHERE user_id = $1 
    ORDER BY created_at DESC 
    LIMIT 1000
  `, [userId]);

  return {
    user: userData[0],
    enrollments,
    reviews,
    activities,
    exported_at: new Date().toISOString(),
    data_version: '1.0'
  };
}

async function exportCourseData(courseId) {
  const course = await execQuery('SELECT * FROM courses WHERE id = $1', [courseId]);
  const lessons = await execQuery('SELECT * FROM lessons WHERE course_id = $1 ORDER BY order_index', [courseId]);
  const enrollments = await execQuery(`
    SELECT e.*, u.username, u.email
    FROM enrollments e
    JOIN users u ON e.user_id = u.id
    WHERE e.course_id = $1
  `, [courseId]);
  const reviews = await execQuery(`
    SELECT cr.*, u.username
    FROM course_reviews cr
    JOIN users u ON cr.user_id = u.id
    WHERE cr.course_id = $1
  `, [courseId]);

  return {
    course: course[0],
    lessons,
    enrollments,
    reviews,
    stats: await getCourseRating(courseId),
    exported_at: new Date().toISOString()
  };
}

// ====== دالة ثابتة لتوليد رابط التطبيق ======
const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;

// ========= نظام الكورسات والدروس =========

// الحصول على الكورسات مع الكاش
app.get('/api/courses', async (req, res) => {
  try {
    const { category, level, search, featured, page = 1, limit = 12 } = req.query;
    const cacheKey = `courses_${category}_${level}_${search}_${featured}_${page}_${limit}`;
    
    const cached = getFromCache(cacheKey);
    if (cached) {
      return success(res, { courses: cached, fromCache: true });
    }
    
    const { offset } = paginate(parseInt(page), parseInt(limit));
    
    let query = `
      SELECT c.*, u.username as instructor_name,
             (SELECT COUNT(*) FROM lessons l WHERE l.course_id = c.id) as lessons_count,
             (SELECT COUNT(*) FROM enrollments e WHERE e.course_id = c.id) as students_count
      FROM courses c
      LEFT JOIN users u ON c.instructor_id = u.id
      WHERE c.published = true
    `;
    
    const params = [];
    let paramCount = 0;

    if (category) {
      paramCount++;
      query += ` AND c.category = $${paramCount}`;
      params.push(category);
    }

    if (level) {
      paramCount++;
      query += ` AND c.level = $${paramCount}`;
      params.push(level);
    }

    if (search) {
      paramCount++;
      query += ` AND (c.title ILIKE $${paramCount} OR c.description ILIKE $${paramCount})`;
      params.push(`%${sanitizeInput(search)}%`);
    }

    if (featured === 'true') {
      query += ` AND c.featured = true`;
    }

    query += ` ORDER BY c.created_at DESC LIMIT $${paramCount + 1} OFFSET $${paramCount + 2}`;
    params.push(parseInt(limit), offset);

    const courses = await execQuery(query, params);
    
    // إضافة معلومات التقدم إذا كان المستخدم مسجل الدخول
    if (req.session.user) {
      for (let course of courses) {
        const enrollment = await execQuery(
          'SELECT progress FROM enrollments WHERE user_id = $1 AND course_id = $2',
          [req.session.user.id, course.id]
        );
        
        course.is_enrolled = enrollment.length > 0;
        course.progress = enrollment.length > 0 ? enrollment[0].progress : 0;
        course.level_label = getLevelLabel(course.level);
        course.rating = await getCourseRating(course.id);
      }
    }

    setCache(cacheKey, courses, 300); // 5 دقائق
    success(res, { courses, fromCache: false });

  } catch (error) {
    logger.error('Get courses error', error);
    fail(res, 'حدث خطأ في جلب الكورسات');
  }
});

// الحصول على تفاصيل كورس مع الكاش
app.get('/api/courses/:id', async (req, res) => {
  try {
    const courseId = req.params.id;
    const cacheKey = `course_${courseId}`;
    
    const cached = getFromCache(cacheKey);
    if (cached) {
      return success(res, { ...cached, fromCache: true });
    }
    
    const courses = await execQuery(`
      SELECT c.*, u.username as instructor_name, u.bio as instructor_bio,
             (SELECT COUNT(*) FROM lessons l WHERE l.course_id = c.id) as lessons_count,
             (SELECT COUNT(*) FROM enrollments e WHERE e.course_id = c.id) as students_count
      FROM courses c
      LEFT JOIN users u ON c.instructor_id = u.id
      WHERE c.id = $1
    `, [courseId]);

    if (courses.length === 0) {
      return fail(res, 'الكورس غير موجود', 404);
    }

    const course = courses[0];

    // الحصول على الدروس
    const lessons = await execQuery(`
      SELECT l.*, 
             (SELECT COUNT(*) FROM lesson_parts lp WHERE lp.lesson_id = l.id) as parts_count
      FROM lessons l
      WHERE l.course_id = $1
      ORDER BY l.order_index
    `, [courseId]);

    // إضافة معلومات التقدم إذا كان المستخدم مسجل الدخول
    if (req.session.user) {
      const enrollment = await execQuery(
        'SELECT progress, progress_data FROM enrollments WHERE user_id = $1 AND course_id = $2',
        [req.session.user.id, courseId]
      );
      
      course.is_enrolled = enrollment.length > 0;
      course.progress = enrollment.length > 0 ? enrollment[0].progress : 0;
      course.progress_data = enrollment.length > 0 ? enrollment[0].progress_data : {};
      
      // تسجيل النشاط
      await logActivity(req.session.user.id, 'VIEW_COURSE', { courseId });
    }

    // حساب مدة الكورس
    course.total_duration = await calculateCourseDuration(courseId);
    course.level_label = getLevelLabel(course.level);
    course.rating = await getCourseRating(courseId);

    const responseData = {
      ...course,
      lessons: lessons
    };

    setCache(cacheKey, responseData, 600); // 10 دقائق
    success(res, { ...responseData, fromCache: false });

  } catch (error) {
    logger.error('Get course details error', error);
    fail(res, 'حدث خطأ في جلب تفاصيل الكورس');
  }
});

// التسجيل في كورس مع التحقق من الصحة
app.post('/api/enroll', 
  requireLogin,
  validateInput([
    body('courseId').isUUID().withMessage('معرف الكورس غير صالح')
  ]),
  async (req, res) => {
    try {
      const { courseId } = req.body;
      
      // التحقق من وجود الكورس
      const courses = await execQuery('SELECT * FROM courses WHERE id = $1 AND published = true', [courseId]);
      if (courses.length === 0) {
        return fail(res, 'الكورس غير موجود', 404);
      }

      const course = courses[0];

      // التحقق من عدم التسجيل مسبقاً
      const existingEnrollment = await execQuery(
        'SELECT id FROM enrollments WHERE user_id = $1 AND course_id = $2',
        [req.session.user.id, courseId]
      );

      if (existingEnrollment.length > 0) {
        return fail(res, 'أنت مسجل بالفعل في هذا الكورس', 400);
      }

      // إذا كان الكورس مجاني، التسجيل مباشرة
      if (course.is_free || course.price === 0) {
        const enrollmentId = uuidv4();
        
        await execQuery(
          `INSERT INTO enrollments (id, user_id, course_id, enrolled_at, progress, progress_data)
           VALUES ($1, $2, $3, $4, $5, $6)`,
          [enrollmentId, req.session.user.id, courseId, new Date(), 0, JSON.stringify({})]
        );

        // تحديث إحصائيات الكورس
        await updateCourseStats(courseId);

        // إرسال بريد التأكيد
        await sendEmailSafe({
          to: req.session.user.email,
          subject: 'تم تسجيلك في الكورس - Elmahdy English',
          html: `
            <div style="font-family: 'Cairo', Arial, sans-serif; direction: rtl; padding: 20px;">
              <h2 style="color: #0056d6;">تم تسجيلك في الكورس بنجاح! 🎉</h2>
              <p><strong>الكورس:</strong> ${course.title}</p>
              <p>يمكنك الآن البدء في التعلم من خلال لوحة التعلم.</p>
              <a href="${APP_URL}/course/${courseId}" style="background: #0056d6; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
                ابدأ التعلم
              </a>
            </div>
          `
        });

        // إنشاء إشعار
        await createNotification(
          req.session.user.id,
          'تم التسجيل في الكورس',
          `تم تسجيلك في كورس "${course.title}" بنجاح`,
          'success'
        );

        // تسجيل النشاط
        await logActivity(req.session.user.id, 'ENROLL_COURSE', { 
          courseId, 
          courseTitle: course.title,
          free: true 
        });

        // مسح الكاش
        clearCacheByPattern('courses');
        deleteFromCache(`user_courses_${req.session.user.id}`);

        return success(res, { 
          enrollmentId: enrollmentId,
          redirectUrl: `/course/${courseId}`
        }, 'تم التسجيل في الكورس بنجاح');
      }

      // إذا كان الكورس مدفوع، إنشاء طلب دفع
      const paymentSessionId = uuidv4();
      
      await execQuery(
        `INSERT INTO payment_sessions (id, user_id, course_id, amount, status, created_at)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [paymentSessionId, req.session.user.id, courseId, course.price, 'pending', new Date()]
      );

      success(res, {
        paymentRequired: true,
        paymentSessionId: paymentSessionId,
        amount: course.price,
        courseTitle: course.title
      }, 'يجب إتمام عملية الدفع');

    } catch (error) {
      logger.error('Enrollment error', error);
      fail(res, 'حدث خطأ أثناء التسجيل في الكورس');
    }
  }
);

// تحديث تقدم الطالب مع التحقق من الصحة
app.post('/api/progress', 
  requireLogin,
  validateInput([
    body('courseId').isUUID().withMessage('معرف الكورس غير صالح'),
    body('lessonId').isUUID().withMessage('معرف الدرس غير صالح'),
    body('partId').isUUID().withMessage('معرف الجزء غير صالح'),
    body('completed').isBoolean().withMessage('يجب أن تكون القيمة boolean')
  ]),
  async (req, res) => {
    try {
      const { courseId, lessonId, partId, completed } = req.body;

      // الحصول على التسجيل الحالي
      const enrollment = await execQuery(
        'SELECT * FROM enrollments WHERE user_id = $1 AND course_id = $2',
        [req.session.user.id, courseId]
      );

      if (enrollment.length === 0) {
        return fail(res, 'أنت غير مسجل في هذا الكورس', 404);
      }

      // تحديث التقدم
      let progressData = enrollment[0].progress_data || {};
      
      if (!progressData.lessons) {
        progressData.lessons = {};
      }

      if (!progressData.lessons[lessonId]) {
        progressData.lessons[lessonId] = {
          completed_parts: [],
          completed: false
        };
      }

      if (completed) {
        if (!progressData.lessons[lessonId].completed_parts.includes(partId)) {
          progressData.lessons[lessonId].completed_parts.push(partId);
        }
      } else {
        progressData.lessons[lessonId].completed_parts = 
          progressData.lessons[lessonId].completed_parts.filter(id => id !== partId);
      }

      // حساب التقدم الكلي
      const totalParts = await execQuery(`
        SELECT COUNT(*) as count FROM lesson_parts lp
        JOIN lessons l ON lp.lesson_id = l.id
        WHERE l.course_id = $1
      `, [courseId]);

      const completedParts = Object.values(progressData.lessons)
        .reduce((total, lesson) => total + lesson.completed_parts.length, 0);

      const totalPartsCount = totalParts[0]?.count || 1;
      const progress = Math.round((completedParts / totalPartsCount) * 100);

      // تحديث قاعدة البيانات
      await execQuery(
        'UPDATE enrollments SET progress = $1, progress_data = $2, updated_at = $3 WHERE user_id = $4 AND course_id = $5',
        [progress, JSON.stringify(progressData), new Date(), req.session.user.id, courseId]
      );

      // تسجيل النشاط
      await logActivity(req.session.user.id, 'UPDATE_PROGRESS', { 
        courseId, lessonId, partId, progress, completed 
      });

      success(res, {
        progress: progress,
        completedParts: completedParts,
        totalParts: totalPartsCount
      }, 'تم تحديث التقدم');

    } catch (error) {
      logger.error('Update progress error', error);
      fail(res, 'حدث خطأ أثناء تحديث التقدم');
    }
  }
);

// ========= دوال جديدة مطلوبة =========

// الحصول على الكورسات الشعبية
app.get('/api/courses/popular', async (req, res) => {
  try {
    const { limit = 5 } = req.query;
    const popularCourses = await getMostPopularCourses(parseInt(limit));
    success(res, { courses: popularCourses });
  } catch (error) {
    logger.error('Get popular courses error', error);
    fail(res, 'حدث خطأ في جلب الكورسات الشعبية');
  }
});

// الحصول على تقرير نشاط المستخدم
app.get('/api/user/activity-report', requireLogin, async (req, res) => {
  try {
    const report = await getUserActivityReport(req.session.user.id);
    success(res, { report });
  } catch (error) {
    logger.error('Get user activity report error', error);
    fail(res, 'حدث خطأ في جلب تقرير النشاط');
  }
});

// الحصول على الإشعارات غير المقروءة
app.get('/api/user/notifications', requireLogin, async (req, res) => {
  try {
    const notifications = await getUnreadNotifications(req.session.user.id);
    success(res, { notifications });
  } catch (error) {
    logger.error('Get notifications error', error);
    fail(res, 'حدث خطأ في جلب الإشعارات');
  }
});

// تسجيل الإشعار كمقروء
app.post('/api/user/notifications/:id/read', requireLogin, async (req, res) => {
  try {
    const { id } = req.params;
    await markNotificationAsRead(id);
    success(res, {}, 'تم تسجيل الإشعار كمقروء');
  } catch (error) {
    logger.error('Mark notification as read error', error);
    fail(res, 'حدث خطأ في تسجيل الإشعار');
  }
});

// ========= دوال الإدارة =========

// حظر مستخدم
app.post('/api/admin/users/:id/ban', requireLogin, checkRole(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    await banUser(id);
    success(res, {}, 'تم حظر المستخدم بنجاح');
  } catch (error) {
    logger.error('Ban user error', error);
    fail(res, 'حدث خطأ في حظر المستخدم');
  }
});

// إلغاء حظر مستخدم
app.post('/api/admin/users/:id/unban', requireLogin, checkRole(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    await unbanUser(id);
    success(res, {}, 'تم إلغاء حظر المستخدم بنجاح');
  } catch (error) {
    logger.error('Unban user error', error);
    fail(res, 'حدث خطأ في إلغاء حظر المستخدم');
  }
});

// الحصول على جميع المدفوعات
app.get('/api/admin/payments', requireLogin, checkRole(['admin']), async (req, res) => {
  try {
    const { page = 1, limit = 50 } = req.query;
    const payments = await getAllPayments(parseInt(limit), parseInt(page));
    success(res, { payments });
  } catch (error) {
    logger.error('Get all payments error', error);
    fail(res, 'حدث خطأ في جلب المدفوعات');
  }
});

// حذف كورس
app.delete('/api/admin/courses/:id', requireLogin, checkRole(['admin']), async (req, res) => {
  try {
    const { id } = req.params;
    await deleteCourse(id);
    success(res, {}, 'تم حذف الكورس بنجاح');
  } catch (error) {
    logger.error('Delete course error', error);
    fail(res, 'حدث خطأ في حذف الكورس');
  }
});

// ========= دوال الصيانة =========

// تنظيف المستخدمين غير النشطين
app.post('/api/admin/maintenance/cleanup-users', requireLogin, checkRole(['admin']), async (req, res) => {
  try {
    const { days = 180 } = req.body;
    const deletedCount = await deleteInactiveUsers(parseInt(days));
    success(res, { deletedCount }, `تم حذف ${deletedCount} مستخدم غير نشط`);
  } catch (error) {
    logger.error('Cleanup users error', error);
    fail(res, 'حدث خطأ في تنظيف المستخدمين');
  }
});

// أرشيف السجلات القديمة
app.post('/api/admin/maintenance/archive-logs', requireLogin, checkRole(['admin']), async (req, res) => {
  try {
    const { days = 90 } = req.body;
    const archivedCount = await archiveOldLogs(parseInt(days));
    success(res, { archivedCount }, `تم أرشيف ${archivedCount} سجل`);
  } catch (error) {
    logger.error('Archive logs error', error);
    fail(res, 'حدث خطأ في أرشيف السجلات');
  }
});

// ========= دوال التصدير =========

// تصدير بيانات المستخدم
app.get('/api/user/export-data', requireLogin, async (req, res) => {
  try {
    const userData = await exportUserData(req.session.user.id);
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename=user-data-${req.session.user.id}.json`);
    res.json(userData);
  } catch (error) {
    logger.error('Export user data error', error);
    fail(res, 'حدث خطأ في تصدير البيانات');
  }
});

// ========= إنشاء الجداول في قاعدة البيانات =========

async function createEducationTables() {
  try {
    // جدول المستخدمين
    await execQuery(`
      CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(36) PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'student',
        bio TEXT,
        avatar_url VARCHAR(500),
        reset_token VARCHAR(255),
        reset_expires TIMESTAMP,
        banned BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // جدول الكورسات
    await execQuery(`
      CREATE TABLE IF NOT EXISTS courses (
        id VARCHAR(36) PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        category VARCHAR(100),
        level VARCHAR(50) DEFAULT 'beginner',
        price DECIMAL(10,2) DEFAULT 0,
        is_free BOOLEAN DEFAULT FALSE,
        image VARCHAR(500),
        requirements JSONB,
        objectives JSONB,
        instructor_id VARCHAR(36) REFERENCES users(id),
        published BOOLEAN DEFAULT FALSE,
        featured BOOLEAN DEFAULT FALSE,
        lessons_count INTEGER DEFAULT 0,
        students_count INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // جدول الدروس
    await execQuery(`
      CREATE TABLE IF NOT EXISTS lessons (
        id VARCHAR(36) PRIMARY KEY,
        course_id VARCHAR(36) REFERENCES courses(id) ON DELETE CASCADE,
        title VARCHAR(255) NOT NULL,
        description TEXT,
        order_index INTEGER DEFAULT 0,
        duration INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // جدول أجزاء الدرس
    await execQuery(`
      CREATE TABLE IF NOT EXISTS lesson_parts (
        id VARCHAR(36) PRIMARY KEY,
        lesson_id VARCHAR(36) REFERENCES lessons(id) ON DELETE CASCADE,
        title VARCHAR(255) NOT NULL,
        content_type VARCHAR(50) DEFAULT 'video',
        content_url VARCHAR(500),
        duration INTEGER DEFAULT 0,
        order_index INTEGER DEFAULT 0,
        is_free_preview BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // جدول التسجيلات
    await execQuery(`
      CREATE TABLE IF NOT EXISTS enrollments (
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(36) REFERENCES users(id),
        course_id VARCHAR(36) REFERENCES courses(id),
        enrolled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        progress INTEGER DEFAULT 0,
        completed BOOLEAN DEFAULT FALSE,
        completed_at TIMESTAMP,
        progress_data JSONB DEFAULT '{}',
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, course_id)
      )
    `);

    // جدول جلسات الدفع
    await execQuery(`
      CREATE TABLE IF NOT EXISTS payment_sessions (
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(36) REFERENCES users(id),
        course_id VARCHAR(36) REFERENCES courses(id),
        amount DECIMAL(10,2),
        status VARCHAR(50) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP
      )
    `);

    // جدول سجلات النشاط
    await execQuery(`
      CREATE TABLE IF NOT EXISTS activity_logs (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(36) REFERENCES users(id),
        action VARCHAR(255) NOT NULL,
        details JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // جدول التقييمات
    await execQuery(`
      CREATE TABLE IF NOT EXISTS course_reviews (
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(36) REFERENCES users(id),
        course_id VARCHAR(36) REFERENCES courses(id),
        rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
        comment TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, course_id)
      )
    `);

    // جدول الإشعارات
    await execQuery(`
      CREATE TABLE IF NOT EXISTS notifications (
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(36) REFERENCES users(id),
        title VARCHAR(255) NOT NULL,
        message TEXT,
        type VARCHAR(50) DEFAULT 'info',
        is_read BOOLEAN DEFAULT FALSE,
        read_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // جدول سجلات الطلبات
    await execQuery(`
      CREATE TABLE IF NOT EXISTS request_logs (
        id SERIAL PRIMARY KEY,
        method VARCHAR(10) NOT NULL,
        url TEXT NOT NULL,
        ip VARCHAR(45),
        user_agent TEXT,
        status_code INTEGER,
        response_time INTEGER,
        user_id VARCHAR(36) REFERENCES users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // جدول سجلات الأخطاء
    await execQuery(`
      CREATE TABLE IF NOT EXISTS error_logs (
        id SERIAL PRIMARY KEY,
        message TEXT NOT NULL,
        stack TEXT,
        url TEXT,
        method VARCHAR(10),
        user_id VARCHAR(36) REFERENCES users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // جدول الأرشيف
    await execQuery(`
      CREATE TABLE IF NOT EXISTS archived_activity_logs (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(36),
        action VARCHAR(255) NOT NULL,
        details JSONB,
        created_at TIMESTAMP
      )
    `);

    await execQuery(`
      CREATE TABLE IF NOT EXISTS archived_request_logs (
        id SERIAL PRIMARY KEY,
        method VARCHAR(10) NOT NULL,
        url TEXT NOT NULL,
        ip VARCHAR(45),
        user_agent TEXT,
        status_code INTEGER,
        response_time INTEGER,
        user_id VARCHAR(36),
        created_at TIMESTAMP
      )
    `);

    logger.info('✅ All tables created successfully');
  } catch (error) {
    logger.error('❌ Error creating tables', error);
  }
}

// ====== إضافة بيانات تجريبية ======
async function seedSampleData() {
  try {
    // التحقق من وجود بيانات
    const existingUsers = await execQuery('SELECT COUNT(*) FROM users');
    
    if (parseInt(existingUsers[0].count) === 0) {
      // إضافة مستخدمين تجريبيين
      const teacherId = uuidv4();
      await execQuery(
        `INSERT INTO users (id, username, email, password_hash, role, bio) 
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [teacherId, 'teacher_ahmed', 'teacher@elmahdy-english.com', await hashValue('password123'), 'teacher', 'مدرس لغة إنجليزية محترف مع 10 سنوات خبرة']
      );

      const adminId = uuidv4();
      await execQuery(
        `INSERT INTO users (id, username, email, password_hash, role) 
         VALUES ($1, $2, $3, $4, $5)`,
        [adminId, 'admin', 'admin@elmahdy-english.com', await hashValue('admin123'), 'admin']
      );

      const studentId = uuidv4();
      await execQuery(
        `INSERT INTO users (id, username, email, password_hash, role) 
         VALUES ($1, $2, $3, $4, $5)`,
        [studentId, 'student_mohamed', 'student@elmahdy-english.com', await hashValue('password123'), 'student']
      );

      // إضافة كورسات تجريبية
      const course1Id = uuidv4();
      await execQuery(
        `INSERT INTO courses (id, title, description, category, level, price, is_free, instructor_id, published, featured)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [course1Id, 'الإنجليزية للمبتدئين من الصفر', 'تعلم الإنجليزية من البداية مع أفضل المدرسين', 'grammar', 'beginner', 150, false, teacherId, true, true]
      );

      const course2Id = uuidv4();
      await execQuery(
        `INSERT INTO courses (id, title, description, category, level, price, is_free, instructor_id, published)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [course2Id, 'محادثة إنجليزية متقدمة', 'تطوير مهارات المحادثة للمستويات المتقدمة', 'conversation', 'advanced', 200, false, teacherId, true]
      );

      const course3Id = uuidv4();
      await execQuery(
        `INSERT INTO courses (id, title, description, category, level, price, is_free, instructor_id, published)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [course3Id, 'قواعد اللغة الإنجليزية الأساسية', 'شرح مبسط لقواعد اللغة الإنجليزية', 'grammar', 'beginner', 0, true, teacherId, true]
      );

      logger.info('✅ Sample data seeded successfully');
    }
  } catch (error) {
    logger.error('❌ Error seeding sample data', error);
  }
}

// ====== صفحة الهبوط الأساسية ======
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ====== تشغيل السيرفر ======
app.listen(PORT, async () => {
  logger.info(`🚀 Server running on ${APP_URL}`);
  logger.info(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
  
  // إنشاء الجداول وإضافة البيانات التجريبية
  await createEducationTables();
  await seedSampleData();
  
  // تشغيل مهام الصيانة الدورية
  startMaintenanceTasks();
});

// ====== مهام الصيانة الدورية ======
function startMaintenanceTasks() {
  // تنظيف التوكينز المنتهية كل ساعة
  setInterval(async () => {
    try {
      const cleaned = await cleanupExpiredTokens();
      if (cleaned > 0) {
        logger.info(`🧹 Cleaned ${cleaned} expired tokens`);
      }
    } catch (error) {
      logger.error('Token cleanup error:', error);
    }
  }, 60 * 60 * 1000);

  // أرشيف السجلات القديمة يومياً
  setInterval(async () => {
    try {
      const archived = await archiveOldLogs(30); // 30 يوم
      if (archived > 0) {
        logger.info(`📦 Archived ${archived} old logs`);
      }
    } catch (error) {
      logger.error('Log archiving error:', error);
    }
  }, 24 * 60 * 60 * 1000);

  // حذف المستخدمين غير النشطين أسبوعياً
  setInterval(async () => {
    try {
      const deleted = await deleteInactiveUsers(180); // 6 أشهر
      if (deleted > 0) {
        logger.info(`🗑️ Deleted ${deleted} inactive users`);
      }
    } catch (error) {
      logger.error('Inactive users cleanup error:', error);
    }
  }, 7 * 24 * 60 * 60 * 1000);
}

export default app;
