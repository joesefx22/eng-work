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
  debug: (...msg) => {
    if (process.env.NODE_ENV === 'development') {
      console.log(`[DEBUG ${new Date().toISOString()}]`, ...msg);
    }
  }
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
    logger.debug('Executing query:', query.substring(0, 100), '...');
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
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));
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
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: 'عدد الطلبات كبير جدًا، حاول لاحقًا',
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'عدد محاولات تسجيل الدخول كبير جداً، حاول بعد 15 دقيقة',
  skipSuccessfulRequests: true
});

app.use(generalLimiter);
app.use('/api/login', authLimiter);
app.use('/api/register', authLimiter);
app.use('/api/forgot-password', authLimiter);

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

// Middleware لإضافة CSRF token لل responses
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken();
  next();
});

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

/**
 * @function generateToken
 * @description إنشاء توكن عشوائي
 * @param {number} length - طول التوكن
 * @returns {string} التوكن المولد
 */
function generateToken(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

/**
 * @function maskEmail
 * @description إخفاء جزء من البريد الإلكتروني
 * @param {string} email - البريد الإلكتروني
 * @returns {string} البريد المخفي
 */
function maskEmail(email) {
  const [name, domain] = email.split('@');
  return name.slice(0, 2) + '***@' + domain;
}

/**
 * @function isStrongPassword
 * @description التحقق من قوة كلمة المرور
 * @param {string} password - كلمة المرور
 * @returns {boolean} إذا كانت قوية
 */
function isStrongPassword(password) {
  const strongRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  return strongRegex.test(password);
}

/**
 * @function encryptData
 * @description تشفير البيانات
 * @param {string} data - البيانات للتشفير
 * @returns {Object} البيانات المشفرة
 */
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

/**
 * @function decryptData
 * @description فك تشفير البيانات
 * @param {Object} encryptedData - البيانات المشفرة
 * @returns {string} البيانات الأصلية
 */
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

/**
 * @function paginate
 * @description حساب الترقيم
 * @param {number} page - الصفحة الحالية
 * @param {number} limit - عدد العناصر في الصفحة
 * @returns {Object} إعدادات الترقيم
 */
function paginate(page = 1, limit = 10) {
  const offset = (page - 1) * limit;
  return { limit, offset };
}

/**
 * @function generateSlug
 * @description إنشاء رابط SEO-friendly
 * @param {string} text - النص
 * @returns {string} الرابط
 */
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

/**
 * @function timeAgo
 * @description حساب الوقت المنقضي
 * @param {Date} date - التاريخ
 * @returns {string} الوقت المنقضي
 */
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

/**
 * @function formatFileSize
 * @description تنسيق حجم الملف
 * @param {number} bytes - الحجم بالبايت
 * @returns {string} الحجم المنسق
 */
function formatFileSize(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * @function generateRandomColor
 * @description إنشاء لون عشوائي
 * @returns {string} اللون
 */
function generateRandomColor() {
  return '#' + Math.floor(Math.random() * 16777215).toString(16);
}

// ====== دوال إرسال البريد الإلكتروني ======

/**
 * @function sendEmailSafe
 * @description إرسال بريد إلكتروني آمن
 * @param {Object} options - خيارات البريد
 * @returns {Promise<boolean>} إذا تم الإرسال
 */
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

/**
 * @function sendBulkEmail
 * @description إرسال بريد جماعي
 * @param {Array} users - المستخدمين
 * @param {string} subject - الموضوع
 * @param {string} html - المحتوى
 * @returns {Promise<Array>} نتائج الإرسال
 */
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

/**
 * @function requireLogin
 * @description التحقق من تسجيل الدخول
 */
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ message: 'يجب تسجيل الدخول أولاً' });
  }
  next();
}

/**
 * @function hashValue
 * @description تشفير قيمة
 * @param {string} value - القيمة
 * @returns {Promise<string>} القيمة المشفرة
 */
async function hashValue(value) {
  const saltRounds = 12;
  return await bcrypt.hash(value, saltRounds);
}

/**
 * @function verifyHash
 * @description التحقق من التشفير
 * @param {string} value - القيمة الأصلية
 * @param {string} hash - التشفير
 * @returns {Promise<boolean>} إذا كانت متطابقة
 */
async function verifyHash(value, hash) {
  return await bcrypt.compare(value, hash);
}

/**
 * @function success
 * @description إرسال رد ناجح
 */
function success(res, data = {}, message = 'تم بنجاح') {
  return res.json({ success: true, message, ...data });
}

/**
 * @function fail
 * @description إرسال رد فاشل
 */
function fail(res, message = 'حدث خطأ ما', status = 500) {
  return res.status(status).json({ success: false, message });
}

/**
 * @function currentUser
 * @description جلب المستخدم الحالي
 */
function currentUser(req) {
  return req.session.user || null;
}

/**
 * @function loginUser
 * @description تسجيل دخول المستخدم
 */
function loginUser(req, user) {
  req.session.user = { 
    id: user.id, 
    email: user.email, 
    role: user.role, 
    username: user.username 
  };
  req.session.save();
}

/**
 * @function logoutUser
 * @description تسجيل خروج المستخدم
 */
function logoutUser(req) {
  req.session.destroy((err) => {
    if (err) {
      logger.error('Logout error:', err);
    }
  });
}

/**
 * @function validateEmail
 * @description التحقق من صحة البريد الإلكتروني
 */
function validateEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

/**
 * @function sanitizeInput
 * @description تنظيف المدخلات
 */
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

/**
 * @function getRandomAvatar
 * @description الحصول على صورة عشوائية
 */
function getRandomAvatar() {
  const avatars = [
    '/img/avatar1.png',
    '/img/avatar2.png',
    '/img/avatar3.png'
  ];
  return avatars[Math.floor(Math.random() * avatars.length)];
}

/**
 * @function getLevelLabel
 * @description الحصول على تسمية المستوى
 */
function getLevelLabel(level) {
  const levels = { beginner: 'مبتدئ', intermediate: 'متوسط', advanced: 'متقدم' };
  return levels[level] || 'غير محدد';
}

// ====== دوال تسجيل النشاط ======

/**
 * @function logActivity
 * @description تسجيل نشاط المستخدم
 */
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

/**
 * @function getFromCache
 * @description جلب بيانات من الكاش
 */
function getFromCache(key) {
  return cache.get(key);
}

/**
 * @function setCache
 * @description حفظ بيانات في الكاش
 */
function setCache(key, data, ttl = 600) {
  return cache.set(key, data, ttl);
}

/**
 * @function deleteFromCache
 * @description حذف بيانات من الكاش
 */
function deleteFromCache(key) {
  return cache.del(key);
}

/**
 * @function clearCacheByPattern
 * @description مسح الكاش بنمط معين
 */
function clearCacheByPattern(pattern) {
  const keys = cache.keys();
  const matchingKeys = keys.filter(key => key.includes(pattern));
  cache.del(matchingKeys);
  return matchingKeys.length;
}

// ====== دوال الكورسات ======

/**
 * @function calculateCourseDuration
 * @description حساب مدة الكورس
 */
async function calculateCourseDuration(courseId) {
  const result = await execQuery(`
    SELECT COALESCE(SUM(duration),0) AS total_duration 
    FROM lessons 
    WHERE course_id = $1
  `, [courseId]);
  return result[0]?.total_duration || 0;
}

/**
 * @function getCourseRating
 * @description جلب تقييمات الكورس
 */
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
  setCache(cacheKey, ratingData, 300);
  
  return ratingData;
}

/**
 * @function updateCourseStats
 * @description تحديث إحصائيات الكورس
 */
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
  
  clearCacheByPattern(`course_${courseId}`);
}

/**
 * @function getMostPopularCourses
 * @description جلب الكورسات الأكثر شعبية
 */
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

  setCache(cacheKey, courses, 600);
  return courses;
}

// ====== دوال التقارير ======

/**
 * @function getUserActivityReport
 * @description جلب تقرير نشاط المستخدم
 */
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

/**
 * @function getRevenueTrend
 * @description جلب اتجاه الإيرادات
 */
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

/**
 * @function getRevenueReportByMonth
 * @description جلب تقرير الإيرادات الشهري
 */
async function getRevenueReportByMonth(year = new Date().getFullYear()) {
  return await execQuery(`
    SELECT 
      EXTRACT(MONTH FROM created_at) as month,
      COUNT(*) as transactions,
      SUM(amount) as revenue
    FROM payment_sessions 
    WHERE status = 'completed' AND EXTRACT(YEAR FROM created_at) = $1
    GROUP BY EXTRACT(MONTH FROM created_at)
    ORDER BY month
  `, [year]);
}

/**
 * @function getSystemStats
 * @description جلب إحصائيات النظام
 */
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

  setCache(cacheKey, stats, 300);
  return stats;
}

// ====== دوال الإشعارات ======

/**
 * @function createNotification
 * @description إنشاء إشعار جديد
 */
async function createNotification(userId, title, message, type = 'info') {
  const notificationId = uuidv4();
  await execQuery(
    `INSERT INTO notifications (id, user_id, title, message, type, is_read, created_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [notificationId, userId, sanitizeInput(title), sanitizeInput(message), type, false, new Date()]
  );
  
  deleteFromCache(`notifications_${userId}`);
  
  return notificationId;
}

/**
 * @function markNotificationAsRead
 * @description تسجيل الإشعار كمقروء
 */
async function markNotificationAsRead(notificationId) {
  await execQuery(
    'UPDATE notifications SET is_read = true, read_at = NOW() WHERE id = $1',
    [notificationId]
  );
}

/**
 * @function getUnreadNotifications
 * @description جلب الإشعارات غير المقروءة
 */
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

  setCache(cacheKey, notifications, 60);
  return notifications;
}

/**
 * @function markAllNotificationsAsRead
 * @description تسجيل كل الإشعارات كمقروءة
 */
async function markAllNotificationsAsRead(userId) {
  await execQuery(
    'UPDATE notifications SET is_read = true, read_at = NOW() WHERE user_id = $1 AND is_read = false',
    [userId]
  );
  deleteFromCache(`notifications_${userId}`);
}

// ====== دوال الإدارة ======

/**
 * @function getAllUsers
 * @description جلب جميع المستخدمين
 */
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

/**
 * @function banUser
 * @description حظر مستخدم
 */
async function banUser(userId) {
  await execQuery('UPDATE users SET banned = true, updated_at = NOW() WHERE id = $1', [userId]);
  await logActivity(userId, 'USER_BANNED');
  clearCacheByPattern('users');
}

/**
 * @function unbanUser
 * @description إلغاء حظر مستخدم
 */
async function unbanUser(userId) {
  await execQuery('UPDATE users SET banned = false, updated_at = NOW() WHERE id = $1', [userId]);
  await logActivity(userId, 'USER_UNBANNED');
  clearCacheByPattern('users');
}

/**
 * @function getAllPayments
 * @description جلب جميع المدفوعات
 */
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

/**
 * @function deleteCourse
 * @description حذف كورس
 */
async function deleteCourse(courseId) {
  await execQuery('DELETE FROM courses WHERE id = $1', [courseId]);
  clearCacheByPattern('course');
  clearCacheByPattern('popular');
}

// ====== دوال الصيانة ======

/**
 * @function deleteInactiveUsers
 * @description حذف المستخدمين غير النشطين
 */
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

/**
 * @function archiveOldLogs
 * @description أرشيف السجلات القديمة
 */
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

/**
 * @function cleanupExpiredTokens
 * @description تنظيف التوكنز المنتهية
 */
async function cleanupExpiredTokens() {
  const result = await execQuery(`
    UPDATE users 
    SET reset_token = NULL, reset_expires = NULL 
    WHERE reset_expires < NOW()
  `);
  return result.rowCount;
}

/**
 * @function cleanupOldSessions
 * @description تنظيف الجلسات القديمة
 */
async function cleanupOldSessions(days = 30) {
  const result = await execQuery(
    'DELETE FROM sessions WHERE created_at < NOW() - INTERVAL \'$1 days\'',
    [days]
  );
  return result.rowCount;
}

// ====== دوال التصدير ======

/**
 * @function exportUserData
 * @description تصدير بيانات المستخدم
 */
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

/**
 * @function exportCourseData
 * @description تصدير بيانات الكورس
 */
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

// ========= Routes الأساسية =========

// Health Check
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    message: 'السيرفر يعمل بشكل طبيعي',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// CSRF Token
app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

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

    setCache(cacheKey, courses, 300);
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

    setCache(cacheKey, responseData, 600);
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

// الحصول على كورسات المستخدم
app.get('/api/user/courses', requireLogin, async (req, res) => {
  try {
    const enrollments = await execQuery(`
      SELECT e.*, c.title, c.description, c.image, c.instructor_id, u.username as instructor_name
      FROM enrollments e
      JOIN courses c ON e.course_id = c.id
      LEFT JOIN users u ON c.instructor_id = u.id
      WHERE e.user_id = $1
      ORDER BY e.updated_at DESC
    `, [req.session.user.id]);

    success(res, { courses: enrollments });
  } catch (error) {
    logger.error('Get user courses error', error);
    fail(res, 'حدث خطأ في جلب كورساتك');
  }
});

// إنشاء كورس جديد (للمعلمين)
app.post('/api/courses', 
  requireLogin,
  checkRole(['teacher', 'admin']),
  validateInput([
    body('title').isLength({ min: 5 }).withMessage('العنوان يجب أن يكون 5 أحرف على الأقل'),
    body('description').isLength({ min: 10 }).withMessage('الوصف يجب أن يكون 10 أحرف على الأقل'),
    body('category').notEmpty().withMessage('التصنيف مطلوب')
  ]),
  async (req, res) => {
    try {
      const { title, description, category, level, price, is_free, requirements, objectives } = req.body;
      
      const courseId = uuidv4();
      
      await execQuery(
        `INSERT INTO courses (id, title, description, category, level, price, is_free, 
         requirements, objectives, instructor_id, published, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
        [courseId, sanitizeInput(title), sanitizeInput(description), category, level, 
         price || 0, is_free || false,
         JSON.stringify(requirements || []), JSON.stringify(objectives || []),
         req.session.user.id, false, new Date()]
      );

      await logActivity(req.session.user.id, 'CREATE_COURSE', { courseId, title });

      success(res, { courseId: courseId }, 'تم إنشاء الكورس بنجاح');

    } catch (error) {
      logger.error('Create course error', error);
      fail(res, 'حدث خطأ أثناء إنشاء الكورس');
    }
  }
);

// ========= نظام المستخدمين =========

// تسجيل الدخول
app.post('/api/login', 
  validateInput([
    body('email').isEmail().withMessage('بريد إلكتروني غير صالح'),
    body('password').isLength({ min: 1 }).withMessage('كلمة المرور مطلوبة')
  ]),
  async (req, res) => {
    try {
      const { email, password } = req.body;

      const users = await execQuery(
        'SELECT * FROM users WHERE email = $1',
        [email.toLowerCase()]
      );

      if (users.length === 0) {
        return fail(res, 'البريد الإلكتروني أو كلمة المرور غير صحيحة', 401);
      }

      const user = users[0];
      
      // التحقق من كلمة المرور باستخدام bcrypt
      const isPasswordValid = await verifyHash(password, user.password_hash);
      if (!isPasswordValid) {
        return fail(res, 'البريد الإلكتروني أو كلمة المرور غير صحيحة', 401);
      }

      // التحقق من الحظر
      if (user.banned) {
        return fail(res, 'تم حظر حسابك', 403);
      }

      loginUser(req, user);

      await logActivity(user.id, 'LOGIN', { ip: req.ip });

      success(res, {
        user: {
          id: user.id,
          email: user.email,
          username: user.username,
          role: user.role
        }
      }, 'تم تسجيل الدخول بنجاح');

    } catch (error) {
      logger.error('Login error', error);
      fail(res, 'حدث خطأ أثناء تسجيل الدخول');
    }
  }
);

// تسجيل الخروج
app.post('/api/logout', requireLogin, (req, res) => {
  logActivity(req.session.user.id, 'LOGOUT');
  logoutUser(req);
  success(res, {}, 'تم تسجيل الخروج بنجاح');
});

// إنشاء حساب جديد
app.post('/api/register', 
  validateInput([
    body('username').isLength({ min: 3 }).withMessage('اسم المستخدم يجب أن يكون 3 أحرف على الأقل'),
    body('email').isEmail().withMessage('بريد إلكتروني غير صالح'),
    body('password').isLength({ min: 6 }).withMessage('كلمة المرور يجب أن تكون 6 أحرف على الأقل')
  ]),
  async (req, res) => {
    try {
      const { username, email, password, role = 'student' } = req.body;

      // التحقق من قوة كلمة المرور
      if (!isStrongPassword(password)) {
        return fail(res, 'كلمة المرور يجب أن تحتوي على حروف كبيرة وصغيرة وأرقام ورموز', 400);
      }

      // التحقق من عدم وجود المستخدم مسبقاً
      const existingUsers = await execQuery(
        'SELECT id FROM users WHERE email = $1 OR username = $2',
        [email.toLowerCase(), sanitizeInput(username)]
      );

      if (existingUsers.length > 0) {
        return fail(res, 'البريد الإلكتروني أو اسم المستخدم موجود مسبقاً', 400);
      }

      const userId = uuidv4();
      const hashedPassword = await hashValue(password);
      
      await execQuery(
        `INSERT INTO users (id, username, email, password_hash, role, avatar_url, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [userId, sanitizeInput(username), email.toLowerCase(), hashedPassword, role, getRandomAvatar(), new Date()]
      );

      // تسجيل الدخول تلقائياً
      const newUser = { id: userId, email, username, role };
      loginUser(req, newUser);

      // إرسال بريد ترحيبي
      await sendEmailSafe({
        to: email,
        subject: 'مرحباً بك في Elmahdy English!',
        html: `
          <div style="font-family: 'Cairo', Arial, sans-serif; direction: rtl; padding: 20px;">
            <h2 style="color: #0056d6;">أهلاً وسهلاً بك في Elmahdy English! 🎉</h2>
            <p><strong>اسم المستخدم:</strong> ${username}</p>
            <p>نشكرك على انضمامك إلى منصتنا التعليمية.</p>
            <p>يمكنك الآن استكشاف الكورسات والبدء في رحلتك التعليمية.</p>
            <a href="${APP_URL}" style="background: #0056d6; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
              ابدأ التعلم الآن
            </a>
          </div>
        `
      });

      await logActivity(userId, 'REGISTER', { username, email });

      success(res, {
        user: newUser
      }, 'تم إنشاء الحساب بنجاح');

    } catch (error) {
      logger.error('Registration error', error);
      fail(res, 'حدث خطأ أثناء إنشاء الحساب');
    }
  }
);

// الحصول على بيانات المستخدم الحالي
app.get('/api/user/me', requireLogin, (req, res) => {
  success(res, { user: req.session.user });
});

// تحديث الملف الشخصي
app.post('/api/user/update-profile', 
  requireLogin,
  validateInput([
    body('username').isLength({ min: 3 }).withMessage('اسم المستخدم يجب أن يكون 3 أحرف على الأقل')
  ]),
  async (req, res) => {
    try {
      const { username, bio, avatar_url } = req.body;
      
      await execQuery(
        'UPDATE users SET username = $1, bio = $2, avatar_url = $3, updated_at = NOW() WHERE id = $4',
        [sanitizeInput(username), sanitizeInput(bio), avatar_url, req.session.user.id]
      );
      
      // تحديث الجلسة
      req.session.user.username = username;
      req.session.save();

      await logActivity(req.session.user.id, 'UPDATE_PROFILE', { username });

      success(res, {}, 'تم تحديث الملف الشخصي');
    } catch (error) {
      logger.error('Update profile error', error);
      fail(res, 'حدث خطأ أثناء تحديث الملف الشخصي');
    }
  }
);

// تغيير كلمة المرور
app.post('/api/user/change-password', 
  requireLogin,
  validateInput([
    body('oldPassword').notEmpty().withMessage('كلمة المرور القديمة مطلوبة'),
    body('newPassword').isLength({ min: 6 }).withMessage('كلمة المرور الجديدة يجب أن تكون 6 أحرف على الأقل')
  ]),
  async (req, res) => {
    try {
      const { oldPassword, newPassword } = req.body;

      if (!isStrongPassword(newPassword)) {
        return fail(res, 'كلمة المرور الجديدة يجب أن تحتوي على حروف كبيرة وصغيرة وأرقام ورموز', 400);
      }

      const user = await execQuery('SELECT * FROM users WHERE id = $1', [req.session.user.id]);
      
      const isOldPasswordValid = await verifyHash(oldPassword, user[0].password_hash);
      if (!isOldPasswordValid) {
        return fail(res, 'كلمة المرور القديمة غير صحيحة', 401);
      }

      const newHashedPassword = await hashValue(newPassword);
      
      await execQuery(
        'UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2',
        [newHashedPassword, req.session.user.id]
      );

      await logActivity(req.session.user.id, 'CHANGE_PASSWORD');

      success(res, {}, 'تم تغيير كلمة المرور بنجاح');
    } catch (error) {
      logger.error('Change password error', error);
      fail(res, 'حدث خطأ أثناء تغيير كلمة المرور');
    }
  }
);

// نسيان كلمة المرور
app.post('/api/user/forgot-password', 
  validateInput([
    body('email').isEmail().withMessage('بريد إلكتروني غير صالح')
  ]),
  async (req, res) => {
    try {
      const { email } = req.body;

      const user = await execQuery('SELECT * FROM users WHERE email = $1', [email]);
      if (!user.length) {
        return fail(res, 'المستخدم غير موجود', 404);
      }

      const token = generateToken(32);
      const expire = new Date(Date.now() + 15 * 60 * 1000); // 15 دقيقة

      await execQuery(
        'UPDATE users SET reset_token = $1, reset_expires = $2 WHERE id = $3',
        [token, expire, user[0].id]
      );

      await sendEmailSafe({
        to: email,
        subject: 'إعادة تعيين كلمة المرور',
        html: `
          <div style="font-family: 'Cairo', Arial, sans-serif; direction: rtl; padding: 20px;">
            <h2 style="color: #0056d6;">إعادة تعيين كلمة المرور</h2>
            <p>لقد طلبت إعادة تعيين كلمة المرور لحسابك.</p>
            <p>اضغط على الرابط التالي لإعادة تعيين كلمة المرور:</p>
            <a href="${APP_URL}/reset-password?token=${token}" style="background: #0056d6; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
              إعادة تعيين كلمة المرور
            </a>
            <p style="color: #666; margin-top: 20px;">هذا الرابط صالح لمدة 15 دقيقة فقط.</p>
          </div>
        `
      });

      success(res, {}, 'تم إرسال رابط إعادة التعيين إلى بريدك الإلكتروني');
    } catch (error) {
      logger.error('Forgot password error', error);
      fail(res, 'حدث خطأ أثناء إرسال رابط إعادة التعيين');
    }
  }
);

// إعادة تعيين كلمة المرور
app.post('/api/user/reset-password', 
  validateInput([
    body('token').notEmpty().withMessage('التوكن مطلوب'),
    body('newPassword').isLength({ min: 6 }).withMessage('كلمة المرور يجب أن تكون 6 أحرف على الأقل')
  ]),
  async (req, res) => {
    try {
      const { token, newPassword } = req.body;

      if (!isStrongPassword(newPassword)) {
        return fail(res, 'كلمة المرور يجب أن تحتوي على حروف كبيرة وصغيرة وأرقام ورموز', 400);
      }

      const users = await execQuery(
        'SELECT * FROM users WHERE reset_token = $1 AND reset_expires > NOW()',
        [token]
      );
      
      if (!users.length) {
        return fail(res, 'الرابط غير صالح أو منتهي', 400);
      }

      const newHashedPassword = await hashValue(newPassword);
      
      await execQuery(
        'UPDATE users SET password_hash = $1, reset_token = NULL, reset_expires = NULL WHERE id = $2',
        [newHashedPassword, users[0].id]
      );

      await logActivity(users[0].id, 'RESET_PASSWORD');

      success(res, {}, 'تم تغيير كلمة المرور بنجاح');
    } catch (error) {
      logger.error('Reset password error', error);
      fail(res, 'حدث خطأ أثناء إعادة تعيين كلمة المرور');
    }
  }
);

// ========= نظام المدفوعات =========

// إنشاء جلسة دفع
app.post('/api/payment/create-session', 
  requireLogin,
  validateInput([
    body('paymentSessionId').isUUID().withMessage('معرف جلسة الدفع غير صالح')
  ]),
  async (req, res) => {
    try {
      const { courseId, paymentSessionId } = req.body;

      // التحقق من جلسة الدفع
      const paymentSession = await execQuery(
        'SELECT * FROM payment_sessions WHERE id = $1 AND user_id = $2 AND status = $3',
        [paymentSessionId, req.session.user.id, 'pending']
      );

      if (paymentSession.length === 0) {
        return fail(res, 'جلسة الدفع غير موجودة أو منتهية', 404);
      }

      const session = paymentSession[0];

      // محاكاة الدفع الناجح
      const enrollmentId = uuidv4();
      
      await execQuery(
        `INSERT INTO enrollments (id, user_id, course_id, enrolled_at, progress, progress_data)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [enrollmentId, req.session.user.id, session.course_id, new Date(), 0, JSON.stringify({})]
      );

      // تحديث حالة الدفع
      await execQuery(
        'UPDATE payment_sessions SET status = $1, completed_at = $2 WHERE id = $3',
        ['completed', new Date(), paymentSessionId]
      );

      // تحديث إحصائيات الكورس
      await updateCourseStats(session.course_id);

      await logActivity(req.session.user.id, 'PAYMENT_COMPLETED', { 
        courseId: session.course_id, amount: session.amount 
      });

      success(res, {
        enrollmentId: enrollmentId,
        redirectUrl: `/course/${session.course_id}`
      }, 'تم الدفع والتسجيل في الكورس بنجاح');

    } catch (error) {
      logger.error('Payment error', error);
      fail(res, 'حدث خطأ أثناء عملية الدفع');
    }
  }
);

// ========= الإحصائيات والتقارير =========

// إحصائيات النظام
app.get('/api/stats', requireLogin, checkRole(['admin']), async (req, res) => {
  try {
    const stats = await getSystemStats();
    success(res, { stats });
  } catch (error) {
    logger.error('Get stats error', error);
    fail(res, 'حدث خطأ في جلب الإحصائيات');
  }
});

// إحصائيات متقدمة
app.get('/api/admin/stats/advanced', requireLogin, checkRole(['admin']), async (req, res) => {
  try {
    const revenueByMonth = await getRevenueReportByMonth();
    const popularCourses = await getMostPopularCourses(10);
    const systemStats = await getSystemStats();
    const revenueTrend = await getRevenueTrend(30);
    
    success(res, {
      revenueByMonth,
      popularCourses,
      systemStats,
      revenueTrend
    });
  } catch (error) {
    logger.error('Get advanced stats error', error);
    fail(res, 'حدث خطأ في جلب الإحصائيات المتقدمة');
  }
});

// إحصائيات المدرب
app.get('/api/instructor/stats', requireLogin, checkRole(['teacher']), async (req, res) => {
  try {
    const courses = await execQuery(
      'SELECT * FROM courses WHERE instructor_id = $1',
      [req.session.user.id]
    );
    
    const totalStudents = await execQuery(`
      SELECT COUNT(DISTINCT e.user_id) as count 
      FROM enrollments e
      JOIN courses c ON e.course_id = c.id
      WHERE c.instructor_id = $1
    `, [req.session.user.id]);

    const revenue = await execQuery(`
      SELECT COALESCE(SUM(ps.amount), 0) as total 
      FROM payment_sessions ps
      JOIN courses c ON ps.course_id = c.id
      WHERE c.instructor_id = $1 AND ps.status = 'completed'
    `, [req.session.user.id]);

    success(res, {
      totalCourses: courses.length,
      totalStudents: parseInt(totalStudents[0].count),
      totalRevenue: parseFloat(revenue[0].total),
      courses: courses
    });
  } catch (error) {
    logger.error('Get instructor stats error', error);
    fail(res, 'حدث خطأ في جلب إحصائيات المدرب');
  }
});

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

// تسجيل كل الإشعارات كمقروءة
app.post('/api/user/notifications/read-all', requireLogin, async (req, res) => {
  try {
    await markAllNotificationsAsRead(req.session.user.id);
    success(res, {}, 'تم تسجيل جميع الإشعارات كمقروءة');
  } catch (error) {
    logger.error('Mark all notifications as read error', error);
    fail(res, 'حدث خطأ في تسجيل الإشعارات');
  }
});

// ========= دوال الإدارة =========

// الحصول على جميع المستخدمين
app.get('/api/admin/users', requireLogin, checkRole(['admin']), async (req, res) => {
  try {
    const { page = 1, limit = 50 } = req.query;
    const users = await getAllUsers(parseInt(limit), parseInt(page));
    success(res, { users });
  } catch (error) {
    logger.error('Get all users error', error);
    fail(res, 'حدث خطأ في جلب المستخدمين');
  }
});

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

// تبديل حالة نشر الكورس
app.post('/api/courses/:id/toggle-publish', requireLogin, async (req, res) => {
  try {
    const courseId = req.params.id;
    
    // التحقق من الملكية أو صلاحيات المدير
    const course = await execQuery('SELECT * FROM courses WHERE id = $1', [courseId]);
    if (course.length === 0) {
      return fail(res, 'الكورس غير موجود', 404);
    }

    if (req.session.user.role !== 'admin' && course[0].instructor_id !== req.session.user.id) {
      return fail(res, 'غير مصرح لك', 403);
    }

    const newStatus = !course[0].published;
    await execQuery(
      'UPDATE courses SET published = $1, updated_at = NOW() WHERE id = $2',
      [newStatus, courseId]
    );
    
    await logActivity(req.session.user.id, 'TOGGLE_COURSE_PUBLISH', { courseId, newStatus });

    success(res, { published: newStatus }, `تم ${newStatus ? 'نشر' : 'إلغاء نشر'} الكورس بنجاح`);
  } catch (error) {
    logger.error('Toggle course publish error', error);
    fail(res, 'حدث خطأ أثناء تغيير حالة الكورس');
  }
});

// إضافة تقييم للكورس
app.post('/api/courses/:id/review', 
  requireLogin,
  validateInput([
    body('rating').isInt({ min: 1, max: 5 }).withMessage('التقييم يجب أن يكون بين 1 و 5'),
    body('comment').optional().isLength({ max: 1000 }).withMessage('التعليق يجب أن يكون أقل من 1000 حرف')
  ]),
  async (req, res) => {
    try {
      const courseId = req.params.id;
      const { rating, comment } = req.body;

      // التحقق من تسجيل المستخدم في الكورس
      const enrollment = await execQuery(
        'SELECT id FROM enrollments WHERE user_id = $1 AND course_id = $2',
        [req.session.user.id, courseId]
      );

      if (enrollment.length === 0) {
        return fail(res, 'يجب أن تكون مسجلاً في الكورس لإضافة تقييم', 400);
      }

      const reviewId = uuidv4();
      await execQuery(
        `INSERT INTO course_reviews (id, user_id, course_id, rating, comment, created_at)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [reviewId, req.session.user.id, courseId, rating, sanitizeInput(comment || ''), new Date()]
      );
      
      await logActivity(req.session.user.id, 'ADD_REVIEW', { courseId, rating });

      success(res, { reviewId }, 'تم إضافة التقييم بنجاح');
    } catch (error) {
      logger.error('Add review error', error);
      fail(res, 'حدث خطأ أثناء إضافة التقييم');
    }
  }
);

// ========= دوال الصيانة =========

// تنظيف المستخدمين غير النشطين
app.post('/api/admin/maintenance/cleanup-users', 
  requireLogin, 
  checkRole(['admin']),
  validateInput([
    body('days').optional().isInt({ min: 30 }).withMessage('عدد الأيام يجب أن يكون 30 على الأقل')
  ]),
  async (req, res) => {
    try {
      const { days = 180 } = req.body;
      const deletedCount = await deleteInactiveUsers(parseInt(days));
      success(res, { deletedCount }, `تم حذف ${deletedCount} مستخدم غير نشط`);
    } catch (error) {
      logger.error('Cleanup users error', error);
      fail(res, 'حدث خطأ في تنظيف المستخدمين');
    }
  }
);

// أرشيف السجلات القديمة
app.post('/api/admin/maintenance/archive-logs', 
  requireLogin, 
  checkRole(['admin']),
  validateInput([
    body('days').optional().isInt({ min: 7 }).withMessage('عدد الأيام يجب أن يكون 7 على الأقل')
  ]),
  async (req, res) => {
    try {
      const { days = 90 } = req.body;
      const archivedCount = await archiveOldLogs(parseInt(days));
      success(res, { archivedCount }, `تم أرشيف ${archivedCount} سجل`);
    } catch (error) {
      logger.error('Archive logs error', error);
      fail(res, 'حدث خطأ في أرشيف السجلات');
    }
  }
);

// تنظيف الجلسات القديمة
app.post('/api/admin/maintenance/cleanup-sessions', 
  requireLogin, 
  checkRole(['admin']),
  validateInput([
    body('days').optional().isInt({ min: 1 }).withMessage('عدد الأيام يجب أن يكون 1 على الأقل')
  ]),
  async (req, res) => {
    try {
      const { days = 30 } = req.body;
      const cleanedCount = await cleanupOldSessions(parseInt(days));
      success(res, { cleanedCount }, `تم تنظيف ${cleanedCount} جلسة`);
    } catch (error) {
      logger.error('Cleanup sessions error', error);
      fail(res, 'حدث خطأ في تنظيف الجلسات');
    }
  }
);

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

// تصدير بيانات الكورس
app.get('/api/courses/:id/export-data', 
  requireLogin, 
  checkRole(['teacher', 'admin']), 
  async (req, res) => {
    try {
      const { id } = req.params;
      
      // التحقق من الملكية
      const course = await execQuery('SELECT * FROM courses WHERE id = $1', [id]);
      if (course.length === 0) {
        return fail(res, 'الكورس غير موجود', 404);
      }

      if (req.session.user.role !== 'admin' && course[0].instructor_id !== req.session.user.id) {
        return fail(res, 'غير مصرح لك', 403);
      }

      const courseData = await exportCourseData(id);
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename=course-data-${id}.json`);
      res.json(courseData);
    } catch (error) {
      logger.error('Export course data error', error);
      fail(res, 'حدث خطأ في تصدير بيانات الكورس');
    }
  }
);

// ========= معالج للروابط غير موجودة =========
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'الرابط غير موجود',
    path: req.originalUrl,
    suggestion: 'تحقق من الرابط أو راجع documentation'
  });
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

    // جدول الجلسات (لـ express-session)
    await execQuery(`
      CREATE TABLE IF NOT EXISTS sessions (
        sid VARCHAR(255) PRIMARY KEY,
        sess JSON NOT NULL,
        expire TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
        [teacherId, 'teacher_ahmed', 'teacher@elmahdy-english.com', await hashValue('Password123!'), 'teacher', 'مدرس لغة إنجليزية محترف مع 10 سنوات خبرة']
      );

      const adminId = uuidv4();
      await execQuery(
        `INSERT INTO users (id, username, email, password_hash, role) 
         VALUES ($1, $2, $3, $4, $5)`,
        [adminId, 'admin', 'admin@elmahdy-english.com', await hashValue('Admin123!'), 'admin']
      );

      const studentId = uuidv4();
      await execQuery(
        `INSERT INTO users (id, username, email, password_hash, role) 
         VALUES ($1, $2, $3, $4, $5)`,
        [studentId, 'student_mohamed', 'student@elmahdy-english.com', await hashValue('Password123!'), 'student']
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
      const archived = await archiveOldLogs(30);
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
      const deleted = await deleteInactiveUsers(180);
      if (deleted > 0) {
        logger.info(`🗑️ Deleted ${deleted} inactive users`);
      }
    } catch (error) {
      logger.error('Inactive users cleanup error:', error);
    }
  }, 7 * 24 * 60 * 60 * 1000);

  // تنظيف الجلسات القديمة يومياً
  setInterval(async () => {
    try {
      const cleaned = await cleanupOldSessions(7);
      if (cleaned > 0) {
        logger.info(`🧽 Cleaned ${cleaned} old sessions`);
      }
    } catch (error) {
      logger.error('Sessions cleanup error:', error);
    }
  }, 24 * 60 * 60 * 1000);
}

export default app;
