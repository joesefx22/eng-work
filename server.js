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

// ====== إعداد __dirname لـ ES Modules ======
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ====== تحميل المتغيرات من .env ======
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// ====== إعداد اللوجر البسيط ======
const logger = {
  info: (...msg) => console.log(`[INFO ${new Date().toISOString()}]`, ...msg),
  error: (...msg) => console.error(`[ERROR ${new Date().toISOString()}]`, ...msg),
};

// ====== إعداد الاتصال بقاعدة البيانات PostgreSQL ======
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://postgres:password@localhost:5432/educationdb',
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

// ====== إعدادات الميدل وير العامة ======
app.use(cors());
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"]
    }
  }
}));
app.use(morgan('dev'));
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
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
      secure: false, 
      maxAge: 24 * 60 * 60 * 1000,
      httpOnly: true
    },
  })
);

// ====== معالج الأخطاء العالمي ======
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', err);
  res.status(500).json({ success: false, message: 'حدث خطأ داخلي في السيرفر' });
});

// ====== دالة إرسال بريد إلكتروني آمن ======
async function sendEmailSafe({ to, subject, html }) {
  try {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });
    await transporter.sendMail({ from: process.env.EMAIL_USER, to, subject, html });
    logger.info(`📧 Email sent to ${to}`);
    return true;
  } catch (error) {
    logger.error('Email send error:', error.message);
    return false;
  }
}

// ====== دالة فحص تسجيل الدخول ======
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ message: 'يجب تسجيل الدخول أولاً' });
  }
  next();
}

// ====== دوال مساعدة إضافية ======
async function hashValue(value) {
  const saltRounds = 10;
  return await bcrypt.hash(value, saltRounds);
}

async function verifyHash(value, hash) {
  return await bcrypt.compare(value, hash);
}

function generateCode(length = 6) {
  return Math.random().toString(36).substr(2, length).toUpperCase();
}

function formatPrice(amount) {
  return `${amount?.toFixed(2) || '0.00'} EGP`;
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

// ====== دوال مساعدة متقدمة ======
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

function formatDate(date) {
  return new Date(date).toLocaleDateString('ar-EG', {
    year: 'numeric',
    month: 'long',
    day: 'numeric'
  });
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

async function calculateCourseDuration(courseId) {
  const result = await execQuery(`
    SELECT COALESCE(SUM(duration),0) AS total_duration 
    FROM lessons 
    WHERE course_id = $1
  `, [courseId]);
  return result[0]?.total_duration || 0;
}

// ====== دالة تسجيل النشاط ======
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

// ====== دوال إضافية للتوسع ======
async function getAllUsers(limit = 50) {
  return await execQuery(`
    SELECT id, username, email, role, created_at 
    FROM users 
    ORDER BY created_at DESC 
    LIMIT $1
  `, [limit]);
}

async function toggleCoursePublish(courseId) {
  const course = await execQuery('SELECT published FROM courses WHERE id = $1', [courseId]);
  if (course.length === 0) throw new Error('Course not found');
  
  const newStatus = !course[0].published;
  await execQuery('UPDATE courses SET published = $1, updated_at = NOW() WHERE id = $2', [newStatus, courseId]);
  
  return newStatus;
}

async function addCourseReview(userId, courseId, rating, comment) {
  const reviewId = uuidv4();
  await execQuery(
    `INSERT INTO course_reviews (id, user_id, course_id, rating, comment, created_at)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [reviewId, userId, courseId, rating, sanitizeInput(comment), new Date()]
  );
  return reviewId;
}

async function createNotification(userId, title, message) {
  const notificationId = uuidv4();
  await execQuery(
    `INSERT INTO notifications (id, user_id, title, message, is_read, created_at)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [notificationId, userId, sanitizeInput(title), sanitizeInput(message), false, new Date()]
  );
  return notificationId;
}

async function exportUserData(userId) {
  const userData = await execQuery('SELECT * FROM users WHERE id = $1', [userId]);
  const enrollments = await execQuery('SELECT * FROM enrollments WHERE user_id = $1', [userId]);
  const reviews = await execQuery('SELECT * FROM course_reviews WHERE user_id = $1', [userId]);
  
  return {
    user: userData[0],
    enrollments,
    reviews,
    exported_at: new Date().toISOString()
  };
}

async function cleanupOldSessions(days = 30) {
  const result = await execQuery(
    'DELETE FROM sessions WHERE created_at < NOW() - INTERVAL \'$1 days\'',
    [days]
  );
  return result.rowCount;
}

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

// ====== دالة ثابتة لتوليد رابط التطبيق ======
const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;

// ========= نظام الكورسات والدروس =========

// الحصول على الكورسات
app.get('/api/courses', async (req, res) => {
  try {
    const { category, level, search, featured } = req.query;
    
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

    query += ` ORDER BY c.created_at DESC`;

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
      }
    }

    success(res, { courses });
  } catch (error) {
    logger.error('Get courses error', error);
    fail(res, 'حدث خطأ في جلب الكورسات');
  }
});

// الحصول على تفاصيل كورس
app.get('/api/courses/:id', async (req, res) => {
  try {
    const courseId = req.params.id;
    
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

    success(res, {
      ...course,
      lessons: lessons
    });

  } catch (error) {
    logger.error('Get course details error', error);
    fail(res, 'حدث خطأ في جلب تفاصيل الكورس');
  }
});

// التسجيل في كورس
app.post('/api/enroll', requireLogin, async (req, res) => {
  try {
    const { courseId } = req.body;
    
    if (!courseId) {
      return fail(res, 'معرف الكورس مطلوب', 400);
    }

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

      // تسجيل النشاط
      await logActivity(req.session.user.id, 'ENROLL_COURSE', { courseId, courseTitle: course.title });

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
});

// تحديث تقدم الطالب
app.post('/api/progress', requireLogin, async (req, res) => {
  try {
    const { courseId, lessonId, partId, completed } = req.body;
    
    if (!courseId || !lessonId || !partId) {
      return fail(res, 'معرف الكورس والدرس والجزء مطلوبون', 400);
    }

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
});

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
app.post('/api/courses', requireLogin, async (req, res) => {
  try {
    const { title, description, category, level, price, is_free, requirements, objectives } = req.body;
    
    if (!title || !description || !category) {
      return fail(res, 'العنوان والوصف والتصنيف مطلوبون', 400);
    }

    // التحقق من أن المستخدم معلم أو مدير
    if (req.session.user.role !== 'teacher' && req.session.user.role !== 'admin') {
      return fail(res, 'مسموح للمعلمين فقط', 403);
    }

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

    // تسجيل النشاط
    await logActivity(req.session.user.id, 'CREATE_COURSE', { courseId, title });

    success(res, { courseId: courseId }, 'تم إنشاء الكورس بنجاح');

  } catch (error) {
    logger.error('Create course error', error);
    fail(res, 'حدث خطأ أثناء إنشاء الكورس');
  }
});

// ========= نظام المستخدمين =========

// تسجيل الدخول
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return fail(res, 'البريد الإلكتروني وكلمة المرور مطلوبان', 400);
    }

    if (!validateEmail(email)) {
      return fail(res, 'صيغة البريد الإلكتروني غير صحيحة', 400);
    }

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

    loginUser(req, user);

    // تسجيل النشاط
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
});

// تسجيل الخروج
app.post('/api/logout', requireLogin, (req, res) => {
  // تسجيل النشاط
  logActivity(req.session.user.id, 'LOGOUT');
  
  logoutUser(req);
  success(res, {}, 'تم تسجيل الخروج بنجاح');
});

// إنشاء حساب جديد
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, role = 'student' } = req.body;
    
    if (!username || !email || !password) {
      return fail(res, 'جميع الحقول مطلوبة', 400);
    }

    if (!validateEmail(email)) {
      return fail(res, 'صيغة البريد الإلكتروني غير صحيحة', 400);
    }

    if (password.length < 6) {
      return fail(res, 'كلمة المرور يجب أن تكون 6 أحرف على الأقل', 400);
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

    // تسجيل النشاط
    await logActivity(userId, 'REGISTER', { username, email });

    success(res, {
      user: newUser
    }, 'تم إنشاء الحساب بنجاح');

  } catch (error) {
    logger.error('Registration error', error);
    fail(res, 'حدث خطأ أثناء إنشاء الحساب');
  }
});

// الحصول على بيانات المستخدم الحالي
app.get('/api/user/me', requireLogin, (req, res) => {
  success(res, { user: req.session.user });
});

// تحديث الملف الشخصي
app.post('/api/user/update-profile', requireLogin, async (req, res) => {
  try {
    const { username, bio, avatar_url } = req.body;
    
    await execQuery(
      'UPDATE users SET username = $1, bio = $2, avatar_url = $3, updated_at = NOW() WHERE id = $4',
      [sanitizeInput(username), sanitizeInput(bio), avatar_url, req.session.user.id]
    );
    
    // تحديث الجلسة
    req.session.user.username = username;
    req.session.save();

    // تسجيل النشاط
    await logActivity(req.session.user.id, 'UPDATE_PROFILE', { username });

    success(res, {}, 'تم تحديث الملف الشخصي');
  } catch (error) {
    logger.error('Update profile error', error);
    fail(res, 'حدث خطأ أثناء تحديث الملف الشخصي');
  }
});

// تغيير كلمة المرور
app.post('/api/user/change-password', requireLogin, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    
    if (!oldPassword || !newPassword) {
      return fail(res, 'أدخل البيانات كاملة', 400);
    }

    if (newPassword.length < 6) {
      return fail(res, 'كلمة المرور الجديدة يجب أن تكون 6 أحرف على الأقل', 400);
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

    // تسجيل النشاط
    await logActivity(req.session.user.id, 'CHANGE_PASSWORD');

    success(res, {}, 'تم تغيير كلمة المرور بنجاح');
  } catch (error) {
    logger.error('Change password error', error);
    fail(res, 'حدث خطأ أثناء تغيير كلمة المرور');
  }
});

// نسيان كلمة المرور
app.post('/api/user/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!validateEmail(email)) {
      return fail(res, 'البريد غير صالح', 400);
    }

    const user = await execQuery('SELECT * FROM users WHERE email = $1', [email]);
    if (!user.length) {
      return fail(res, 'المستخدم غير موجود', 404);
    }

    const token = crypto.randomBytes(32).toString('hex');
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
});

// إعادة تعيين كلمة المرور
app.post('/api/user/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    
    if (!token || !newPassword) {
      return fail(res, 'بيانات ناقصة', 400);
    }

    if (newPassword.length < 6) {
      return fail(res, 'كلمة المرور يجب أن تكون 6 أحرف على الأقل', 400);
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

    // تسجيل النشاط
    await logActivity(users[0].id, 'RESET_PASSWORD');

    success(res, {}, 'تم تغيير كلمة المرور بنجاح');
  } catch (error) {
    logger.error('Reset password error', error);
    fail(res, 'حدث خطأ أثناء إعادة تعيين كلمة المرور');
  }
});

// ========= نظام المدفوعات =========

// إنشاء جلسة دفع
app.post('/api/payment/create-session', requireLogin, async (req, res) => {
  try {
    const { courseId, paymentSessionId } = req.body;
    
    if (!paymentSessionId) {
      return fail(res, 'معرف جلسة الدفع مطلوب', 400);
    }

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

    // تسجيل النشاط
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
});

// ========= الإحصائيات والتقارير =========

// إحصائيات النظام
app.get('/api/stats', requireLogin, async (req, res) => {
  try {
    // التحقق من صلاحيات المدير
    if (req.session.user.role !== 'admin') {
      return fail(res, 'غير مصرح لك بالوصول للإحصائيات', 403);
    }

    const users = await execQuery('SELECT COUNT(*) as count FROM users');
    const courses = await execQuery('SELECT COUNT(*) as count FROM courses WHERE published = true');
    const enrollments = await execQuery('SELECT COUNT(*) as count FROM enrollments');
    const revenue = await execQuery(`
      SELECT COALESCE(SUM(amount), 0) as total FROM payment_sessions WHERE status = 'completed'
    `);

    const stats = {
      totalUsers: parseInt(users[0].count),
      totalCourses: parseInt(courses[0].count),
      totalEnrollments: parseInt(enrollments[0].count),
      totalRevenue: parseFloat(revenue[0].total)
    };

    success(res, { stats });
  } catch (error) {
    logger.error('Get stats error', error);
    fail(res, 'حدث خطأ في جلب الإحصائيات');
  }
});

// إحصائيات المدرب
app.get('/api/instructor/stats', requireLogin, async (req, res) => {
  try {
    if (req.session.user.role !== 'teacher') {
      return fail(res, 'غير مصرح لك', 403);
    }

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

// ========= دوال إضافية للتوسع =========

// الحصول على جميع المستخدمين (للمدير)
app.get('/api/admin/users', requireLogin, async (req, res) => {
  try {
    if (req.session.user.role !== 'admin') {
      return fail(res, 'غير مصرح لك', 403);
    }

    const users = await getAllUsers();
    success(res, { users });
  } catch (error) {
    logger.error('Get all users error', error);
    fail(res, 'حدث خطأ في جلب المستخدمين');
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

    const newStatus = await toggleCoursePublish(courseId);
    
    // تسجيل النشاط
    await logActivity(req.session.user.id, 'TOGGLE_COURSE_PUBLISH', { courseId, newStatus });

    success(res, { published: newStatus }, `تم ${newStatus ? 'نشر' : 'إلغاء نشر'} الكورس بنجاح`);
  } catch (error) {
    logger.error('Toggle course publish error', error);
    fail(res, 'حدث خطأ أثناء تغيير حالة الكورس');
  }
});

// إضافة تقييم للكورس
app.post('/api/courses/:id/review', requireLogin, async (req, res) => {
  try {
    const courseId = req.params.id;
    const { rating, comment } = req.body;

    if (!rating || rating < 1 || rating > 5) {
      return fail(res, 'التقييم يجب أن يكون بين 1 و 5', 400);
    }

    // التحقق من تسجيل المستخدم في الكورس
    const enrollment = await execQuery(
      'SELECT id FROM enrollments WHERE user_id = $1 AND course_id = $2',
      [req.session.user.id, courseId]
    );

    if (enrollment.length === 0) {
      return fail(res, 'يجب أن تكون مسجلاً في الكورس لإضافة تقييم', 400);
    }

    const reviewId = await addCourseReview(req.session.user.id, courseId, rating, comment);
    
    // تسجيل النشاط
    await logActivity(req.session.user.id, 'ADD_REVIEW', { courseId, rating });

    success(res, { reviewId }, 'تم إضافة التقييم بنجاح');
  } catch (error) {
    logger.error('Add review error', error);
    fail(res, 'حدث خطأ أثناء إضافة التقييم');
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
        is_read BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    logger.info('✅ Education tables created successfully');
  } catch (error) {
    logger.error('❌ Error creating education tables', error);
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
  
  // إنشاء الجداول وإضافة البيانات التجريبية
  await createEducationTables();
  await seedSampleData();
});

export default app;
