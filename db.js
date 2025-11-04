// db.js - ملف إدارة قاعدة البيانات المتكامل (محدث)
import pg from 'pg';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

const { Pool } = pg;

// إعداد الاتصال بقاعدة البيانات
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://postgres:password@localhost:5432/elmahdy_english',
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// ====== دوال تنفيذ الاستعلامات ======

/**
 * تنفيذ استعلام مع معالجة الأخطاء
 */
export async function execQuery(query, params = []) {
  const client = await pool.connect();
  try {
    const result = await client.query(query, params);
    return result.rows;
  } catch (error) {
    console.error('❌ Database Query Error:', {
      query: query.substring(0, 100) + '...',
      params,
      error: error.message
    });
    throw error;
  } finally {
    client.release();
  }
}

/**
 * تنفيذ استعلام وإرجاع الصف الأول فقط
 */
export async function execQuerySingle(query, params = []) {
  const rows = await execQuery(query, params);
  return rows.length > 0 ? rows[0] : null;
}

/**
 * تنفيذ استعلام INSERT وإرجاع الصف المضاف
 */
export async function execInsert(table, data) {
  const keys = Object.keys(data);
  const values = Object.values(data);
  const placeholders = keys.map((_, i) => `$${i + 1}`).join(', ');
  
  const query = `
    INSERT INTO ${table} (${keys.join(', ')})
    VALUES (${placeholders})
    RETURNING *
  `;
  
  const result = await execQuery(query, values);
  return result[0];
}

/**
 * تنفيذ استعلام UPDATE
 */
export async function execUpdate(table, id, data) {
  const keys = Object.keys(data);
  const values = Object.values(data);
  const setClause = keys.map((key, i) => `${key} = $${i + 1}`).join(', ');
  
  const query = `
    UPDATE ${table}
    SET ${setClause}, updated_at = CURRENT_TIMESTAMP
    WHERE id = $${keys.length + 1}
    RETURNING *
  `;
  
  const result = await execQuery(query, [...values, id]);
  return result[0];
}

/**
 * تنفيذ استعلام DELETE
 */
export async function execDelete(table, id) {
  const query = `DELETE FROM ${table} WHERE id = $1 RETURNING *`;
  const result = await execQuery(query, [id]);
  return result[0];
}

/**
 * البحث في جدول معين
 */
export async function execSearch(table, searchFields, searchTerm, additionalConditions = '') {
  const conditions = searchFields.map(field => `${field} ILIKE $1`).join(' OR ');
  const query = `
    SELECT * FROM ${table}
    WHERE (${conditions}) ${additionalConditions}
    ORDER BY created_at DESC
  `;
  
  return await execQuery(query, [`%${searchTerm}%`]);
}

// ====== دوال التشفير والمساعدات ======

export function hashValue(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

export function generateId() {
  return uuidv4();
}

export function generateCode(length = 6) {
  return Math.random().toString(36).substr(2, length).toUpperCase();
}

export function formatPrice(amount) {
  return `${parseFloat(amount).toFixed(2)} EGP`;
}

// ====== دوال جديدة مطلوبة لصفحة الكورس ======

/**
 * جلب تفاصيل الكورس مع معلومات المدرب
 */
export async function getCourseDetails(courseId) {
  return await execQuerySingle(`
    SELECT 
      c.*,
      u.username as instructor_name,
      u.bio as instructor_bio,
      u.avatar_url as instructor_image,
      cat.name as category_name,
      (SELECT COUNT(*) FROM enrollments WHERE course_id = c.id) as students_count,
      (SELECT COALESCE(AVG(r.rating), 0) FROM reviews r WHERE r.course_id = c.id) as average_rating,
      (SELECT COUNT(*) FROM course_sections WHERE course_id = c.id) as sections_count
    FROM courses c
    LEFT JOIN users u ON c.instructor_id = u.id
    LEFT JOIN categories cat ON c.category_id = cat.id
    WHERE c.id = $1 AND c.published = true
  `, [courseId]);
}

/**
 * جلب أقسام الكورس
 */
export async function getCourseSections(courseId) {
  return await execQuery(`
    SELECT 
      cs.*,
      (SELECT COUNT(*) FROM section_parts WHERE section_id = cs.id) as parts_count
    FROM course_sections cs
    WHERE cs.course_id = $1
    ORDER BY cs.order_index ASC
  `, [courseId]);
}

/**
 * جلب بيانات قسم معين
 */
export async function getSectionData(sectionId) {
  return await execQuerySingle(`
    SELECT 
      cs.*,
      c.title as course_title,
      c.id as course_id,
      (SELECT COUNT(*) FROM course_sections WHERE course_id = cs.course_id) as total_sections
    FROM course_sections cs
    LEFT JOIN courses c ON cs.course_id = c.id
    WHERE cs.id = $1
  `, [sectionId]);
}

/**
 * جلب تقدم المستخدم في الكورس
 */
export async function getUserCourseProgress(userId, courseId) {
  const progress = await execQuerySingle(`
    SELECT 
      up.*,
      COUNT(DISTINCT CASE WHEN up.completed = true THEN up.section_id END) as completed_sections_count,
      (SELECT COUNT(*) FROM course_sections WHERE course_id = $2) as total_sections,
      (COUNT(DISTINCT CASE WHEN up.completed = true THEN up.section_id END) * 100.0 / 
       GREATEST((SELECT COUNT(*) FROM course_sections WHERE course_id = $2), 1)) as progress_percentage
    FROM user_progress up
    WHERE up.user_id = $1 AND up.course_id = $2
    GROUP BY up.user_id, up.course_id, up.current_section_id
  `, [userId, courseId]);

  if (!progress) {
    return {
      progress: 0,
      completedSections: [],
      currentSectionIndex: 0,
      currentSectionId: null
    };
  }

  // جلب الأقسام المكتملة
  const completedSections = await execQuery(`
    SELECT section_id FROM user_progress 
    WHERE user_id = $1 AND course_id = $2 AND completed = true
  `, [userId, courseId]);

  // جلب الفهرس الحالي
  const currentSection = await execQuerySingle(`
    SELECT cs.order_index as current_index
    FROM course_sections cs
    WHERE cs.id = $1
  `, [progress.current_section_id]);

  return {
    progress: Math.round(progress.progress_percentage),
    completedSections: completedSections.map(row => row.section_id),
    currentSectionIndex: currentSection ? currentSection.current_index : 0,
    currentSectionId: progress.current_section_id
  };
}

/**
 * تحديث تقدم المستخدم
 */
export async function updateUserProgress(userId, courseId, sectionId, completed = false) {
  const existingProgress = await execQuerySingle(`
    SELECT * FROM user_progress 
    WHERE user_id = $1 AND course_id = $2 AND section_id = $3
  `, [userId, courseId, sectionId]);

  if (existingProgress) {
    return await execUpdate('user_progress', existingProgress.id, {
      completed,
      last_accessed: new Date(),
      time_spent: (existingProgress.time_spent || 0) + 1
    });
  } else {
    return await execInsert('user_progress', {
      id: generateId(),
      user_id: userId,
      course_id: courseId,
      section_id: sectionId,
      completed,
      progress_percentage: completed ? 100 : 0,
      last_accessed: new Date(),
      time_spent: 1,
      created_at: new Date()
    });
  }
}

/**
 * الاشتراك المجاني في الكورس
 */
export async function enrollUserFree(userId, courseId) {
  // التحقق من عدم التسجيل المسبق
  const existingEnrollment = await execQuerySingle(
    'SELECT id FROM enrollments WHERE user_id = $1 AND course_id = $2',
    [userId, courseId]
  );

  if (existingEnrollment) {
    throw new Error('أنت مسجل بالفعل في هذا الكورس');
  }

  // حساب تاريخ انتهاء الصلاحية (سنة من الآن)
  const expiryDate = new Date();
  expiryDate.setFullYear(expiryDate.getFullYear() + 1);

  return await execInsert('enrollments', {
    id: generateId(),
    user_id: userId,
    course_id: courseId,
    enrolled_at: new Date(),
    expiry_date: expiryDate,
    progress: 0,
    completed: false
  });
}

/**
 * جلب بيانات المستخدم مع الكورسات المشتراة
 */
export async function getUserWithPurchasedCourses(userId) {
  const user = await execQuerySingle(`
    SELECT 
      u.id, u.username as name, u.email, u.avatar_url, u.balance,
      COALESCE(
        json_agg(
          json_build_object(
            'course_id', e.course_id,
            'expiry_date', e.expiry_date,
            'progress', e.progress
          ) 
        ) FILTER (WHERE e.id IS NOT NULL),
        '[]'
      ) as purchased_courses
    FROM users u
    LEFT JOIN enrollments e ON u.id = e.user_id
    WHERE u.id = $1
    GROUP BY u.id, u.username, u.email, u.avatar_url, u.balance
  `, [userId]);

  return user;
}

// ====== دوال المستخدمين ======

export async function createUser(userData) {
  const { username, email, password, role = 'student', bio = '', avatar_url = '' } = userData;
  
  return await execInsert('users', {
    id: generateId(),
    username,
    email,
    password_hash: hashValue(password),
    role,
    bio,
    avatar_url,
    created_at: new Date()
  });
}

export async function findUserByEmail(email) {
  return await execQuerySingle('SELECT * FROM users WHERE email = $1', [email]);
}

export async function findUserById(id) {
  return await execQuerySingle('SELECT id, username, email, role, bio, avatar_url, balance, created_at FROM users WHERE id = $1', [id]);
}

export async function findUserByCredentials(email, password) {
  return await execQuerySingle(
    'SELECT * FROM users WHERE email = $1 AND password_hash = $2',
    [email, hashValue(password)]
  );
}

export async function updateUserProfile(userId, updateData) {
  const allowedFields = ['username', 'bio', 'avatar_url', 'balance'];
  const filteredData = Object.keys(updateData)
    .filter(key => allowedFields.includes(key))
    .reduce((obj, key) => {
      obj[key] = updateData[key];
      return obj;
    }, {});

  if (Object.keys(filteredData).length === 0) {
    throw new Error('لا توجد بيانات صالحة للتحديث');
  }

  return await execUpdate('users', userId, filteredData);
}

export async function getUserStats(userId) {
  const stats = await execQuerySingle(`
    SELECT 
      (SELECT COUNT(*) FROM enrollments WHERE user_id = $1) as total_courses,
      (SELECT COUNT(*) FROM enrollments WHERE user_id = $1 AND progress = 100) as completed_courses,
      (SELECT COALESCE(SUM(progress), 0) FROM enrollments WHERE user_id = $1) as total_progress,
      (SELECT COALESCE(AVG(progress), 0) FROM enrollments WHERE user_id = $1) as average_progress
  `, [userId]);

  return stats;
}

// ====== دوال الكورسات ======

export async function getAllCourses(filters = {}) {
  let query = `
    SELECT 
      c.*, 
      u.username as instructor_name,
      u.avatar_url as instructor_avatar,
      cat.name as category_name,
      (SELECT COUNT(*) FROM course_sections cs WHERE cs.course_id = c.id) as sections_count,
      (SELECT COUNT(*) FROM enrollments e WHERE e.course_id = c.id) as students_count,
      (SELECT COALESCE(AVG(r.rating), 0) FROM reviews r WHERE r.course_id = c.id) as average_rating
    FROM courses c
    LEFT JOIN users u ON c.instructor_id = u.id
    LEFT JOIN categories cat ON c.category_id = cat.id
    WHERE c.published = true
  `;
  
  const params = [];
  let paramCount = 0;

  if (filters.category) {
    paramCount++;
    query += ` AND c.category_id = $${paramCount}`;
    params.push(filters.category);
  }

  if (filters.level) {
    paramCount++;
    query += ` AND c.level = $${paramCount}`;
    params.push(filters.level);
  }

  if (filters.search) {
    paramCount++;
    query += ` AND (c.title ILIKE $${paramCount} OR c.description ILIKE $${paramCount})`;
    params.push(`%${filters.search}%`);
  }

  if (filters.price === 'free') {
    query += ` AND c.price = 0`;
  } else if (filters.price === 'paid') {
    query += ` AND c.price > 0`;
  }

  if (filters.featured) {
    query += ` AND c.featured = true`;
  }

  if (filters.instructor_id) {
    paramCount++;
    query += ` AND c.instructor_id = $${paramCount}`;
    params.push(filters.instructor_id);
  }

  // تطبيق الترتيب
  if (filters.sort === 'popular') {
    query += ` ORDER BY students_count DESC`;
  } else if (filters.sort === 'rating') {
    query += ` ORDER BY average_rating DESC`;
  } else if (filters.sort === 'price-low') {
    query += ` ORDER BY c.price ASC`;
  } else if (filters.sort === 'price-high') {
    query += ` ORDER BY c.price DESC`;
  } else {
    query += ` ORDER BY c.created_at DESC`;
  }

  return await execQuery(query, params);
}

export async function getCourseById(courseId, userId = null) {
  const course = await execQuerySingle(`
    SELECT 
      c.*, 
      u.username as instructor_name,
      u.bio as instructor_bio,
      u.avatar_url as instructor_avatar,
      cat.name as category_name,
      (SELECT COUNT(*) FROM course_sections cs WHERE cs.course_id = c.id) as sections_count,
      (SELECT COUNT(*) FROM enrollments e WHERE e.course_id = c.id) as students_count,
      (SELECT COALESCE(AVG(r.rating), 0) FROM reviews r WHERE r.course_id = c.id) as average_rating,
      (SELECT COUNT(*) FROM reviews r WHERE r.course_id = c.id) as reviews_count
    FROM courses c
    LEFT JOIN users u ON c.instructor_id = u.id
    LEFT JOIN categories cat ON c.category_id = cat.id
    WHERE c.id = $1
  `, [courseId]);

  if (!course) return null;

  // إضافة معلومات التسجيل إذا كان المستخدم مسجل الدخول
  if (userId) {
    const enrollment = await execQuerySingle(
      'SELECT * FROM enrollments WHERE user_id = $1 AND course_id = $2',
      [userId, courseId]
    );
    
    course.is_enrolled = !!enrollment;
    course.progress = enrollment ? enrollment.progress : 0;
    course.enrollment_date = enrollment ? enrollment.enrolled_at : null;
  }

  return course;
}

export async function createCourse(courseData) {
  const {
    title,
    description,
    category,
    level = 'beginner',
    price = 0,
    is_free = false,
    image = '',
    requirements = [],
    objectives = [],
    instructor_id,
    featured = false
  } = courseData;

  return await execInsert('courses', {
    id: generateId(),
    title,
    description,
    category,
    level,
    price: parseFloat(price),
    is_free,
    image,
    requirements: JSON.stringify(requirements),
    objectives: JSON.stringify(objectives),
    instructor_id,
    featured,
    published: false,
    created_at: new Date()
  });
}

export async function updateCourse(courseId, updateData) {
  const allowedFields = [
    'title', 'description', 'category', 'level', 'price', 'is_free',
    'image', 'requirements', 'objectives', 'featured', 'published'
  ];
  
  const filteredData = Object.keys(updateData)
    .filter(key => allowedFields.includes(key))
    .reduce((obj, key) => {
      obj[key] = updateData[key];
      return obj;
    }, {});

  if (updateData.requirements) {
    filteredData.requirements = JSON.stringify(updateData.requirements);
  }

  if (updateData.objectives) {
    filteredData.objectives = JSON.stringify(updateData.objectives);
  }

  return await execUpdate('courses', courseId, filteredData);
}

export async function getInstructorCourses(instructorId) {
  return await execQuery(`
    SELECT 
      c.*,
      (SELECT COUNT(*) FROM course_sections cs WHERE cs.course_id = c.id) as sections_count,
      (SELECT COUNT(*) FROM enrollments e WHERE e.course_id = c.id) as students_count,
      (SELECT COALESCE(SUM(e.progress), 0) FROM enrollments e WHERE e.course_id = c.id) as total_progress
    FROM courses c
    WHERE c.instructor_id = $1
    ORDER BY c.created_at DESC
  `, [instructorId]);
}

// ====== دوال التسجيل في الكورسات ======

export async function enrollUserInCourse(userId, courseId) {
  // التحقق من عدم التسجيل المسبق
  const existingEnrollment = await execQuerySingle(
    'SELECT id FROM enrollments WHERE user_id = $1 AND course_id = $2',
    [userId, courseId]
  );

  if (existingEnrollment) {
    throw new Error('أنت مسجل بالفعل في هذا الكورس');
  }

  return await execInsert('enrollments', {
    id: generateId(),
    user_id: userId,
    course_id: courseId,
    enrolled_at: new Date(),
    progress: 0,
    completed: false,
    progress_data: JSON.stringify({ sections: {} })
  });
}

export async function getUserEnrollments(userId) {
  return await execQuery(`
    SELECT 
      e.*,
      c.title,
      c.description,
      c.image,
      c.category,
      c.level,
      u.username as instructor_name
    FROM enrollments e
    JOIN courses c ON e.course_id = c.id
    LEFT JOIN users u ON c.instructor_id = u.id
    WHERE e.user_id = $1
    ORDER BY e.enrolled_at DESC
  `, [userId]);
}

export async function updateEnrollmentProgress(userId, courseId, progress, progressData = null) {
  const updateData = {
    progress: Math.min(100, Math.max(0, progress)),
    updated_at: new Date()
  };

  if (progressData) {
    updateData.progress_data = JSON.stringify(progressData);
  }

  if (progress >= 100) {
    updateData.completed = true;
    updateData.completed_at = new Date();
  }

  return await execUpdate('enrollments', `${userId}-${courseId}`, updateData);
}

export async function getEnrollmentProgress(userId, courseId) {
  return await execQuerySingle(
    'SELECT * FROM enrollments WHERE user_id = $1 AND course_id = $2',
    [userId, courseId]
  );
}

// ====== دوال الدروس ======

export async function getCourseLessons(courseId) {
  return await execQuery(`
    SELECT 
      l.*,
      (SELECT COUNT(*) FROM lesson_parts lp WHERE lp.lesson_id = l.id) as parts_count,
      (SELECT COALESCE(SUM(lp.duration), 0) FROM lesson_parts lp WHERE lp.lesson_id = l.id) as total_duration
    FROM lessons l
    WHERE l.course_id = $1
    ORDER BY l.order_index, l.created_at
  `, [courseId]);
}

export async function getLessonWithParts(lessonId) {
  const lesson = await execQuerySingle('SELECT * FROM lessons WHERE id = $1', [lessonId]);
  if (!lesson) return null;

  const parts = await execQuery(`
    SELECT * FROM lesson_parts 
    WHERE lesson_id = $1 
    ORDER BY order_index, created_at
  `, [lessonId]);

  return {
    ...lesson,
    parts
  };
}

export async function createLesson(lessonData) {
  return await execInsert('lessons', {
    id: generateId(),
    ...lessonData,
    created_at: new Date()
  });
}

export async function createLessonPart(partData) {
  return await execInsert('lesson_parts', {
    id: generateId(),
    ...partData,
    created_at: new Date()
  });
}

// ====== دوال التقييمات والمراجعات ======

export async function createReview(reviewData) {
  const { user_id, course_id, rating, comment = '' } = reviewData;

  // التحقق من أن المستخدم مسجل في الكورس
  const enrollment = await execQuerySingle(
    'SELECT id FROM enrollments WHERE user_id = $1 AND course_id = $2',
    [user_id, course_id]
  );

  if (!enrollment) {
    throw new Error('يجب أن تكون مسجلاً في الكورس لتتمكن من التقييم');
  }

  // التحقق من عدم التقييم المسبق
  const existingReview = await execQuerySingle(
    'SELECT id FROM reviews WHERE user_id = $1 AND course_id = $2',
    [user_id, course_id]
  );

  if (existingReview) {
    throw new Error('لقد قمت بتقييم هذا الكورس مسبقاً');
  }

  return await execInsert('reviews', {
    id: generateId(),
    user_id,
    course_id,
    rating: Math.min(5, Math.max(1, rating)),
    comment,
    created_at: new Date()
  });
}

export async function getCourseReviews(courseId) {
  return await execQuery(`
    SELECT 
      r.*,
      u.username,
      u.avatar_url
    FROM reviews r
    JOIN users u ON r.user_id = u.id
    WHERE r.course_id = $1
    ORDER BY r.created_at DESC
  `, [courseId]);
}

// ====== دوال الإحصائيات والتقارير ======

export async function getPlatformStats() {
  return await execQuerySingle(`
    SELECT 
      (SELECT COUNT(*) FROM users) as total_users,
      (SELECT COUNT(*) FROM users WHERE role = 'student') as total_students,
      (SELECT COUNT(*) FROM users WHERE role = 'teacher') as total_teachers,
      (SELECT COUNT(*) FROM courses) as total_courses,
      (SELECT COUNT(*) FROM courses WHERE published = true) as published_courses,
      (SELECT COUNT(*) FROM enrollments) as total_enrollments,
      (SELECT COUNT(*) FROM enrollments WHERE completed = true) as completed_enrollments,
      (SELECT COALESCE(SUM(price), 0) FROM courses WHERE is_free = false) as total_revenue
  `);
}

export async function getInstructorStats(instructorId) {
  return await execQuerySingle(`
    SELECT 
      (SELECT COUNT(*) FROM courses WHERE instructor_id = $1) as total_courses,
      (SELECT COUNT(*) FROM courses WHERE instructor_id = $1 AND published = true) as published_courses,
      (SELECT COUNT(*) FROM enrollments e JOIN courses c ON e.course_id = c.id WHERE c.instructor_id = $1) as total_students,
      (SELECT COALESCE(SUM(e.progress), 0) FROM enrollments e JOIN courses c ON e.course_id = c.id WHERE c.instructor_id = $1) as total_progress,
      (SELECT COALESCE(AVG(r.rating), 0) FROM reviews r JOIN courses c ON r.course_id = c.id WHERE c.instructor_id = $1) as average_rating
  `, [instructorId]);
}

// ====== دوال المدفوعات ======

export async function createPaymentSession(paymentData) {
  return await execInsert('payment_sessions', {
    id: generateId(),
    ...paymentData,
    created_at: new Date()
  });
}

export async function updatePaymentSession(sessionId, updateData) {
  return await execUpdate('payment_sessions', sessionId, updateData);
}

export async function getPaymentSession(sessionId) {
  return await execQuerySingle(`
    SELECT ps.*, u.username, c.title as course_title
    FROM payment_sessions ps
    JOIN users u ON ps.user_id = u.id
    JOIN courses c ON ps.course_id = c.id
    WHERE ps.id = $1
  `, [sessionId]);
}

// ====== دوال الإشعارات ======

export async function createNotification(notificationData) {
  return await execInsert('notifications', {
    id: generateId(),
    ...notificationData,
    created_at: new Date(),
    read: false
  });
}

export async function getUserNotifications(userId, limit = 20) {
  return await execQuery(`
    SELECT * FROM notifications 
    WHERE user_id = $1 
    ORDER BY created_at DESC 
    LIMIT $2
  `, [userId, limit]);
}

export async function markNotificationAsRead(notificationId) {
  return await execUpdate('notifications', notificationId, { read: true });
}

// ====== دوال إدارة قاعدة البيانات ======

export async function initializeDatabase() {
  try {
    await createTables();
    await seedInitialData();
    console.log('✅ Database initialized successfully');
    return true;
  } catch (error) {
    console.error('❌ Database initialization failed:', error);
    return false;
  }
}

async function createTables() {
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
      balance DECIMAL(10,2) DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // جدول التصنيفات
  await execQuery(`
    CREATE TABLE IF NOT EXISTS categories (
      id VARCHAR(36) PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      description TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // جدول الكورسات
  await execQuery(`
    CREATE TABLE IF NOT EXISTS courses (
      id VARCHAR(36) PRIMARY KEY,
      title VARCHAR(255) NOT NULL,
      description TEXT,
      full_description TEXT,
      category_id VARCHAR(36) REFERENCES categories(id),
      level VARCHAR(50) DEFAULT 'beginner',
      price DECIMAL(10,2) DEFAULT 0,
      duration VARCHAR(100),
      image_url VARCHAR(500),
      instructor_id VARCHAR(36) REFERENCES users(id),
      published BOOLEAN DEFAULT FALSE,
      featured BOOLEAN DEFAULT FALSE,
      requirements JSONB DEFAULT '[]',
      learning_outcomes JSONB DEFAULT '[]',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // جدول أقسام الكورس
  await execQuery(`
    CREATE TABLE IF NOT EXISTS course_sections (
      id VARCHAR(36) PRIMARY KEY,
      course_id VARCHAR(36) REFERENCES courses(id) ON DELETE CASCADE,
      title VARCHAR(255) NOT NULL,
      description TEXT,
      content_type VARCHAR(20) CHECK (content_type IN ('video', 'pdf', 'quiz')),
      content_url VARCHAR(500),
      duration INTEGER DEFAULT 0,
      order_index INTEGER NOT NULL,
      is_free BOOLEAN DEFAULT false,
      questions_count INTEGER DEFAULT 0,
      pass_score INTEGER DEFAULT 70,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // جدول تقدم المستخدم
  await execQuery(`
    CREATE TABLE IF NOT EXISTS user_progress (
      id VARCHAR(36) PRIMARY KEY,
      user_id VARCHAR(36) REFERENCES users(id),
      course_id VARCHAR(36) REFERENCES courses(id),
      section_id VARCHAR(36) REFERENCES course_sections(id),
      completed BOOLEAN DEFAULT false,
      progress_percentage INTEGER DEFAULT 0,
      last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      time_spent INTEGER DEFAULT 0,
      current_section_id VARCHAR(36) REFERENCES course_sections(id),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, section_id)
    )
  `);

  // جدول التسجيلات
  await execQuery(`
    CREATE TABLE IF NOT EXISTS enrollments (
      id VARCHAR(36) PRIMARY KEY,
      user_id VARCHAR(36) REFERENCES users(id),
      course_id VARCHAR(36) REFERENCES courses(id),
      enrolled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      expiry_date DATE,
      progress INTEGER DEFAULT 0,
      completed BOOLEAN DEFAULT FALSE,
      completed_at TIMESTAMP,
      progress_data JSONB DEFAULT '{}',
      UNIQUE(user_id, course_id)
    )
  `);

  // جدول التقييمات
  await execQuery(`
    CREATE TABLE IF NOT EXISTS reviews (
      id VARCHAR(36) PRIMARY KEY,
      user_id VARCHAR(36) REFERENCES users(id),
      course_id VARCHAR(36) REFERENCES courses(id),
      rating INTEGER CHECK (rating >= 1 AND rating <= 5),
      comment TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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
      payment_method VARCHAR(100),
      transaction_id VARCHAR(255),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      completed_at TIMESTAMP
    )
  `);

  // جدول الإشعارات
  await execQuery(`
    CREATE TABLE IF NOT EXISTS notifications (
      id VARCHAR(36) PRIMARY KEY,
      user_id VARCHAR(36) REFERENCES users(id),
      title VARCHAR(255) NOT NULL,
      message TEXT NOT NULL,
      type VARCHAR(50) DEFAULT 'info',
      read BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  console.log('✅ All tables created successfully');
}

async function seedInitialData() {
  // التحقق من وجود بيانات
  const userCount = await execQuerySingle('SELECT COUNT(*) FROM users');
  
  if (parseInt(userCount.count) === 0) {
    // إضافة تصنيفات
    const categories = [
      { id: generateId(), name: 'برمجة', description: 'كورسات البرمجة وتطوير الويب' },
      { id: generateId(), name: 'تصميم', description: 'كورسات التصميم والجرافيك' },
      { id: generateId(), name: 'لغات', description: 'كورسات تعلم اللغات' },
      { id: generateId(), name: 'تسويق', description: 'كورسات التسويق الرقمي' },
      { id: generateId(), name: 'أعمال', description: 'كورسات إدارة الأعمال' }
    ];

    for (const category of categories) {
      await execInsert('categories', category);
    }

    // إضافة مستخدم مدير
    const adminId = generateId();
    await execInsert('users', {
      id: adminId,
      username: 'admin',
      email: 'admin@elmahdy-english.com',
      password_hash: hashValue('admin123'),
      role: 'admin',
      bio: 'مدير النظام في منصة المهدي للغة الإنجليزية',
      balance: 1000
    });

    // إضافة معلم تجريبي
    const teacherId = generateId();
    await execInsert('users', {
      id: teacherId,
      username: 'teacher_ahmed',
      email: 'teacher@elmahdy-english.com',
      password_hash: hashValue('teacher123'),
      role: 'teacher',
      bio: 'مدرس لغة إنجليزية محترف مع 10 سنوات خبرة في تدريس اللغة الإنجليزية لجميع المستويات',
      balance: 500
    });

    // إضافة كورس تجريبي
    const courseId = generateId();
    await execInsert('courses', {
      id: courseId,
      title: 'تعلم اللغة الإنجليزية من الصفر',
      description: 'كورس متكامل لتعلم اللغة الإنجليزية من البداية حتى الاحتراف',
      full_description: '<p>هذا الكورس الشامل سيساعدك على تعلم اللغة الإنجليزية من الصفر. سنبدأ بالأساسيات ثم ننتقل للمستويات المتقدمة.</p>',
      category_id: categories[2].id,
      level: 'beginner',
      price: 0,
      duration: '30 ساعة',
      image_url: 'https://via.placeholder.com/300x180/4A90E2/FFFFFF?text=English+Course',
      instructor_id: teacherId,
      published: true,
      requirements: JSON.stringify(['لا توجد متطلبات مسبقة', 'جهاز كمبيوتر أو هاتف ذكي', 'اتصال بالإنترنت']),
      learning_outcomes: JSON.stringify(['التحدث باللغة الإنجليزية بطلاقة', 'فهم القواعد الأساسية', 'تحسين النطق', 'اكتساب مفردات جديدة'])
    });

    // إضافة أقسام للكورس
    const sections = [
      {
        id: generateId(),
        course_id: courseId,
        title: 'مقدمة في اللغة الإنجليزية',
        description: 'تعلم الأساسيات والمفردات الأساسية',
        content_type: 'video',
        content_url: 'https://example.com/videos/intro.mp4',
        duration: 45,
        order_index: 1,
        is_free: true
      },
      {
        id: generateId(),
        course_id: courseId,
        title: 'القواعد الأساسية',
        description: 'تعلم قواعد اللغة الإنجليزية الأساسية',
        content_type: 'pdf',
        content_url: 'https://example.com/pdfs/grammar.pdf',
        duration: 60,
        order_index: 2,
        is_free: false
      },
      {
        id: generateId(),
        course_id: courseId,
        title: 'اختبار المستوى الأول',
        description: 'اختبر مستواك في اللغة الإنجليزية',
        content_type: 'quiz',
        duration: 30,
        order_index: 3,
        questions_count: 20,
        pass_score: 70,
        is_free: false
      }
    ];

    for (const section of sections) {
      await execInsert('course_sections', section);
    }

    console.log('✅ Initial data seeded successfully');
  }
}

// ====== تصدير دوال الاتصال ======

export { pool };

// اختبار الاتصال عند التحميل
export async function testConnection() {
  try {
    await execQuery('SELECT 1');
    console.log('✅ Database connection established');
    return true;
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
    return false;
  }
}

// تهيئة قاعدة البيانات عند التحميل
testConnection();
