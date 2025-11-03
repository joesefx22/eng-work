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
      params.push(`%${search}%`);
    }

    if (featured) {
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
      }
    }

    res.json(courses);
  } catch (error) {
    logger.error('Get courses error', error);
    res.status(500).json({ message: 'حدث خطأ في جلب الكورسات' });
  }
});

// التسجيل في كورس
app.post('/api/enroll', requireLogin, async (req, res) => {
  try {
    const { courseId } = req.body;
    
    // التحقق من وجود الكورس
    const courses = await execQuery('SELECT * FROM courses WHERE id = $1', [courseId]);
    if (courses.length === 0) {
      return res.status(404).json({ message: 'الكورس غير موجود' });
    }

    const course = courses[0];

    // التحقق من عدم التسجيل مسبقاً
    const existingEnrollment = await execQuery(
      'SELECT id FROM enrollments WHERE user_id = $1 AND course_id = $2',
      [req.session.user.id, courseId]
    );

    if (existingEnrollment.length > 0) {
      return res.status(400).json({ message: 'أنت مسجل بالفعل في هذا الكورس' });
    }

    // إذا كان الكورس مجاني، التسجيل مباشرة
    if (course.is_free || course.price === 0) {
      const enrollmentId = uuidv4();
      
      await execQuery(
        `INSERT INTO enrollments (id, user_id, course_id, enrolled_at, progress)
         VALUES ($1, $2, $3, $4, $5)`,
        [enrollmentId, req.session.user.id, courseId, new Date(), 0]
      );

      // إرسال بريد التأكيد
      try {
        await sendEmailSafe({
          to: req.session.user.email,
          subject: 'تم تسجيلك في الكورس - احجزلي التعليمية',
          html: `
            <div style="font-family: 'Cairo', Arial, sans-serif; direction: rtl; padding: 20px;">
              <h2 style="color: #1a7f46;">تم تسجيلك في الكورس بنجاح! 🎉</h2>
              <p><strong>الكورس:</strong> ${course.title}</p>
              <p><strong>المدرب:</strong> ${course.instructor_name}</p>
              <p>يمكنك الآن البدء في التعلم من خلال لوحة التعلم.</p>
              <a href="${APP_URL}/course/${courseId}" style="background: #1a7f46; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
                ابدأ التعلم
              </a>
            </div>
          `
        });
      } catch (emailError) {
        logger.error('Failed to send enrollment email:', emailError);
      }

      return res.json({ 
        message: 'تم التسجيل في الكورس بنجاح',
        enrollmentId: enrollmentId,
        redirectUrl: `/course/${courseId}`
      });
    }

    // إذا كان الكورس مدفوع، إنشاء طلب دفع
    const paymentSession = {
      id: uuidv4(),
      user_id: req.session.user.id,
      course_id: courseId,
      amount: course.price,
      status: 'pending',
      created_at: new Date()
    };

    await execQuery(
      `INSERT INTO payment_sessions (id, user_id, course_id, amount, status, created_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [paymentSession.id, paymentSession.user_id, paymentSession.course_id, 
       paymentSession.amount, paymentSession.status, paymentSession.created_at]
    );

    res.json({
      message: 'يجب إتمام عملية الدفع',
      paymentRequired: true,
      paymentSessionId: paymentSession.id,
      amount: course.price
    });

  } catch (error) {
    logger.error('Enrollment error', error);
    res.status(500).json({ message: 'حدث خطأ أثناء التسجيل في الكورس' });
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
      return res.status(404).json({ message: 'الكورس غير موجود' });
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
        'SELECT progress, completed_lessons FROM enrollments WHERE user_id = $1 AND course_id = $2',
        [req.session.user.id, courseId]
      );
      
      course.is_enrolled = enrollment.length > 0;
      course.progress = enrollment.length > 0 ? enrollment[0].progress : 0;
      course.completed_lessons = enrollment.length > 0 ? enrollment[0].completed_lessons : [];
    }

    res.json({
      ...course,
      lessons: lessons
    });

  } catch (error) {
    logger.error('Get course details error', error);
    res.status(500).json({ message: 'حدث خطأ في جلب تفاصيل الكورس' });
  }
});

// تحديث تقدم الطالب
app.post('/api/progress', requireLogin, async (req, res) => {
  try {
    const { courseId, lessonId, partId, completed } = req.body;
    
    // الحصول على التسجيل الحالي
    const enrollment = await execQuery(
      'SELECT * FROM enrollments WHERE user_id = $1 AND course_id = $2',
      [req.session.user.id, courseId]
    );

    if (enrollment.length === 0) {
      return res.status(404).json({ message: 'أنت غير مسجل في هذا الكورس' });
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

    const progress = Math.round((completedParts / totalParts[0].count) * 100);

    // تحديث قاعدة البيانات
    await execQuery(
      'UPDATE enrollments SET progress = $1, progress_data = $2, updated_at = $3 WHERE user_id = $4 AND course_id = $5',
      [progress, JSON.stringify(progressData), new Date(), req.session.user.id, courseId]
    );

    res.json({
      message: 'تم تحديث التقدم',
      progress: progress,
      completedParts: completedParts,
      totalParts: totalParts[0].count
    });

  } catch (error) {
    logger.error('Update progress error', error);
    res.status(500).json({ message: 'حدث خطأ أثناء تحديث التقدم' });
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

    res.json(enrollments);
  } catch (error) {
    logger.error('Get user courses error', error);
    res.status(500).json({ message: 'حدث خطأ في جلب كورساتك' });
  }
});

// إنشاء كورس جديد (للمعلمين)
app.post('/api/courses', requireLogin, async (req, res) => {
  try {
    const { title, description, category, level, price, is_free, requirements, objectives } = req.body;
    
    if (!title || !description || !category) {
      return res.status(400).json({ message: 'العنوان والوصف والتصنيف مطلوبون' });
    }

    // التحقق من أن المستخدم معلم أو مدير
    if (req.session.user.role !== 'teacher' && req.session.user.role !== 'admin') {
      return res.status(403).json({ message: 'مسموح للمعلمين فقط' });
    }

    const courseId = uuidv4();
    
    await execQuery(
      `INSERT INTO courses (id, title, description, category, level, price, is_free, 
       requirements, objectives, instructor_id, published, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
      [courseId, title, description, category, level, price || 0, is_free || false,
       JSON.stringify(requirements || []), JSON.stringify(objectives || []),
       req.session.user.id, false, new Date()]
    );

    res.json({
      message: 'تم إنشاء الكورس بنجاح',
      courseId: courseId,
      success: true
    });

  } catch (error) {
    logger.error('Create course error', error);
    res.status(500).json({ message: 'حدث خطأ أثناء إنشاء الكورس' });
  }
});

// ========= الجداول الجديدة في قاعدة البيانات =========

async function createEducationTables() {
  try {
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

    logger.info('✅ Education tables created successfully');
  } catch (error) {
    logger.error('❌ Error creating education tables', error);
  }
}

// استدعاء الدالة في بداية التشغيل
createEducationTables();
