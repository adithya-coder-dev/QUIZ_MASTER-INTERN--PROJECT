from datetime import datetime
from controller.database import db

# ============================================================
# USER, ROLE, STUDENT, STAFF
# ============================================================

class User(db.Model):
    __tablename__ = "user"

    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    username = db.Column(db.String(80), unique=True, nullable=False)   # email / login
    email = db.Column(db.String(120), unique=True, nullable=False)

    password_hash = db.Column(db.String(128), nullable=False)

    full_name = db.Column(db.String(120), nullable=False)
   
    profile_image = db.Column(db.String(255))
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    roles = db.relationship(
        "Role",
        secondary="user_role",
        backref=db.backref("users", lazy=True)
    )

    student_details = db.relationship(
        "Student",
        backref="user",
        uselist=False,
        cascade="all, delete-orphan"
    )

    staff_details = db.relationship(
        "Staff",
        backref="user",
        uselist=False,
        cascade="all, delete-orphan"
    )

    attempts = db.relationship(
        "QuizAttempt",
        backref="user",
        cascade="all, delete-orphan"
    )
    is_active = db.Column(db.Boolean, default=True)  

class Role(db.Model):
    __tablename__ = "role"

    role_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    # admin / teacher / user


class UserRole(db.Model):
    __tablename__ = "user_role"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.user_id"),
        nullable=False
    )

    role_id = db.Column(
        db.Integer,
        db.ForeignKey("role.role_id"),
        nullable=False
    )


class Staff(db.Model):
    __tablename__ = "staff"

    staff_id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.user_id"),
        unique=True,
        nullable=False
    )

    is_active = db.Column(db.Boolean, default=True)


class Student(db.Model):
    __tablename__ = "student"

    student_id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.user_id"),
        unique=True,
        nullable=False
    )

    is_active = db.Column(db.Boolean, default=True)


# ============================================================
# QUIZ CONTENT (TEACHER)
# ============================================================

class Subject(db.Model):
    __tablename__ = "subject"

    subject_id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    chapters = db.relationship(
        "Chapter",
        backref="subject",
        cascade="all, delete-orphan"
    )


class Chapter(db.Model):
    __tablename__ = "chapter"

    chapter_id = db.Column(db.Integer, primary_key=True)

    subject_id = db.Column(
        db.Integer,
        db.ForeignKey("subject.subject_id"),
        nullable=False
    )

    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)

    quizzes = db.relationship(
        "Quiz",
        backref="chapter",
        cascade="all, delete-orphan"
    )


class Quiz(db.Model):
    __tablename__ = "quiz"

    quiz_id = db.Column(db.Integer, primary_key=True)

    chapter_id = db.Column(
        db.Integer,
        db.ForeignKey("chapter.chapter_id"),
        nullable=False
    )

    scheduled_date = db.Column(db.DateTime, nullable=False)
    duration = db.Column(db.Integer, nullable=False)  # minutes
    status = db.Column(db.String(20), default="active")

    questions = db.relationship(
        "Question",
        backref="quiz",
        cascade="all, delete-orphan"
    )

    attempts = db.relationship(
        "QuizAttempt",
        backref="quiz",
        cascade="all, delete-orphan"
    )


# ============================================================
# QUESTIONS
# ============================================================

class Question(db.Model):
    __tablename__ = "question"

    question_id = db.Column(db.Integer, primary_key=True)

    quiz_id = db.Column(
        db.Integer,
        db.ForeignKey("quiz.quiz_id"),
        nullable=False
    )

    title = db.Column(db.String(255), nullable=False)
    statement = db.Column(db.Text, nullable=False)

    option_1 = db.Column(db.String(255), nullable=False)
    option_2 = db.Column(db.String(255), nullable=False)
    option_3 = db.Column(db.String(255), nullable=False)
    option_4 = db.Column(db.String(255), nullable=False)

    correct_option = db.Column(db.Integer, nullable=False)


# ============================================================
# QUIZ ATTEMPTS & ANSWERS (STUDENT)
# ============================================================

class QuizAttempt(db.Model):
    __tablename__ = "quiz_attempt"

    attempt_id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.user_id"),
        nullable=False
    )

    quiz_id = db.Column(
        db.Integer,
        db.ForeignKey("quiz.quiz_id"),
        nullable=False
    )

    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)

    score = db.Column(db.Integer, default=0)
    total_questions = db.Column(db.Integer)
    submitted = db.Column(db.Boolean, default=False)

    violations = db.Column(db.Integer, default=0)

    answers = db.relationship(
        "UserAnswer",
        backref="attempt",
        cascade="all, delete-orphan"
    )


class UserAnswer(db.Model):
    __tablename__ = "user_answer"

    answer_id = db.Column(db.Integer, primary_key=True)

    attempt_id = db.Column(
        db.Integer,
        db.ForeignKey("quiz_attempt.attempt_id"),
        nullable=False
    )

    question_id = db.Column(
        db.Integer,
        db.ForeignKey("question.question_id"),
        nullable=False
    )

    selected_option = db.Column(db.Integer, nullable=False)
    is_correct = db.Column(db.Boolean)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Note(db.Model):
    __tablename__ = "note"

    note_id = db.Column(db.Integer, primary_key=True)

    title = db.Column(db.String(200), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)

    subject_id = db.Column(
        db.Integer,
        db.ForeignKey("subject.subject_id"),  # ✅ FIXED
        nullable=False
    )

    chapter_id = db.Column(
        db.Integer,
        db.ForeignKey("chapter.chapter_id"),  # ✅ FIXED
        nullable=False
    )

    uploaded_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    # relationships (match model class names)
    subject = db.relationship("Subject", backref="notes")
    chapter = db.relationship("Chapter", backref="notes")