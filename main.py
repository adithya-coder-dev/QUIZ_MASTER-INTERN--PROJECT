import os
from functools import wraps
from datetime import datetime
from flask_login import current_user
from flask import abort
from flask_login import LoginManager, login_required, current_user
from flask import send_from_directory
from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import send_from_directory
from controller.config import Config
from controller.database import db
from controller.models import (
    User, Role, UserRole,
    Student, Staff,
    Subject, Chapter, Quiz, Question,
    QuizAttempt, UserAnswer, Note
)
from sqlalchemy.orm import joinedload
from google import genai
from controller.llm_service import generate_mcq_questions
import fitz
# ============================================================
# APP SETUP
# ============================================================
app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    if user and not user.is_active:
        return None
    return user


app.config.from_object(Config)

db.init_app(app)

UPLOAD_FOLDER = "uploads/profile_images"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

with app.app_context():
    db.create_all()

    # ---------------- SEED ROLES ----------------
    def get_or_create_role(role_name):
        role = Role.query.filter_by(name=role_name).first()
        if not role:
            role = Role(name=role_name)
            db.session.add(role)
            db.session.commit()
        return role

    admin_role = get_or_create_role("admin")
    teacher_role = get_or_create_role("teacher")
    user_role = get_or_create_role("user")

    # ---------------- SEED ADMIN ----------------
    admin_user = User.query.filter_by(username="admin").first()
    if not admin_user:
        admin_user = User(
            username="admin",
            email="admin@qma.com",
            password_hash=generate_password_hash("admin123"),
            full_name="System Admin"
        )
        db.session.add(admin_user)
        db.session.commit()
        db.session.add(UserRole(
            user_id=admin_user.user_id,
            role_id=admin_role.role_id
        ))
        db.session.commit()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

UPLOAD_NOTES_FOLDER = os.path.join(BASE_DIR, "uploads", "notes")
os.makedirs(UPLOAD_NOTES_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {"pdf", "doc", "docx"}

app.config["UPLOAD_NOTES_FOLDER"] = UPLOAD_NOTES_FOLDER


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
   

# ============================================================
# HELPERS & DECORATORS
# ============================================================
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def get_user_role(user_id):
    role = (
        db.session.query(Role.name)
        .join(UserRole, Role.role_id == UserRole.role_id)
        .filter(UserRole.user_id == user_id)
        .first()
    )
    return role[0] if role else None


# -------- ADDED (REQUIRED FOR USER QUIZZES) --------
def has_attempted(user_id, quiz_id):
    return QuizAttempt.query.filter_by(
        user_id=user_id,
        quiz_id=quiz_id,
        submitted=True
    ).first() is not None
# --------------------------------------------------


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login first")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if session.get("role") != required_role:
                flash("Unauthorized access")
                return redirect(url_for("login"))
            return f(*args, **kwargs)
        return wrapper
    return decorator

# ============================================================
# HOME
# ============================================================
@app.route("/")
def home():
    return render_template("home.html")

# ============================================================
# REGISTRATION
# ============================================================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":

        user = User(
            username=request.form["username"],
            email=request.form["email"],
            password_hash=generate_password_hash(request.form["password"]),
            full_name=request.form["full_name"],
        )

        # Check duplicate user
        if User.query.filter(
            (User.username == user.username) |
            (User.email == user.email)
        ).first():
            flash("User already exists")
            return redirect(url_for("register"))

        db.session.add(user)
        db.session.commit()

        # 🔑 ROLE SELECTION (FIXED & SAFE)
        selected_role = request.form.get("role", "student")

        if selected_role == "teacher":
            role = Role.query.filter_by(name="teacher").first()
            db.session.add(UserRole(
                user_id=user.user_id,
                role_id=role.role_id
            ))
            db.session.add(Staff(user_id=user.user_id))
        else:
            # Default → student
            role = Role.query.filter_by(name="user").first()
            db.session.add(UserRole(
                user_id=user.user_id,
                role_id=role.role_id
            ))
            db.session.add(Student(user_id=user.user_id))

        db.session.commit()

        flash("Registration successful")
        return redirect(url_for("login"))

    return render_template("register.html")


# ============================================================
# LOGIN
# ============================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter(
            (User.username == request.form["username"]) |
            (User.email == request.form["username"])
        ).first()

        if not user or not check_password_hash(
            user.password_hash, request.form["password"]
        ):
            flash("Invalid credentials")
            return redirect(url_for("login"))

        role = get_user_role(user.user_id)
        session["user_id"] = user.user_id
        session["role"] = role

        if role == "admin":
            return redirect(url_for("admin_dashboard"))
        elif role == "teacher":
            return redirect(url_for("teacher_dashboard"))
        else:
            return redirect(url_for("user_dashboard"))

    return render_template("login.html")

# ============================================================
# ADMIN LOGIN
# ============================================================
@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        user = User.query.filter(
            (User.username == request.form["username"]) |
            (User.email == request.form["username"])
        ).first()

        if not user or not check_password_hash(
            user.password_hash, request.form["password"]
        ):
            flash("Invalid admin credentials")
            return redirect(url_for("admin_login"))

        if get_user_role(user.user_id) != "admin":
            flash("Unauthorized")
            return redirect(url_for("admin_login"))

        session["user_id"] = user.user_id
        session["role"] = "admin"
        return redirect(url_for("admin_dashboard"))

    return render_template("admin_login.html")

# ============================================================
# DASHBOARDS
# ============================================================
@app.route("/user/dashboard")
@login_required
@role_required("user")
def user_dashboard():
    quizzes = Quiz.query.all()
    return render_template(
        "user/dashboard.html",
        user=User.query.get(session["user_id"]),
        quizzes=quizzes,
        has_attempted=has_attempted
    )


@app.route("/teacher/dashboard")
@login_required
@role_required("teacher")
def teacher_dashboard():
    quizzes = Quiz.query.options(
        joinedload(Quiz.chapter).joinedload(Chapter.subject)
    ).all()

    return render_template(
        "teacher/dashboard.html",
        quizzes=quizzes,
        total_subjects=Subject.query.count(),
        total_chapters=Chapter.query.count(),
        total_quizzes=Quiz.query.count()
    )

@app.route("/admin/dashboard")
@login_required
@role_required("admin")
def admin_dashboard():
    return render_template("admin/dashboard.html")

# ============================================================
# USER — UPCOMING QUIZZES (ADDED)
# ============================================================
@app.route("/user/results")
@login_required
@role_required("user")
def user_quizzes():
    attempts = (
        db.session.query(QuizAttempt)
        .join(Quiz)
        .join(Chapter)
        .join(Subject)
        .filter(QuizAttempt.submitted == True)
        .filter(QuizAttempt.user_id == current_user.user_id)
        .order_by(QuizAttempt.submitted_at.desc())
        .all()
    )

    return render_template(
        "user/results.html",
        attempts=attempts
    )


@app.route("/quizzes/<int:quiz_id>/begin")
@login_required
@role_required("user")
def start_quiz(quiz_id):
    if has_attempted(session["user_id"], quiz_id):
        flash("You have already attempted this quiz.")
        return redirect(url_for("user_quizzes"))

    quiz = Quiz.query.get_or_404(quiz_id)

    attempt = QuizAttempt(
        user_id=session["user_id"],
        quiz_id=quiz_id,
        start_time=datetime.utcnow(),
        total_questions=len(quiz.questions)
    )

    db.session.add(attempt)
    db.session.commit()

    return redirect(url_for("take_quiz", attempt_id=attempt.attempt_id))


# ============================================================
# START QUIZ — CREATE ATTEMPT (ADDED)
# ============================================================
@app.route("/quizzes/<int:quiz_id>/attempt", methods=["POST"])
@login_required
@role_required("user")
def begin_attempt(quiz_id):
    if has_attempted(session["user_id"], quiz_id):
        flash("Quiz already attempted")
        return redirect(url_for("user_quizzes"))

    attempt = QuizAttempt(
        user_id=session["user_id"],
        quiz_id=quiz_id,
        started_at=datetime.utcnow(),
        submitted=False
    )
    db.session.add(attempt)
    db.session.commit()

    return redirect(url_for("take_quiz", attempt_id=attempt.attempt_id))


#     Take Quiz (display questions)      #
@app.route("/quiz/attempt/<int:attempt_id>")
@login_required
@role_required("user")
def take_quiz(attempt_id):
    attempt = QuizAttempt.query.get_or_404(attempt_id)

    if attempt.submitted:
        flash("Quiz already submitted")
        return redirect(url_for("user_dashboard"))

    quiz = Quiz.query.get(attempt.quiz_id)

    elapsed = (datetime.utcnow() - attempt.start_time).total_seconds()
    if elapsed > quiz.duration * 60:
        attempt.submitted = True
        attempt.end_time = datetime.utcnow()
        db.session.commit()
        flash("Time up! Quiz auto-submitted.")
        return redirect(url_for("user_dashboard"))

    questions = Question.query.filter_by(quiz_id=quiz.quiz_id).all()

    return render_template(
        "user/take_quiz.html",
        quiz=quiz,
        attempt=attempt,
        questions=questions
    )
# ============================================================
# USER — SUBMIT QUIZ
# ============================================================
@app.route("/quiz/attempt/<int:attempt_id>/submit", methods=["POST"])
@login_required
@role_required("user")
def submit_quiz(attempt_id):
    attempt = QuizAttempt.query.get_or_404(attempt_id)

    if attempt.submitted:
        flash("Quiz already submitted")
        return redirect(url_for("user_dashboard"))

    questions = Question.query.filter_by(
        quiz_id=attempt.quiz_id
    ).all()

    score = 0

    for q in questions:
        selected = request.form.get(f"question_{q.question_id}")

        if not selected:
            continue

        selected = int(selected)
        is_correct = selected == q.correct_option

        if is_correct:
            score += 1

        db.session.add(UserAnswer(
            attempt_id=attempt.attempt_id,
            question_id=q.question_id,
            selected_option=selected,
            is_correct=is_correct
        ))

    attempt.score = score
    attempt.total_questions = len(questions)
    attempt.submitted = True
    attempt.end_time = datetime.utcnow()

    db.session.commit()

    flash(f"Quiz submitted! Your score: {score}/{len(questions)}")
    return redirect(url_for("user_dashboard"))

# ============================================================
# USER — AUTO SAVE ANSWER (AJAX)
# ============================================================
@app.route("/quiz/answer/save", methods=["POST"])
@login_required
@role_required("user")
def save_answer():
    attempt_id = request.form.get("attempt_id", type=int)
    question_id = request.form.get("question_id", type=int)
    selected_option = request.form.get("selected_option", type=int)

    if not all([attempt_id, question_id, selected_option]):
        return {"status": "error", "message": "Invalid data"}, 400

    attempt = QuizAttempt.query.get_or_404(attempt_id)

    if attempt.submitted:
        return {"status": "locked"}

    answer = UserAnswer.query.filter_by(
        attempt_id=attempt_id,
        question_id=question_id
    ).first()

    if answer:
        answer.selected_option = selected_option
    else:
        answer = UserAnswer(
            attempt_id=attempt_id,
            question_id=question_id,
            selected_option=selected_option
        )
        db.session.add(answer)

    db.session.commit()
    return {"status": "saved"}

# ============================================================
# USER — FINAL SUBMIT QUIZ
# ============================================================
@app.route("/quiz/submit/<int:attempt_id>", methods=["POST"])
@login_required
@role_required("user")
def submit_quiz_final(attempt_id):
    attempt = QuizAttempt.query.get_or_404(attempt_id)

    # Prevent double submission
    if attempt.submitted:
        flash("Quiz already submitted")
        return redirect(url_for("user_dashboard"))

    # Fetch all answers by user
    answers = UserAnswer.query.filter_by(
        attempt_id=attempt_id
    ).all()

    score = 0

    for answer in answers:
        question = Question.query.get(answer.question_id)
        if question and answer.selected_option == question.correct_option:
            score += 1

    # Save result
    attempt.score = score
    attempt.submitted = True
    attempt.submitted_at = datetime.utcnow()

    db.session.commit()

    return redirect(url_for("quiz_result", attempt_id=attempt_id))


# ============================================================
# USER — QUIZ RESULT
# ============================================================
@app.route("/quiz/result/<int:attempt_id>")
@login_required
@role_required("user")
def quiz_result(attempt_id):
    attempt = QuizAttempt.query.get_or_404(attempt_id)

    if not attempt.submitted:
        flash("Quiz not submitted yet")
        return redirect(url_for("user_dashboard"))

    quiz = Quiz.query.get(attempt.quiz_id)
    total_questions = Question.query.filter_by(
        quiz_id=attempt.quiz_id
    ).count()

    return render_template(
        "user/results.html",
        attempt=attempt,
        quiz=quiz,
        total_questions=total_questions
    )

# ============================================================
# USER — QUIZ REVIEW (QUESTION-WISE)
# ============================================================
@app.route("/quiz/review/<int:attempt_id>")
@login_required
@role_required("user")
def quiz_review(attempt_id):
    attempt = QuizAttempt.query.get_or_404(attempt_id)

    if not attempt.submitted:
        flash("Quiz not submitted yet")
        return redirect(url_for("user_dashboard"))

    questions = Question.query.filter_by(
        quiz_id=attempt.quiz_id
    ).all()

    answers = UserAnswer.query.filter_by(
        attempt_id=attempt_id
    ).all()

    answer_map = {a.question_id: a for a in answers}

    return render_template(
        "user/review.html",
        attempt=attempt,
        questions=questions,
        answer_map=answer_map
    )


# ============================================================
# TEACHER CRUD — SUBJECTS
# ============================================================
@app.route("/teacher/subjects")
@login_required
@role_required("teacher")
def teacher_subjects():
    return render_template(
        "teacher/subjects.html",
        subjects=Subject.query.all()
    )


@app.route("/teacher/subjects/new", methods=["POST"])
@login_required
@role_required("teacher")
def create_subject():
    db.session.add(
        Subject(
            name=request.form["name"],
            description=request.form.get("description")
        )
    )
    db.session.commit()
    return redirect(url_for("teacher_subjects"))


@app.route("/teacher/subjects/<int:subject_id>/edit", methods=["POST"])
@login_required
@role_required("teacher")
def edit_subject(subject_id):
    s = Subject.query.get_or_404(subject_id)
    s.name = request.form["name"]
    s.description = request.form.get("description")
    db.session.commit()
    return redirect(url_for("teacher_subjects"))


@app.route("/teacher/subjects/<int:subject_id>/delete", methods=["POST"])
@login_required
@role_required("teacher")
def delete_subject(subject_id):
    db.session.delete(Subject.query.get_or_404(subject_id))
    db.session.commit()
    return redirect(url_for("teacher_subjects"))

# ============================================================
# TEACHER CRUD — CHAPTERS
# ============================================================
@app.route("/teacher/subjects/<int:subject_id>/chapters")
@login_required
@role_required("teacher")
def teacher_chapters(subject_id):
    return render_template(
        "teacher/chapters.html",
        subject=Subject.query.get_or_404(subject_id),
        chapters=Chapter.query.filter_by(subject_id=subject_id).all()
    )


@app.route("/teacher/chapters/new", methods=["POST"])
@login_required
@role_required("teacher")
def create_chapter():
    c = Chapter(
        subject_id=request.form["subject_id"],
        name=request.form["name"],
        description=request.form.get("description")
    )
    db.session.add(c)
    db.session.commit()
    return redirect(url_for("teacher_chapters", subject_id=c.subject_id))


@app.route("/teacher/chapters/<int:chapter_id>/edit", methods=["POST"])
@login_required
@role_required("teacher")
def edit_chapter(chapter_id):
    c = Chapter.query.get_or_404(chapter_id)
    c.name = request.form["name"]
    c.description = request.form.get("description")
    db.session.commit()
    return redirect(url_for("teacher_chapters", subject_id=c.subject_id))


@app.route("/teacher/chapters/<int:chapter_id>/delete", methods=["POST"])
@login_required
@role_required("teacher")
def delete_chapter(chapter_id):
    c = Chapter.query.get_or_404(chapter_id)
    sid = c.subject_id
    db.session.delete(c)
    db.session.commit()
    return redirect(url_for("teacher_chapters", subject_id=sid))

# ============================================================
# TEACHER CRUD — QUIZZES
# ============================================================
@app.route("/teacher/chapters/<int:chapter_id>/quizzes")
@login_required
@role_required("teacher")
def teacher_quizzes(chapter_id):
    chapter = Chapter.query.get_or_404(chapter_id)
    subject = Subject.query.get_or_404(chapter.subject_id)
    quizzes = Quiz.query.filter_by(chapter_id=chapter_id).all()

    return render_template(
        "teacher/quizzes.html",
        chapter=chapter,
        subject=subject,   # ✅ THIS FIXES THE ERROR
        quizzes=quizzes
    )

@app.route("/teacher/quizzes/new", methods=["POST"])
@login_required
@role_required("teacher")
def create_quiz():

    # 🔑 FIX: convert string → datetime
    raw_date = request.form["scheduled_date"]
    scheduled_date = datetime.strptime(raw_date, "%Y-%m-%dT%H:%M")

    q = Quiz(
        chapter_id=int(request.form["chapter_id"]),
        scheduled_date=scheduled_date,
        duration=int(request.form["duration"])
    )

    db.session.add(q)
    db.session.commit()

    return redirect(url_for("teacher_quizzes", chapter_id=q.chapter_id))


@app.route("/teacher/quizzes/<int:quiz_id>/edit", methods=["POST"])
@login_required
@role_required("teacher")
def edit_quiz(quiz_id):
    q = Quiz.query.get_or_404(quiz_id)
    q.scheduled_date = request.form["scheduled_date"]
    q.duration = request.form["duration"]
    q.status = request.form.get("status", q.status)
    db.session.commit()
    return redirect(url_for("teacher_quizzes", chapter_id=q.chapter_id))


@app.route("/teacher/quizzes/<int:quiz_id>/delete", methods=["POST"])
@login_required
@role_required("teacher")
def delete_quiz(quiz_id):
    q = Quiz.query.get_or_404(quiz_id)
    cid = q.chapter_id
    db.session.delete(q)
    db.session.commit()
    return redirect(url_for("teacher_quizzes", chapter_id=cid))

# ============================================================
# TEACHER CRUD — QUESTIONS
# ============================================================
@app.route("/teacher/quizzes/<int:quiz_id>/questions")
@login_required
@role_required("teacher")
def teacher_questions(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    chapter = Chapter.query.get_or_404(quiz.chapter_id)
    subject = Subject.query.get_or_404(chapter.subject_id)

    questions = Question.query.filter_by(quiz_id=quiz_id).all()

    return render_template(
        "teacher/questions.html",
        quiz=quiz,
        chapter=chapter,
        subject=subject,     # ✅ THIS WAS MISSING
        questions=questions
    )

@app.route("/teacher/questions/create", methods=["POST"])
@login_required
@role_required("teacher")
def create_question():
    q = Question(
        quiz_id=request.form["quiz_id"],
        title=request.form["title"],
        statement=request.form["statement"],
        option_1=request.form["option_1"],
        option_2=request.form["option_2"],
        option_3=request.form["option_3"],
        option_4=request.form["option_4"],
        correct_option=int(request.form["correct_option"])
    )

    db.session.add(q)
    db.session.commit()

    # 🔹 Add another question (keep modal open)
    if request.form.get("add_more") == "1":
        return redirect(url_for(
            "teacher_questions",
            quiz_id=request.form["quiz_id"],
            add_more=1
        ))

    # 🔹 Normal save
    return redirect(url_for(
        "teacher_questions",
        quiz_id=request.form["quiz_id"]
    ))



@app.route("/teacher/questions/<int:question_id>/edit", methods=["POST"])
@login_required
@role_required("teacher")
def edit_question(question_id):
    q = Question.query.get_or_404(question_id)
    q.title = request.form["title"]
    q.statement = request.form["statement"]
    q.option_1 = request.form["option_1"]
    q.option_2 = request.form["option_2"]
    q.option_3 = request.form["option_3"]
    q.option_4 = request.form["option_4"]
    q.correct_option = request.form["correct_option"]
    db.session.commit()
    return redirect(url_for("teacher_questions", quiz_id=q.quiz_id))


@app.route("/teacher/questions/<int:question_id>/delete", methods=["POST"])
@login_required
@role_required("teacher")
def delete_question(question_id):
    q = Question.query.get_or_404(question_id)
    qid = q.quiz_id
    db.session.delete(q)
    db.session.commit()
    return redirect(url_for("teacher_questions", quiz_id=qid))

# ============================================================
# TEACHER — QUIZ ANALYTICS
# ============================================================
@app.route("/teacher/quizzes/<int:quiz_id>/analytics")
@login_required
@role_required("teacher")
def quiz_analytics(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)

    attempts = (
        QuizAttempt.query
        .filter_by(quiz_id=quiz_id, submitted=True)
        .all()
    )

    total = len(attempts)
    average = round(
        sum(a.score for a in attempts) / total, 2
    ) if total > 0 else 0

    return render_template(
        "teacher/quiz_analytics.html",
        quiz=quiz,
        attempts=attempts,
        total_attempts=total,
        average_score=average
    )
# ============================================================ #

#Teacher – View All Quiz Results#
# ============================================================ #
@app.route("/teacher/results")
@login_required
@role_required("teacher")
def teacher_results():
    page = request.args.get("page", 1, type=int)

    attempts = (
        QuizAttempt.query
        .filter(QuizAttempt.submitted == True)
        .order_by(QuizAttempt.attempt_id.desc())  # ✅ FIX HERE
        .paginate(page=page, per_page=10)
    )

    return render_template(
        "teacher/results.html",
        attempts=attempts
    )


# ============================================================
# TEACHER — MANAGE STUDENTS
# ============================================================
@app.route("/teacher/manage-students")
@login_required
@role_required("teacher")
def teacher_manage_students():
    students = (
        User.query
        .join(UserRole)
        .join(Role)
        .filter(Role.name == "student")
        .order_by(User.username)
        .all()
    )

    return render_template(
        "teacher/manage_students.html",
        students=students
    )



@app.route("/teacher/student/toggle/<int:student_id>", methods=["POST"])
@login_required
@role_required("teacher")
def toggle_student(student_id):
    student = User.query.get_or_404(student_id)

    # Safety check: only students can be blocked
    if not any(r.name == "student" for r in student.roles):
        abort(403)

    student.is_active = not student.is_active
    db.session.commit()

    return redirect(url_for("teacher_manage_students"))

# ============================================================ #
#    Teacher – View Detailed Result of a Student    #
# ============================================================
@app.route("/teacher/results/<int:attempt_id>")
@login_required
@role_required("teacher")
def teacher_result_detail(attempt_id):
    attempt = QuizAttempt.query.get_or_404(attempt_id)

    answers = (
        UserAnswer.query
        .join(Question, Question.question_id == UserAnswer.question_id)
        .filter(UserAnswer.attempt_id == attempt_id)
        .all()
    )

    return render_template(
        "teacher/result_detail.html",
        attempt=attempt,
        answers=answers
    )
# ============================================================
# TEACHER -- NOTES
# ============================================================
@app.route("/teacher/notes", methods=["GET", "POST"])
@login_required
@role_required("teacher")
def teacher_notes():
    subjects = Subject.query.all()
    chapters = Chapter.query.all()

    if request.method == "POST":
        title = request.form.get("title")
        subject_id = request.form.get("subject_id")
        chapter_id = request.form.get("chapter_id")
        file = request.files.get("file")

        if not file or file.filename == "":
            flash("No file selected", "error")
            return redirect(url_for("teacher_notes"))

        if not allowed_file(file.filename):
            flash("Invalid file type", "error")
            return redirect(url_for("teacher_notes"))

        filename = secure_filename(file.filename)
        save_path = os.path.join(app.config["UPLOAD_NOTES_FOLDER"], filename)
        file.save(save_path)

        note = Note(
            title=title,
            file_path=filename,
            subject_id=subject_id,
            chapter_id=chapter_id
        )

        db.session.add(note)
        db.session.commit()

        flash("Notes uploaded successfully", "success")
        return redirect(url_for("teacher_notes"))

    notes = Note.query.order_by(Note.uploaded_at.desc()).all()

    return render_template(
        "teacher/notes.html",
        subjects=subjects,
        chapters=chapters,
        notes=notes
    )
@app.route("/teacher/notes/delete/<int:note_id>", methods=["POST"])
@login_required
@role_required("teacher")
def delete_note(note_id):
    note = Note.query.get_or_404(note_id)

    file_path = os.path.join(app.config["UPLOAD_NOTES_FOLDER"], note.file_path)
    if os.path.exists(file_path):
        os.remove(file_path)

    db.session.delete(note)
    db.session.commit()

    flash("Note deleted", "success")
    return redirect(url_for("teacher_notes"))


@app.route("/uploads/notes/<filename>")
@login_required
def serve_note_file(filename):
    return send_from_directory(
        app.config["UPLOAD_NOTES_FOLDER"],
        filename,
        as_attachment=False
    )

# ============================================================
# TEACHER SUMMARY
# ============================================================
@app.route("/teacher/summary")
@login_required
@role_required("teacher")
def teacher_summary():
    quizzes = Quiz.query.all()

    labels = []
    attempts_data = []
    avg_scores = []

    pass_count = 0
    fail_count = 0

    for q in quizzes:
        # ✅ Safe quiz label
        quiz_label = (
            getattr(q, "quiz_name", None)
            or getattr(q, "name", None)
            or f"Quiz {q.quiz_id}"
        )
        labels.append(quiz_label)

        # Get total questions for this quiz
        total_questions = Question.query.filter_by(
            quiz_id=q.quiz_id
        ).count()

        attempts = QuizAttempt.query.filter_by(
            quiz_id=q.quiz_id,
            submitted=True
        ).all()

        attempts_data.append(len(attempts))

        # Average score
        if attempts:
            avg = round(sum(a.score for a in attempts) / len(attempts), 2)
        else:
            avg = 0
        avg_scores.append(avg)

        # Pass / Fail calculation (40% rule)
        for a in attempts:
            if total_questions > 0:
                percent = (a.score / total_questions) * 100
            else:
                percent = 0

            if percent >= 40:
                pass_count += 1
            else:
                fail_count += 1

    analytics = {
        "labels": labels,
        "attempts": attempts_data,
        "averages": avg_scores,
        "pass": pass_count,
        "fail": fail_count
    }

    return render_template(
        "teacher/summary.html",
        analytics=analytics
    )



# ============================================================
# USER sUMMARY
# ============================================================
@app.route("/user/summary")
@login_required
@role_required("user")
def user_summary():
    return render_template("user/summary.html")


# ============================================================
# USER PROFILE
# ============================================================
@app.route("/user/profile")
@login_required 
@role_required("user")
def user_profile():
    return render_template(
        "user/profile.html",
        user=User.query.get(session["user_id"])
    )


@app.route("/user/profile/upload", methods=["POST"])
@login_required
@role_required("user")
def upload_profile_image():
    file = request.files.get("profile_image")
    if not file or not allowed_file(file.filename):
        return redirect(url_for("user_profile"))

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    filename = secure_filename(file.filename)
    path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(path)

    user = User.query.get(session["user_id"])
    user.profile_image = "/" + path
    db.session.commit()
    return redirect(url_for("user_profile"))



@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory("uploads", filename)
# ============================================================
# GENERATE QUESTIONS --AI
# ============================================================
# ============================================================
# TEACHER — AI GENERATE QUESTIONS
# ============================================================
@app.route("/teacher/ai/generate-questions", methods=["POST"])
@login_required
@role_required("teacher")
def ai_generate_questions():

    data = request.json
    subject = Subject.query.get_or_404(data["subject_id"])
    chapter = Chapter.query.get_or_404(data["chapter_id"])
    difficulty = data.get("difficulty", "medium")

    # 🔍 Try to get notes PDF for this chapter
    note = Note.query.filter_by(chapter_id=chapter.chapter_id)\
                     .order_by(Note.uploaded_at.desc())\
                     .first()

    if note:
        notes_text = extract_pdf_text(note.file_path)

        prompt = f"""
You are a professional exam question setter.

You MUST generate questions ONLY from the NOTES CONTENT below.
If the answer is not present in the notes, DO NOT invent it.

Generate exactly 5 MCQs in this STRICT format:

Q1|Question text
A|Option 1
B|Option 2
C|Option 3
D|Option 4
ANS|B

RULES:
- Use ONLY the notes content
- Exam oriented
- One correct answer
- Difficulty: {difficulty}

NOTES CONTENT START
{notes_text}
NOTES CONTENT END
"""
    else:
        # 🔁 fallback (original behavior)
        prompt = f"""
You are a professional exam question setter.

Generate exactly 5 MCQs in this STRICT format:

Q1|Question text
A|Option 1
B|Option 2
C|Option 3
D|Option 4
ANS|B

Rules:
- Exam oriented
- One correct answer
- Difficulty: {difficulty}

Subject: {subject.name}
Chapter: {chapter.name}
"""

    output = generate_mcq_questions(prompt)
    return {"content": output}



# ============================================================
# TEACHER — AI SAVE QUESTIONS
# ============================================================
@app.route("/teacher/ai/save", methods=["POST"])
@login_required
@role_required("teacher")
def save_ai_questions():

    data = request.json
    quiz_id = data["quiz_id"]
    ai_text = data["content"]

    parsed = parse_ai_questions(ai_text)
    saved = 0

    for q in parsed:
        if is_duplicate(quiz_id, q["statement"]):
            continue

        db.session.add(Question(
            quiz_id=quiz_id,
            title="AI Question",
            statement=q["statement"],
            option_1=q["option_1"],
            option_2=q["option_2"],
            option_3=q["option_3"],
            option_4=q["option_4"],
            correct_option=q["correct_option"]
        ))
        saved += 1

    db.session.commit()
    return {"saved": saved}



# ================= AI HELPERS =================

def parse_ai_questions(text):
    questions = []
    blocks = text.strip().split("\n\n")

    for block in blocks:
        lines = block.splitlines()
        if len(lines) < 6:
            continue
        try:
            questions.append({
                "statement": lines[0].split("|",1)[1],
                "option_1": lines[1].split("|",1)[1],
                "option_2": lines[2].split("|",1)[1],
                "option_3": lines[3].split("|",1)[1],
                "option_4": lines[4].split("|",1)[1],
                "correct_option": ["A","B","C","D"].index(
                    lines[5].split("|",1)[1]
                ) + 1
            })
        except:
            continue
    return questions


def is_duplicate(quiz_id, statement):
    return Question.query.filter(
        Question.quiz_id == quiz_id,
        Question.statement.ilike(statement[:80] + "%")
    ).first() is not None

def extract_pdf_text(file_path, limit=12000):
    """
    file_path can be:
    - OOP.pdf
    - notes/OOP.pdf
    - full absolute path
    """

    # normalize slashes (Windows safety)
    file_path = file_path.replace("\\", "/")

    # if absolute path, use as-is
    if os.path.isabs(file_path):
        path = file_path
    else:
        # always resolve from UPLOAD_NOTES_FOLDER
        filename = os.path.basename(file_path)
        path = os.path.join(app.config["UPLOAD_NOTES_FOLDER"], filename)

    if not os.path.exists(path):
        raise FileNotFoundError(f"Notes file not found at: {path}")

    doc = fitz.open(path)
    text = "\n".join(page.get_text() for page in doc)
    return text[:limit]

# ============================================================
# LOGOUT
# ============================================================
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ============================================================
# RUN
# ============================================================
if __name__ == "__main__":
    app.run(debug=True)