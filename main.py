import os
from functools import wraps
from datetime import datetime
from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash, abort, send_from_directory
)
from flask_login import LoginManager, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

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

# Use Vercel's temporary directory write path for profiles
UPLOAD_FOLDER = "/tmp/uploads/profile_images"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

try:
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
except Exception as e:
    print(f"Database initialization bypassed or unavailable: {e}")

# Use Vercel's temporary directory write path for notes
UPLOAD_NOTES_FOLDER = "/tmp/uploads/notes"
os.makedirs(UPLOAD_NOTES_FOLDER, exist_ok=True)
ALLOWED_NOTES_EXTENSIONS = {"pdf", "doc", "docx"}
app.config["UPLOAD_NOTES_FOLDER"] = UPLOAD_NOTES_FOLDER

# ============================================================
# HELPERS & DECORATORS
# ============================================================
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def allowed_notes_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_NOTES_EXTENSIONS

def get_user_role(user_id):
    role = (
        db.session.query(Role.name)
        .join(UserRole, Role.role_id == UserRole.role_id)
        .filter(UserRole.user_id == user_id)
        .first()
    )
    return role[0] if role else None

def has_attempted(user_id, quiz_id):
    return QuizAttempt.query.filter_by(
        user_id=user_id,
        quiz_id=quiz_id,
        submitted=True
    ).first() is not None

# Custom decorator wrapper renaming to avoid collision with flask_login framework
def custom_login_required(f):
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
# DASHBOARDS (Cleaned & Completed Templates)
# ============================================================
@app.route("/admin/dashboard")
@custom_login_required
@role_required("admin")
def admin_dashboard():
    return render_template("admin_dashboard.html")

@app.route("/teacher/dashboard")
@custom_login_required
@role_required("teacher")
def teacher_dashboard():
    return render_template("teacher_dashboard.html")

@app.route("/user/dashboard")
@custom_login_required
def user_dashboard():
    return render_template("user_dashboard.html")

# ============================================================
# FALLBACK RUN TARGETS
# ============================================================
if __name__ == "__main__":
    app.run(debug=True)
