import os
class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "a_secure_fallback_key")
    # Reads a cloud PostgreSQL database URL if present, otherwise falls back to a temporary memory SQLite database
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:////tmp/quiz_master.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
