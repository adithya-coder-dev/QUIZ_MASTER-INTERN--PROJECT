import os

class Config:
    SECRET_KEY = '@12345abc'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(
        os.getcwd(), 'instance', 'quiz.db'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
