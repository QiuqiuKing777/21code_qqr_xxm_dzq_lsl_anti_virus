import os


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key'
    # 连接串
    SQLALCHEMY_DATABASE_URI = 
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PORT = 3000
