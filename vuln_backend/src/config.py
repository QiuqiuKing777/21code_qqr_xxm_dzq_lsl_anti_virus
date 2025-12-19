import os


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key'
     # 连接串 下面这一行要根据您的mysql密码来填写：SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:您的数据库密码@localhost:3306/nvd_database'
    SQLALCHEMY_DATABASE_URI = 
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PORT = 3000
