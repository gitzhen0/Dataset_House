from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

from flask_login import UserMixin

# 初始化 SQLAlchemy，稍后在 app.py 中绑定
db = SQLAlchemy()

# 1. USERS Table
# 对应 ERD 中的 USERS [cite: 9]
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)  # PK_user_id
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship: User owns Datasets [cite: 11]
    datasets = db.relationship('Dataset', backref='owner', lazy=True)
    
    # Relationship: User executes QueryLogs [cite: 32]
    queries = db.relationship('QueryLog', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.email}>'

# models.py (只修改 Dataset 类，其他不变)

class Dataset(db.Model):
    __tablename__ = 'datasets'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    table_name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    tags = db.Column(db.String(200))
    rows = db.Column(db.Integer, default=0)
    columns = db.Column(db.Integer, default=0)
    
    # --- 新增这一行 ---
    types = db.Column(db.String(200), default="unknown") 
    # ----------------
    
    visibility = db.Column(db.String(20), default='public')
    file_path = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    logs = db.relationship('QueryLog', backref='dataset', lazy=True, cascade="all, delete-orphan")

    
# 3. QUERYLOGS Table
# 对应 ERD 中的 QUERYLOGS [cite: 34]
class QueryLog(db.Model):
    __tablename__ = 'querylogs'
    
    id = db.Column(db.Integer, primary_key=True) # PK_query_id
    sql_text = db.Column(db.Text, nullable=False)
    result_count = db.Column(db.Integer, default=0)
    executed_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # FK_dataset_id [cite: 39]
    dataset_id = db.Column(db.Integer, db.ForeignKey('datasets.id'), nullable=False)
    
    # FK_user_id [cite: 40]
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)