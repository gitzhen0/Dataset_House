from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

from flask_login import UserMixin


db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)  # PK_user_id
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


    datasets = db.relationship('Dataset', backref='owner', lazy=True)
    

    queries = db.relationship('QueryLog', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.email}>'



class Dataset(db.Model):
    __tablename__ = 'datasets'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    table_name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    tags = db.Column(db.String(200))
    rows = db.Column(db.Integer, default=0)
    columns = db.Column(db.Integer, default=0)
    

    types = db.Column(db.String(200), default="unknown") 

    
    visibility = db.Column(db.String(20), default='public')
    file_path = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    logs = db.relationship('QueryLog', backref='dataset', lazy=True, cascade="all, delete-orphan")



class QueryLog(db.Model):
    __tablename__ = 'querylogs'
    
    id = db.Column(db.Integer, primary_key=True) # PK_query_id
    sql_text = db.Column(db.Text, nullable=False)
    result_count = db.Column(db.Integer, default=0)
    executed_at = db.Column(db.DateTime, default=datetime.utcnow)
    

    dataset_id = db.Column(db.Integer, db.ForeignKey('datasets.id'), nullable=False)
    

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)