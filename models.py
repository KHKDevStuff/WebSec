from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), default='user')
    scans = db.relationship('ScanResult', backref='user', lazy=True)

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(500), nullable=False)
    domain = db.Column(db.String(500))
    ip_address = db.Column(db.String(50))
    risk_score = db.Column(db.Float, default=0.0)
    vulnerabilities = db.Column(db.Text)  # Storing JSON string or summary
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
