"""
Minimal test to verify Vercel + Neon database connection works
Visit /test after deploying to verify everything is working
"""
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'test'

# Database Configuration
db_url = os.environ.get('DATABASE_URL') or os.environ.get('POSTGRES_URL')
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql+pg8000://", 1)
elif db_url and db_url.startswith("postgresql://"):
    db_url = db_url.replace("postgresql://", "postgresql+pg8000://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url or 'sqlite:///:memory:'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class TestUser(db.Model):
    __tablename__ = 'test_users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))

@app.route('/test')
def test():
    try:
        # Try to create table
        db.create_all()
        
        # Try to insert a record
        test_user = TestUser(name='TestUser123')
        db.session.add(test_user)
        db.session.commit()
        
        # Try to query
        users = TestUser.query.all()
        
        return f"SUCCESS! Database working. Found {len(users)} users. DB URL: {app.config['SQLALCHEMY_DATABASE_URI'][:50]}..."
    except Exception as e:
        return f"ERROR: {str(e)}", 500

if __name__ == '__main__':
    app.run(debug=True)
