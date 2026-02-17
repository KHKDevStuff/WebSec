from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
import json
import io
import threading
import uuid

from scanner_core import SecurityScanner
from models import db, User, ScanResult

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key')

# Database Configuration for Vercel (Neon Postgres)
db_url = os.environ.get('DATABASE_URL') or os.environ.get('POSTGRES_URL')

if db_url:
    # Remove sslmode parameter if present (pg8000 doesn't support it in the URL)
    if '?sslmode=' in db_url:
        db_url = db_url.split('?sslmode=')[0]
    
    # Convert postgres:// to postgresql+pg8000://
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql+pg8000://", 1)
    elif db_url.startswith("postgresql://"):
        db_url = db_url.replace("postgresql://", "postgresql+pg8000://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url or 'sqlite:///:memory:'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

scanner = SecurityScanner()

# In-memory storage for scan jobs
scan_jobs = {}

# Initialize database tables - MUST be after all imports and app setup
def init_db():
    with app.app_context():
        try:
            # Import all models to ensure they're registered
            from models import User, ScanResult
            
            # Check if the user table exists but has wrong schema
            # db.create_all() won't fix existing tables with missing columns
            try:
                from sqlalchemy import text
                result = db.session.execute(text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_name = 'user' AND column_name = 'password_hash'"
                ))
                columns = result.fetchall()
                if not columns:
                    # Table exists but missing password_hash column - need to rebuild
                    print("⚠ Schema mismatch detected - rebuilding tables...")
                    db.drop_all()
                    db.create_all()
                    print("✓ Database tables rebuilt successfully")
                else:
                    db.create_all()
                    print("✓ Database tables verified successfully")
            except Exception:
                # Table might not exist yet, or using SQLite - just create all
                db.create_all()
                print("✓ Database tables created successfully")
                
        except Exception as e:
            print(f"✗ Database initialization error: {e}")

# Call initialization immediately
init_db()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/setup_db')
def setup_db():
    """Manual database setup endpoint - visit this once after deployment"""
    try:
        db.create_all()
        return "Database tables created successfully!", 200
    except Exception as e:
        return f"Error creating tables: {str(e)}", 500

@app.route('/reset_db')
def reset_db():
    """Drop and recreate all tables - fixes schema mismatches. WARNING: deletes all data!"""
    try:
        db.drop_all()
        db.create_all()
        return "Database tables dropped and recreated successfully! All data has been cleared.", 200
    except Exception as e:
        return f"Error resetting tables: {str(e)}", 500

@app.route('/')
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role', 'user')
        secret_code = request.form.get('admin_secret', '')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
            
        if role == 'admin':
            # In production, use environment variable
            admin_code = os.environ.get('ADMIN_SECRET', 'kuttykunji')
            if secret_code != admin_code:
                flash('Invalid Admin Secret Code', 'error')
                return redirect(url_for('register'))

        user = User(username=username, role=role)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful!', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/scan', methods=['POST'])
@login_required
def scan():
    data = request.json
    target = data.get('target')
    if not target:
        return jsonify({"error": "No target provided"}), 400
    
    # Generate unique Job ID
    job_id = str(uuid.uuid4())
    scan_jobs[job_id] = {
        "status": "running",
        "progress": 0,
        "message": "Initializing...",
        "result": None
    }
    
    # Define worker function
    def run_scan(target, job_id, user_id):
        def update_progress(p, msg):
            scan_jobs[job_id]["progress"] = p
            scan_jobs[job_id]["message"] = msg
            
        try:
            results = scanner.perform_full_scan(target, max_pages=3, status_callback=update_progress)
            
            # Save to DB (using user_id from closure if needed, but we used current_user in main thread)
            # We need app context for DB operations in thread
            with app.app_context():
                scan_entry = ScanResult(
                    target=results['target'],
                    domain=results['domain'],
                    ip_address=results['ip'],
                    risk_score=results['risk_score'],
                    vulnerabilities=json.dumps(results['vulnerabilities']),
                    user_id=user_id
                )
                db.session.add(scan_entry)
                db.session.commit()
                results['scan_id'] = scan_entry.id
            
            scan_jobs[job_id]["result"] = results
            scan_jobs[job_id]["status"] = "completed"
            scan_jobs[job_id]["progress"] = 100
            scan_jobs[job_id]["message"] = "Scan Complete"
            
        except Exception as e:
            scan_jobs[job_id]["status"] = "failed"
            scan_jobs[job_id]["error"] = str(e)

    # Start the thread
    thread = threading.Thread(target=run_scan, args=(target, job_id, current_user.id))
    thread.start()
    
    return jsonify({"job_id": job_id})

@app.route('/scan_status/<job_id>', methods=['GET'])
@login_required
def scan_status(job_id):
    job = scan_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job)

@app.route('/history')
@login_required
def history():
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    # Admin sees all scans
    user_scans = ScanResult.query.order_by(ScanResult.timestamp.desc()).all()
    return render_template('history.html', scans=user_scans)

from fpdf import FPDF

class PDF(FPDF):
    def header(self):
        self.set_font('Helvetica', 'B', 20)
        self.cell(0, 10, 'Web Security Scanner Report', align='C')
        self.ln(10)
        self.set_font('Helvetica', '', 10)
        self.cell(0, 10, f'Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', align='C')
        self.ln(20)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}}', align='C')

def generate_pdf(target, risk_score, ip_address, vulnerabilities):
    pdf = PDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    
    # Target Info
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 10, f'Target: {target}', ln=True)
    pdf.cell(0, 10, f'Risk Score: {risk_score}/10', ln=True)
    pdf.cell(0, 10, f'IP Address: {ip_address}', ln=True)
    pdf.ln(10)
    
    # Vulnerabilities
    pdf.set_font('Helvetica', 'B', 14)
    pdf.cell(0, 10, 'Vulnerabilities Detected', ln=True)
    pdf.ln(5)
    
    vulns = vulnerabilities
    if isinstance(vulns, str):
        try:
            vulns = json.loads(vulns)
        except:
            vulns = []

    if not vulns:
        pdf.set_font('Helvetica', '', 12)
        pdf.cell(0, 10, 'No significant vulnerabilities detected.', ln=True)
    else:
        for v in vulns:
            severity = v.get('severity', 'Low')
            # Color code severity
            if severity == 'Critical': pdf.set_text_color(255, 51, 51)
            elif severity == 'High': pdf.set_text_color(255, 107, 107)
            elif severity == 'Medium': pdf.set_text_color(255, 165, 0)
            else: pdf.set_text_color(32, 201, 151)
            
            pdf.set_font('Helvetica', 'B', 12)
            pdf.cell(0, 8, f"[{severity}] {v.get('name', 'Unknown')}", ln=True)
            
            pdf.set_text_color(0, 0, 0)
            pdf.set_font('Helvetica', '', 11)
            pdf.multi_cell(0, 6, v.get('description', ''))
            pdf.ln(5)

    return pdf.output(dest='S') # Return as byte string

@app.route('/scan_details/<int:scan_id>')
@login_required
def scan_details(scan_id):
    if current_user.role != 'admin':
        return jsonify({"error": "Admin access required"}), 403
        
    scan = ScanResult.query.get_or_404(scan_id)
    return jsonify({
        "id": scan.id,
        "target": scan.target,
        "risk_score": scan.risk_score,
        "ip_address": scan.ip_address,
        "timestamp": scan.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        "vulnerabilities": scan.vulnerabilities,
        "username": scan.user.username
    })

@app.route('/delete_scan/<int:scan_id>', methods=['POST'])
@login_required
def delete_scan(scan_id):
    if current_user.role != 'admin':
        return jsonify({"error": "Admin access required"}), 403
        
    scan = ScanResult.query.get_or_404(scan_id)
    try:
        db.session.delete(scan)
        db.session.commit()
        return jsonify({"message": "Scan deleted successfully"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/download_scan_pdf/<int:scan_id>')
@login_required
def download_scan_pdf(scan_id):
    if current_user.role != 'admin':
        return "Admin access required", 403
        
    scan = ScanResult.query.get_or_404(scan_id)
    
    pdf_bytes = generate_pdf(
        scan.target, 
        scan.risk_score, 
        scan.ip_address, 
        scan.vulnerabilities
    )

    return send_file(
        io.BytesIO(pdf_bytes),
        as_attachment=True,
        download_name=f"web_scan_report_{scan.id}.pdf",
        mimetype='application/pdf'
    )

@app.route('/export_pdf', methods=['POST'])
@login_required
def export_pdf():
    data = request.json
    if not data:
        return "No scan available to export", 400
        
    pdf_bytes = generate_pdf(
        data.get('target', 'N/A'), 
        data.get('risk_score', 0), 
        data.get('ip', 'N/A'), 
        data.get('vulnerabilities', [])
    )

    return send_file(
        io.BytesIO(pdf_bytes),
        as_attachment=True,
        download_name=f"web_scan_report_{datetime.now().strftime('%Y%m%d')}.pdf",
        mimetype='application/pdf'
    )

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)
