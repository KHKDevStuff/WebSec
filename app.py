from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash
from scanner_core import SecurityScanner
from models import db, User, ScanResult
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from fpdf import FPDF
import os
import datetime
import io
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'supersecretkey_change_in_production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

scanner = SecurityScanner()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
            
        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful!', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/history')
@login_required
def history():
    user_scans = ScanResult.query.filter_by(user_id=current_user.id).order_by(ScanResult.timestamp.desc()).all()
    return render_template('history.html', scans=user_scans)

@app.route('/scan', methods=['POST'])
@login_required
def scan():
    data = request.json
    target = data.get('target')
    if not target:
        return jsonify({"error": "No target provided"}), 400
    
    try:
        # Perform scan (now supports crawling if we passed max_pages, default is 1)
        # Using max_pages=1 to keep it fast for default, could be configurable
        results = scanner.perform_full_scan(target, max_pages=3) 
        
        # Save to DB
        scan_entry = ScanResult(
            target=results['target'],
            domain=results['domain'],
            ip_address=results['ip'],
            risk_score=results['risk_score'],
            vulnerabilities=json.dumps(results['vulnerabilities']),
            user_id=current_user.id
        )
        db.session.add(scan_entry)
        db.session.commit()
        
        # Return ID so frontend can request PDF for this specific scan if needed, 
        # or just return results as before
        results['scan_id'] = scan_entry.id
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'WebScrub Security Report', 0, 1, 'C')
        self.ln(10)

@app.route('/export_pdf', methods=['POST'])
@login_required
def export_pdf():
    # Expecting JSON data with results, matching original frontend behavior
    data = request.json
    
    if not data:
        return "No scan available to export", 400
    
    pdf = PDFReport()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    
    pdf.cell(200, 10, txt=f"Target: {data.get('target', 'N/A')}", ln=1)
    pdf.cell(200, 10, txt=f"Risk Score: {data.get('risk_score', 0)}/10", ln=1)
    pdf.cell(200, 10, txt=f"IP Address: {data.get('ip', 'N/A')}", ln=1)
    pdf.ln(10)

    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="Vulnerabilities:", ln=1)
    pdf.set_font("Arial", size=10)
    
    vulns = data.get('vulnerabilities', [])
    if isinstance(vulns, str):
        try:
            vulns = json.loads(vulns)
        except:
            vulns = []

    for v in vulns:
        pdf.set_text_color(200, 0, 0)
        pdf.cell(200, 10, txt=f"[{v.get('severity')}] {v.get('name')}", ln=1)
        pdf.set_text_color(0, 0, 0)
        pdf.multi_cell(0, 5, txt=v.get('description', ''))
        pdf.ln(2)

    pdf_output = pdf.output(dest='S').encode('latin-1')
    return send_file(
        io.BytesIO(pdf_output),
        as_attachment=True,
        download_name="webscrub_report.pdf",
        mimetype='application/pdf'
    )

if __name__ == '__main__':
    app.run(debug=True, port=5000)
