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
from xhtml2pdf import pisa
from scanner_core import SecurityScanner
from models import db, User, ScanResult

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

scanner = SecurityScanner()

# In-memory storage for scan jobs
scan_jobs = {}

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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

def generate_pdf_html(target, risk_score, ip_address, vulnerabilities):
    vulns = vulnerabilities
    if isinstance(vulns, str):
        try:
            vulns = json.loads(vulns)
        except:
            vulns = []
            
    # Create HTML content
    html_content = f"""
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: Helvetica, sans-serif; color: #333; }}
            .header {{ text-align: center; margin-bottom: 30px; border-bottom: 2px solid #00ff6a; padding-bottom: 10px; }}
            h1 {{ color: #1a1a1a; }}
            .info-box {{ background: #f5f5f5; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background-color: #f8f9fa; font-weight: bold; }}
            .severity-Critical {{ color: #ffffff; background-color: #ff3333; padding: 3px 8px; border-radius: 3px; font-weight: bold; }}
            .severity-High {{ color: #ffffff; background-color: #ff6b6b; padding: 3px 8px; border-radius: 3px; font-weight: bold; }}
            .severity-Medium {{ color: #ffffff; background-color: #ffa500; padding: 3px 8px; border-radius: 3px; font-weight: bold; }}
            .severity-Low {{ color: #ffffff; background-color: #20c997; padding: 3px 8px; border-radius: 3px; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Web Security Scanner Report</h1>
            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="info-box">
            <p><strong>Target:</strong> {target}</p>
            <p><strong>Risk Score:</strong> {risk_score}/10</p>
            <p><strong>IP Address:</strong> {ip_address}</p>
        </div>
        
        <h2>Vulnerabilities Detected</h2>
    """
    
    if not vulns:
        html_content += "<p>No significant vulnerabilities detected.</p>"
    else:
        html_content += """
        <table>
            <thead>
                <tr>
                    <th style="width: 15%">Severity</th>
                    <th style="width: 30%">Vulnerability</th>
                    <th style="width: 55%">Description</th>
                </tr>
            </thead>
            <tbody>
        """
        for v in vulns:
            severity = v.get('severity', 'Low')
            html_content += f"""
            <tr>
                <td><span class="severity-{severity}">{severity}</span></td>
                <td>{v.get('name', 'Unknown')}</td>
                <td>{v.get('description', '')}</td>
            </tr>
            """
        html_content += """
            </tbody>
        </table>
        """
        
    html_content += """
    <div style="margin-top: 50px; font-size: 0.8rem; text-align: center; color: #777;">
        <p>This report is generated by Web Security Scanner 2.0. Not for malicious use.</p>
    </div>
    </body>
    </html>
    """
    return html_content

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
    
    html_content = generate_pdf_html(
        scan.target, 
        scan.risk_score, 
        scan.ip_address, 
        scan.vulnerabilities
    )

    pdf_output = io.BytesIO()
    pisa_status = pisa.CreatePDF(html_content, dest=pdf_output)
    
    if pisa_status.err:
        return f"PDF generation error: {pisa_status.err}", 500
        
    pdf_output.seek(0)
    return send_file(
        pdf_output,
        as_attachment=True,
        download_name=f"web_scan_report_{scan.id}.pdf",
        mimetype='application/pdf'
    )

@app.route('/export_pdf', methods=['POST'])
@login_required
def export_pdf():
    # Expecting JSON data with results
    data = request.json
    
    if not data:
        return "No scan available to export", 400
        
    html_content = generate_pdf_html(
        data.get('target', 'N/A'), 
        data.get('risk_score', 0), 
        data.get('ip', 'N/A'), 
        data.get('vulnerabilities', [])
    )

    pdf_output = io.BytesIO()
    pisa_status = pisa.CreatePDF(html_content, dest=pdf_output)
    
    if pisa_status.err:
        return f"PDF generation error: {pisa_status.err}", 500
        
    pdf_output.seek(0)
    return send_file(
        pdf_output,
        as_attachment=True,
        download_name=f"web_scan_report_{datetime.now().strftime('%Y%m%d')}.pdf",
        mimetype='application/pdf'
    )

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)
