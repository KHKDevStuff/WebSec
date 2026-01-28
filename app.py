from flask import Flask, render_template, request, jsonify, send_file
from scanner_core import SecurityScanner
from fpdf import FPDF
import os
import datetime

app = Flask(__name__)
scanner = SecurityScanner()

last_scan_result = {}

class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'WebScrub Security Report', 0, 1, 'C')
        self.ln(10)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    global last_scan_result
    target = request.json.get('target')
    if not target:
        return jsonify({"error": "No target provided"}), 400
    
    try:
        results = scanner.perform_full_scan(target)
        last_scan_result = results
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/export_pdf', methods=['GET', 'POST'])
def export_pdf():
    global last_scan_result
    
    # If POST, data comes from the request body (e.g., from History)
    if request.method == 'POST':
        data = request.json
    else:
        # If GET, use the last successful scan
        data = last_scan_result

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
    for v in data.get('vulnerabilities', []):
        pdf.set_text_color(200, 0, 0)
        pdf.cell(200, 10, txt=f"[{v.get('severity')}] {v.get('name')}", ln=1)
        pdf.set_text_color(0, 0, 0)
        pdf.multi_cell(0, 5, txt=v.get('description', ''))
        pdf.ln(2)

    filename = "webscrub_report.pdf"
    full_path = os.path.join(os.getcwd(), filename)
    pdf.output(full_path)
    return send_file(full_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
