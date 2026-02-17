let currentJobId = null;
let pollInterval = null;
let currentScanData = null; // Store for PDF generation

async function startScan() {
    const target = document.getElementById('target').value;
    if (!target) {
        alert("Please enter a target URL");
        return;
    }

    // Reset UI
    document.getElementById('results-area').style.display = 'none';
    document.getElementById('progress-container').style.display = 'block';
    document.getElementById('progress-fill').style.width = '0%';
    document.getElementById('status-text').innerText = 'Initializing...';

    try {
        const response = await fetch('/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target: target })
        });

        const data = await response.json();

        if (data.error) {
            alert(data.error);
            return;
        }

        currentJobId = data.job_id;
        pollInterval = setInterval(checkStatus, 1000);

    } catch (e) {
        console.error(e);
        alert("Failed to start scan");
    }
}

async function checkStatus() {
    if (!currentJobId) return;

    try {
        const response = await fetch(`/scan_status/${currentJobId}`);
        const data = await response.json();

        // Update Progress
        document.getElementById('progress-fill').style.width = `${data.progress}%`;
        document.getElementById('status-text').innerText = data.message;

        if (data.status === 'completed') {
            clearInterval(pollInterval);
            displayResults(data.result);
        } else if (data.status === 'failed') {
            clearInterval(pollInterval);
            alert(`Scan Failed: ${data.error}`);
            document.getElementById('status-text').innerText = 'Failed.';
        }

    } catch (e) {
        console.error(e);
    }
}

function displayResults(data) {
    currentScanData = data;
    const resultsArea = document.getElementById('results-area');
    const vulnList = document.getElementById('vuln-list');

    // Summary
    document.getElementById('risk-score').innerText = `${data.risk_score}/10`;
    document.getElementById('target-ip').innerText = data.ip;
    document.getElementById('vuln-count').innerText = data.vulnerabilities.length;

    // Risk Color
    const riskEl = document.getElementById('risk-score');
    if (data.risk_score > 7) riskEl.style.color = '#ff3333'; // Critical
    else if (data.risk_score > 4) riskEl.style.color = '#ffa500'; // Med
    else riskEl.style.color = '#00ff6a'; // Low

    // Vuln List
    vulnList.innerHTML = '';
    if (data.vulnerabilities.length === 0) {
        vulnList.innerHTML = '<p class="glass-panel" style="padding: 20px; text-align: center;">No vulnerabilities found. Good job!</p>';
    } else {
        data.vulnerabilities.forEach(v => {
            const card = document.createElement('div');
            card.className = 'glass-panel';
            card.style.padding = '20px';
            card.style.marginBottom = '15px';
            card.style.borderLeft = `4px solid ${getSeverityColor(v.severity)}`;
            card.style.background = 'rgba(255,255,255,0.02)';

            card.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                    <h4 style="margin: 0; color: #fff;">${v.name}</h4>
                    <span style="background: ${getSeverityColor(v.severity)}20; color: ${getSeverityColor(v.severity)}; padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: bold;">
                        ${v.severity}
                    </span>
                </div>
                <p style="margin: 0; color: var(--text-muted); font-size: 0.9rem;">${v.description}</p>
            `;
            vulnList.appendChild(card);
        });
    }

    resultsArea.style.display = 'block';

    // Scroll to results
    resultsArea.scrollIntoView({ behavior: 'smooth' });
}

function getSeverityColor(severity) {
    switch (severity) {
        case 'Critical': return '#ff3333';
        case 'High': return '#ff6b6b';
        case 'Medium': return '#ffa500';
        case 'Low': return '#20c997';
        default: return '#ccc';
    }
}

async function downloadReport() {
    if (!currentScanData) return;

    try {
        const response = await fetch('/export_pdf', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(currentScanData)
        });

        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `web_scan_report_${Date.now()}.pdf`;
            document.body.appendChild(a);
            a.click();
            a.remove();
        } else {
            alert("Failed to generate PDF");
        }
    } catch (e) {
        console.error(e);
        alert("Error downloading report");
    }
}
