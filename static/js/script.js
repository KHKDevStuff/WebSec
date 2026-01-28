let scanHistory = [];

function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('open');
}

function showSection(sectionId) {
    // Hide all sections
    document.querySelectorAll('.content-section').forEach(el => el.classList.add('hidden'));

    // Update Nav Active State
    document.querySelectorAll('.nav-links li').forEach(el => el.classList.remove('active'));

    const navItems = {
        'new-scan': 'nav-dashboard',
        'reports': 'nav-reports',
        'settings': 'nav-settings'
    };

    if (sectionId in navItems) {
        if (sectionId === 'new-scan') {
            document.getElementById('scan-view').classList.remove('hidden');
        } else {
            document.getElementById(sectionId + '-view').classList.remove('hidden');
        }
        document.getElementById(navItems[sectionId]).classList.add('active');

        if (sectionId === 'reports') {
            renderHistory();
        }
    } else {
        // Fallback to dashboard
        document.getElementById('scan-view').classList.remove('hidden');
        document.getElementById('nav-dashboard').classList.add('active');
    }

    // Close sidebar on mobile after selection
    if (window.innerWidth <= 992) {
        document.getElementById('sidebar').classList.remove('open');
    }
}

function logToTerminal(message, type = 'info') {
    const term = document.getElementById('terminal-log');
    if (!term) return;
    const p = document.createElement('p');
    p.classList.add('log-entry', `log-${type}`);
    const time = new Date().toLocaleTimeString();
    p.innerText = `[${time}] ${message}`;
    term.appendChild(p);
    term.scrollTop = term.scrollHeight;
}

async function startScan() {
    const urlInput = document.getElementById('target-url');
    const target = urlInput.value.trim();
    if (!target) {
        logToTerminal("Error: No target specified", "error");
        return;
    }

    resetButton(true);
    logToTerminal(`Initiating sequence for: ${target}`, "info");
    logToTerminal("Connecting to module services...", "info");
    logToTerminal("Scanning for headers and SSL status...", "info");

    try {
        const response = await fetch('/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target: target })
        });

        const data = await response.json();
        if (response.status !== 200 || data.error) {
            logToTerminal(`Scan failed: ${data.error}`, "error");
            resetButton(false);
            return;
        }

        logToTerminal("Sequence complete. Analysing gathered intel...", "success");

        // Add to local history
        data.timestamp = new Date().toLocaleString();
        scanHistory.unshift(data);

        displayResults(data);
    } catch (error) {
        logToTerminal(`Network Error: ${error}`, "error");
        resetButton(false);
    }
}

let currentScanData = null;

async function exportPDF(data = null) {
    const scanToExport = data || currentScanData;
    if (!scanToExport) {
        logToTerminal("No report data to export", "error");
        return;
    }

    try {
        const response = await fetch('/export_pdf', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(scanToExport)
        });

        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `webscrub_${scanToExport.target.replace(/[^a-z0-9]/gi, '_')}.pdf`;
            document.body.appendChild(a);
            a.click();
            a.remove();
        } else {
            logToTerminal("Failed to generate PDF", "error");
        }
    } catch (error) {
        logToTerminal("Error exporting PDF: " + error, "error");
    }
}

function displayResults(data) {
    currentScanData = data;
    document.getElementById('scan-view').classList.add('hidden');
    document.getElementById('results-view').classList.remove('hidden');
    resetButton(false);

    document.getElementById('res-target').innerText = data.target;
    document.getElementById('res-score').innerText = data.risk_score;
    document.getElementById('res-ip').innerText = data.ip;

    const vulnList = document.getElementById('vuln-list');
    vulnList.innerHTML = '';
    
    if (data.vulnerabilities.length === 0) {
        vulnList.innerHTML = '<li class="vuln-item" style="border-color: var(--accent);">No core vulnerabilities detected.</li>';
    } else {
        data.vulnerabilities.forEach(v => {
            const li = document.createElement('li');
            li.className = `vuln-item severity-${v.severity}`;
            li.innerHTML = `<strong>[${v.severity}] ${v.name}</strong><br><small>${v.description}</small>`;
            vulnList.appendChild(li);
        });
    }

    document.getElementById('res-scapy').innerText = "SSL/TLS Info:\n" + JSON.stringify(data.ssl_info, null, 2) + 
                                                   "\n\nDNS Records:\n" + JSON.stringify(data.dns_info, null, 2);
    document.getElementById('res-nmap').innerText = "Response Headers:\n" + JSON.stringify(data.raw_headers, null, 2);
}

function renderHistory() {
    const container = document.getElementById('history-list');
    if (!container) return;
    
    if (scanHistory.length === 0) {
        container.innerHTML = '<p class="empty-msg">No previous scan history found.</p>';
        return;
    }

    container.innerHTML = '';
    scanHistory.forEach((scan, index) => {
        const item = document.createElement('div');
        item.className = 'history-item';
        
        const content = document.createElement('div');
        content.style.flex = "1";
        content.onclick = () => viewHistoryItem(index);
        content.innerHTML = `
            <div class="hist-target">${scan.target}</div>
            <small style="color: var(--text-muted)">${scan.timestamp}</small>
        `;

        const meta = document.createElement('div');
        meta.style.display = "flex";
        meta.style.alignItems = "center";
        meta.style.gap = "15px";
        
        const score = document.createElement('div');
        score.className = 'hist-score';
        score.innerText = `${scan.risk_score}/10`;
        
        const downloadBtn = document.createElement('button');
        downloadBtn.className = 'btn-icon';
        downloadBtn.style.background = "none";
        downloadBtn.style.border = "none";
        downloadBtn.style.color = "var(--accent)";
        downloadBtn.style.cursor = "pointer";
        downloadBtn.innerHTML = '<i class="fas fa-download"></i>';
        downloadBtn.onclick = (e) => {
            e.stopPropagation();
            exportPDF(scan);
        };

        meta.appendChild(score);
        meta.appendChild(downloadBtn);
        
        item.appendChild(content);
        item.appendChild(meta);
        container.appendChild(item);
    });
}

function viewHistoryItem(index) {
    displayResults(scanHistory[index]);
}

function resetButton(loading) {
    const btn = document.getElementById('scan-btn');
    if (!btn) return;
    btn.disabled = loading;
    btn.innerHTML = loading ? 'SCANNING... <i class="fas fa-spinner fa-spin"></i>' : 'INITIATE SCAN <i class="fas fa-bolt"></i>';
}

function resetView() {
    document.getElementById('results-view').classList.add('hidden');
    document.getElementById('scan-view').classList.remove('hidden');
    logToTerminal("System ready.", "info");
}
