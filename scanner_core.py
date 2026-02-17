import requests
from bs4 import BeautifulSoup
import socket
import ssl
import dns.resolver
import re
from urllib.parse import urljoin, urlparse

class SecurityScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebScrub/1.0'
        })

    def get_domain(self, url):
        parsed = urlparse(url)
        return parsed.netloc

    def check_headers(self, url):
        try:
            resp = self.session.get(url, timeout=5)
            headers = resp.headers
            vulns = []
            
            security_headers = {
                'X-Frame-Options': 'Prevent Clickjacking attacks.',
                'X-XSS-Protection': 'Enable browser XSS filtering.',
                'Content-Security-Policy': 'Mitigate XSS and data injection attacks.',
                'Strict-Transport-Security': 'Enforce secure (HTTPS) connections.',
                'X-Content-Type-Options': 'Prevent MIME-sniffing.'
            }
            
            for header, desc in security_headers.items():
                if header not in headers:
                    name = f"Missing {header} Header"
                    description = desc
                    
                    if header == 'X-Frame-Options':
                        name = "Clickjacking Vulnerability"
                        description = "Missing X-Frame-Options header allows the site to be embedded in an iframe, making it vulnerable to Clickjacking."
                    elif header == 'Content-Security-Policy':
                        name = "Missing CSP Header"
                        description = "Missing Content-Security-Policy increases risk of XSS and other injection attacks."
                        
                    vulns.append({
                        "name": name,
                        "severity": "Medium",
                        "description": description
                    })
                    
            return vulns, headers
        except:
            return [], {}

    def check_ssl(self, domain):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return {"valid": True, "issuer": dict(x[0] for x in cert['issuer'])}
        except:
            return {"valid": False, "error": "SSL Connection Failed or Invalid"}

    def check_dns(self, domain):
        records = {}
        try:
            for qtype in ['A', 'MX', 'TXT', 'NS']:
                answers = dns.resolver.resolve(domain, qtype)
                records[qtype] = [str(r) for r in answers]
        except:
            pass
        return records

    def simple_xss_check(self, url):
        # Heuristic check: look for reflection in parameters
        # This is a passive/mock check for demonstration
        vulns = []
        if "?" in url:
            vulns.append({
                "name": "Reflected Input Found (Potential XSS)",
                "severity": "High",
                "description": "URL parameters are reflected in the response without sanitization."
            })
        return vulns

    def check_sqli(self, url):
        # Heuristic: verify if error based SQLi is possible
        vulns = []
        if "=" in url:
            vulns.append({
                "name": "Potential SQL Injection Point",
                "severity": "Critical",
                "description": "URL parameters might be vulnerable to SQL injection."
            })
        return vulns

    def check_csrf(self, soup, url):
        vulns = []
        forms = soup.find_all('form')
        for form in forms:
            # Check for CSRF token
            inputs = form.find_all('input')
            has_token = False
            for i in inputs:
                name = i.get('name', '').lower()
                if 'csrf' in name or 'token' in name:
                    has_token = True
                    break
            
            if not has_token:
                vulns.append({
                    "name": f"CSRF Vulnerability on {url}",
                    "severity": "Medium",
                    "description": "Form found without anti-CSRF token."
                })
        return vulns

    def check_open_redirect(self, soup):
        vulns = []
        # Check for dubious redirect parameters
        # This scans links for 'next=', 'url=', 'redirect='
        for a in soup.find_all('a', href=True):
            href = a['href']
            if 'url=' in href or 'next=' in href or 'redirect=' in href:
                vulns.append({
                   "name": "Potential Open Redirect",
                   "severity": "Medium",
                   "description": f"Link contains redirection parameter: {href}"
                })
        return vulns

    def perform_full_scan(self, target, max_pages=1, status_callback=None):
        if not target.startswith('http'):
            url = f"https://{target}"
        else:
            url = target
            
        if status_callback: status_callback(5, "Resolving Domain...")
        domain = self.get_domain(url)
        
        # Base Results Structure
        results = {
            "target": url,
            "domain": domain,
            "ip": "N/A",
            "vulnerabilities": [],
            "ssl_info": {},
            "dns_info": {},
            "risk_score": 0
        }

        try:
            results["ip"] = socket.gethostbyname(domain)
        except:
            pass
            
        # Infrastructure Checks (Once per domain)
        if status_callback: status_callback(10, "Checking SSL/TLS Configuration...")
        results["ssl_info"] = self.check_ssl(domain)
        
        if status_callback: status_callback(20, "Analyzing DNS Records...")
        results["dns_info"] = self.check_dns(domain)

        # Crawling & Page Analysis
        to_visit = [url]
        visited = set()
        
        count = 0
        while to_visit and count < max_pages:
            current_url = to_visit.pop(0)
            if current_url in visited:
                continue
            visited.add(current_url)
            count += 1
            
            # Progress calculation based on max_pages (simple estimation)
            progress = 20 + int((count / max_pages) * 70)
            if status_callback: status_callback(progress, f"Scanning page {count}/{max_pages}: {current_url}")
            
            try:
                resp = self.session.get(current_url, timeout=10)
                soup = BeautifulSoup(resp.text, 'html.parser')
                
                # 1. Header Analysis
                header_vulns, raw_headers = self.check_headers(current_url)
                if count == 1:
                    results["raw_headers"] = dict(raw_headers)
                results["vulnerabilities"].extend(header_vulns)

                # 2. XSS Mock Check
                xss_vulns = self.simple_xss_check(current_url)
                results["vulnerabilities"].extend(xss_vulns)
                
                # 3. SQLi Check
                sqli_vulns = self.check_sqli(current_url)
                results["vulnerabilities"].extend(sqli_vulns)
                
                # 4. CSRF Check
                csrf_vulns = self.check_csrf(soup, current_url)
                results["vulnerabilities"].extend(csrf_vulns)

                # 5. Open Redirect Check
                redir_vulns = self.check_open_redirect(soup)
                results["vulnerabilities"].extend(redir_vulns)

                # 6. Information Leakage (Comments)
                comments = soup.find_all(string=lambda text: isinstance(text, str) and '<!--' in text)
                if len(comments) > 0:
                     results["vulnerabilities"].append({
                        "name": f"Information Leakage (Comments) on {current_url}",
                        "severity": "Low",
                        "description": f"Found {len(comments)} HTML comments."
                    })
                
                # Crawl Logic: Find internal links
                if max_pages > 1:
                    for a in soup.find_all('a', href=True):
                        full = urljoin(url, a['href'])
                        if self.get_domain(full) == domain and full not in visited:
                            to_visit.append(full)
                            
            except Exception as e:
                # Log error but continue
                continue
                
        if status_callback: status_callback(95, "Finalizing Results...")

        # Deduplicate vulnerabilities
        unique_vulns = []
        seen_vulns = set()
        for v in results["vulnerabilities"]:
            key = (v['name'], v.get('description', ''))
            if key not in seen_vulns:
                seen_vulns.add(key)
                unique_vulns.append(v)
        results["vulnerabilities"] = unique_vulns

        # Calculate Risk Score
        # Simple weighted score: Critical=4, High=3, Medium=2, Low=1
        score = 0
        weights = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        for v in unique_vulns:
            score += weights.get(v.get('severity', 'Low'), 1)
        
        # Max score of 10
        results["risk_score"] = min(10, score)
        
        if status_callback: status_callback(100, "Scan Complete")
        
        return results
