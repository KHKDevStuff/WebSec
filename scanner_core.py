import requests
import socket
import ssl
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import dns.resolver
import logging
import re

class SecurityScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'WebScrub-Security-Scanner/1.0'})

    def get_domain(self, target):
        parsed = urlparse(target)
        return parsed.netloc if parsed.netloc else target

    def check_headers(self, url):
        results = []
        try:
            response = self.session.get(url, timeout=10)
            headers = response.headers
            
            security_headers = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY',
                'Strict-Transport-Security': 'max-age',
                'Content-Security-Policy': 'default-src',
                'X-XSS-Protection': '1; mode=block'
            }
            
            for header, keyword in security_headers.items():
                if header not in headers:
                    results.append({
                        "name": f"Missing {header}",
                        "severity": "Medium",
                        "description": f"The security header {header} is missing, which is a common best practice."
                    })
            return results, headers
        except Exception as e:
            return [{"name": "Header Check Error", "severity": "Low", "description": str(e)}], {}

    def check_ssl(self, domain):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return {"status": "Valid", "details": "SSL/TLS Certificate is active and valid."}
        except Exception as e:
            return {"status": "Error/Weak", "details": str(e)}

    def check_dns(self, domain):
        try:
            res = {}
            for qtype in ['A', 'MX', 'TXT', 'NS']:
                try:
                    answers = dns.resolver.resolve(domain, qtype)
                    res[qtype] = [str(rdata) for rdata in answers]
                except:
                    res[qtype] = []
            return res
        except:
            return {}

    def check_csrf(self, soup, url):
        issues = []
        forms = soup.find_all('form')
        for form in forms:
            if not form.find(attrs={'name': re.compile(r'csrf', re.I)}) and \
               not form.find(attrs={'id': re.compile(r'csrf', re.I)}) and \
               not form.find(attrs={'name': re.compile(r'token', re.I)}):
                issues.append({
                    "name": "Missing CSRF Token",
                    "severity": "Medium",
                    "description": f"Form at {url} appears to be missing a CSRF token."
                })
        return issues

    def check_open_redirect(self, soup):
        issues = []
        for a in soup.find_all('a', href=True):
            href = a['href']
            if any(x in href for x in ['redirect=', 'next=', 'url=', 'dest=']):
                issues.append({
                    "name": "Potential Open Redirect",
                    "severity": "Low",
                    "description": f"Link {href} contains parameters often used for open redirects."
                })
        return issues

    def simple_xss_check(self, url):
        xss_payload = "<script>alert('WebScrub')</script>"
        try:
            # Very basic check: can we inject a script tag into a URL param and see it in response
            # Note: This is an extremely simplified demonstration
            test_url = f"{url}?search={xss_payload}"
            resp = self.session.get(test_url, timeout=10)
            if xss_payload in resp.text:
                return [{
                    "name": "Potential XSS Found",
                    "severity": "High",
                    "description": "The page seems to reflect input from URL parameters without proper encoding."
                }]
        except:
            pass
        return []



    def perform_full_scan(self, target, max_pages=1):
        if not target.startswith('http'):
            url = f"https://{target}"
        else:
            url = target
            
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
        results["ssl_info"] = self.check_ssl(domain)
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
            
            try:
                resp = self.session.get(current_url, timeout=10)
                soup = BeautifulSoup(resp.text, 'html.parser')
                
                # 1. Header Analysis (on first page or all? doing all for now but merging results might be noisy)
                # For simplicity, we stick to main URL for headers in the summary, 
                # but if we find issues on subpages we add them.
                header_vulns, raw_headers = self.check_headers(current_url)
                if count == 1:
                    results["raw_headers"] = dict(raw_headers)
                results["vulnerabilities"].extend(header_vulns)

                # 2. XSS Mock Check
                xss_vulns = self.simple_xss_check(current_url)
                results["vulnerabilities"].extend(xss_vulns)
                
                # 3. CSRF Check
                csrf_vulns = self.check_csrf(soup, current_url)
                results["vulnerabilities"].extend(csrf_vulns)

                # 4. Open Redirect Check
                redir_vulns = self.check_open_redirect(soup)
                results["vulnerabilities"].extend(redir_vulns)

                # 5. Information Leakage (Comments)
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
        results["risk_score"] = 0
        for v in results["vulnerabilities"]:
            if v["severity"] == "High": results["risk_score"] += 3
            if v["severity"] == "Medium": results["risk_score"] += 1.5
            if v["severity"] == "Low": results["risk_score"] += 0.5
        
        results["risk_score"] = min(round(results["risk_score"], 1), 10)
        
        return results
