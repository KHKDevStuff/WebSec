import requests
import socket
import ssl
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import dns.resolver
import logging

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

    def perform_full_scan(self, target):
        if not target.startswith('http'):
            url = f"https://{target}"
        else:
            url = target
            
        domain = self.get_domain(url)
        
        results = {
            "target": url,
            "domain": domain,
            "ip": socket.gethostbyname(domain) if domain else "N/A",
            "vulnerabilities": [],
            "ssl_info": self.check_ssl(domain),
            "dns_info": self.check_dns(domain),
            "risk_score": 0
        }

        # 1. Header Analysis
        header_vulns, raw_headers = self.check_headers(url)
        results["vulnerabilities"].extend(header_vulns)
        results["raw_headers"] = dict(raw_headers)

        # 2. XSS Mock Check
        xss_vulns = self.simple_xss_check(url)
        results["vulnerabilities"].extend(xss_vulns)

        # 3. BeautifulSoup - Check for sensitive comments
        try:
            resp = self.session.get(url, timeout=10)
            soup = BeautifulSoup(resp.text, 'html.parser')
            # Look for comments - often contain dev notes
            import re
            comments = soup.find_all(string=lambda text: isinstance(text, str) and '<!--' in text)
            if len(comments) > 0:
                 results["vulnerabilities"].append({
                    "name": "Information Leakage (Comments)",
                    "severity": "Low",
                    "description": f"Found {len(comments)} HTML comments which might contain sensitive internal info."
                })
        except:
            pass

        # Calculate Risk Score
        for v in results["vulnerabilities"]:
            if v["severity"] == "High": results["risk_score"] += 3
            if v["severity"] == "Medium": results["risk_score"] += 1.5
            if v["severity"] == "Low": results["risk_score"] += 0.5
        
        results["risk_score"] = min(round(results["risk_score"], 1), 10)
        
        return results
