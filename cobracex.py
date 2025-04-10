#!/usr/bin/env python3
import argparse
import requests
import json
import re
import time
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional
from enum import Enum
import hashlib
import hmac
import base64

# Disable warnings
import warnings
warnings.filterwarnings("ignore")

class Severity(Enum):
    CRITICAL = 4  # Direct fund theft or mass data leak
    HIGH = 3      # Indirect fund risk or targeted data leak
    # Medium/Low not included - we focus only on critical risks

class CEXScanner:
    def __init__(self, cex_url: str):
        self.cex_url = cex_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9'
        })
        self.findings = []
        self.request_delay = 1.2  # Avoid rate limiting
        self.api_endpoints = self._discover_api_endpoints()

    def scan_all(self) -> Dict:
        """Execute complete security scan"""
        print(f"\n[▶] Scanning {self.cex_url} for critical vulnerabilities")
        
        scan_sequence = [
            self._scan_auth_mechanisms,
            self._scan_token_handling,
            self._scan_payment_flows,
            self._scan_admin_interfaces,
            self._scan_data_leaks,
            self._scan_dom_based_xss
        ]
        
        for step in scan_sequence:
            try:
                step()
                time.sleep(self.request_delay)
            except Exception as e:
                print(f"[!] {step.__name__} failed: {str(e)[:100]}")
        
        return self._generate_report()

    def _discover_api_endpoints(self) -> List[str]:
        """Find API endpoints from JavaScript files"""
        print("[•] Discovering API endpoints...")
        js_code = self._fetch_js_code()
        api_patterns = [
            r'https?://api\.[^"\']+',
            r'/api/v\d+/[^"\']+',
            r'baseURL:\s*["\'](https?://[^"\']+)',
            r'axios\.create\([^)]*baseURL:\s*["\'](https?://[^"\']+)'
        ]
        
        endpoints = set()
        for pattern in api_patterns:
            matches = re.finditer(pattern, js_code, re.IGNORECASE)
            for match in matches:
                url = match.group(1) if match.groups() else match.group(0)
                if not url.startswith('http'):
                    url = urljoin(self.cex_url, url)
                endpoints.add(url)
        
        return list(endpoints)[:10]  # Limit to top 10 endpoints

    def _scan_auth_mechanisms(self):
        """Check for authentication vulnerabilities"""
        print("[•] Testing authentication mechanisms...")
        
        # Test for JWT issues
        auth_checks = [
            (r'localStorage\.(set|get)Item\(["\'](token|jwt|auth_token)', 
             "JWT in LocalStorage", 
             "Tokens stored in localStorage are vulnerable to XSS"),
             
            (r'Authorization:\s*Bearer\s*[\w-]+\.[\w-]+\.[\w-]+', 
             "Hardcoded JWT", 
             "Found potential hardcoded authentication token"),
             
            (r'alg:\s*["\'](none|HS256)["\']', 
             "Weak JWT Algorithm", 
             "Insecure JWT algorithm allows token manipulation")
        ]
        
        js_code = self._fetch_js_code()
        self._match_patterns(js_code, auth_checks, "Authentication")

    def _scan_token_handling(self):
        """Check API token handling vulnerabilities"""
        print("[•] Analyzing API token handling...")
        
        # Test API endpoints for token leakage
        for endpoint in self.api_endpoints[:3]:  # Check top 3 endpoints
            try:
                response = self.session.get(endpoint, timeout=10)
                if 'api_key=' in response.text:
                    self._add_finding(
                        "API Key in URL",
                        f"Found API key in URL parameters at {endpoint}",
                        Severity.CRITICAL,
                        endpoint
                    )
                
                if 'x-signature' in response.headers:
                    self._test_signature_bypass(endpoint)
                    
            except Exception as e:
                continue

    def _test_signature_bypass(self, endpoint: str):
        """Test for signature bypass vulnerabilities"""
        test_payload = {'amount': '1000', 'currency': 'USDT'}
        
        # Test with empty signature
        try:
            response = self.session.post(
                endpoint,
                headers={'X-Signature': ''},
                json=test_payload,
                timeout=8
            )
            if response.status_code == 200:
                self._add_finding(
                    "Signature Bypass",
                    f"Endpoint {endpoint} accepts empty signatures",
                    Severity.CRITICAL,
                    endpoint
                )
        except:
            pass

    def _scan_payment_flows(self):
        """Check payment processing vulnerabilities"""
        print("[•] Testing payment flows...")
        html = self._fetch_html()
        
        # Check for direct crypto address injection
        payment_risks = [
            (r'document\.(getElementById|querySelector)\(["\'][^"\']+["\']\)\.value\s*=', 
             "DOM-based Address Injection", 
             "Potential for wallet address hijacking"),
             
            (r'window\.location\.hash\s*=\s*["\'][^"\']+["\']', 
             "URL Hash Manipulation", 
             "Payment parameters can be modified via URL hash")
        ]
        
        self._match_patterns(html, payment_risks, "Payment Processing")

    def _scan_admin_interfaces(self):
        """Check for exposed admin interfaces"""
        print("[•] Searching for admin interfaces...")
        common_admin_paths = [
            '/admin', '/administrator', '/wp-admin',
            '/manager', '/console', '/backoffice'
        ]
        
        for path in common_admin_paths:
            try:
                url = urljoin(self.cex_url, path)
                response = self.session.get(url, timeout=8, allow_redirects=False)
                
                if response.status_code == 200 and any(
                    x in response.text.lower() 
                    for x in ['login', 'admin', 'dashboard']
                ):
                    self._add_finding(
                        "Exposed Admin Interface",
                        f"Admin panel accessible at {url}",
                        Severity.CRITICAL,
                        url
                    )
                    
            except Exception as e:
                continue

    def _scan_data_leaks(self):
        """Check for sensitive data leaks"""
        print("[•] Checking for data leaks...")
        
        # Test common API endpoints
        leak_endpoints = [
            '/api/v1/user', '/account/profile',
            '/withdraw/history', '/order/history'
        ]
        
        for endpoint in leak_endpoints:
            try:
                url = urljoin(self.cex_url, endpoint)
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200:
                    sensitive_data = re.findall(
                        r'(api_?key|secret|password|private_?key|2fa|totp)["\']?\s*:\s*["\'][^"\']+',
                        response.text,
                        re.IGNORECASE
                    )
                    
                    if sensitive_data:
                        self._add_finding(
                            "Sensitive Data Exposure",
                            f"Found {len(sensitive_data)} sensitive data fields at {url}",
                            Severity.CRITICAL,
                            url
                        )
                        
            except Exception as e:
                continue

    def _scan_dom_based_xss(self):
        """Check for DOM-based XSS in withdrawal flows"""
        print("[•] Testing for DOM XSS in withdrawal...")
        html = self._fetch_html()
        
        xss_patterns = [
            (r'document\.write\([^)]*window\.location', 
             "DOM XSS via document.write", 
             "Critical XSS in withdrawal flow"),
             
            (r'eval\([^)]*location\.hash', 
             "DOM XSS via eval", 
             "Critical XSS in payment processing"),
             
            (r'innerHTML\s*=\s*[^;]*location\.', 
             "DOM XSS via innerHTML", 
             "Critical XSS in balance display")
        ]
        
        self._match_patterns(html, xss_patterns, "DOM XSS")

    def _fetch_html(self) -> str:
        """Fetch main page HTML"""
        try:
            return self.session.get(self.cex_url, timeout=15).text
        except:
            return ""

    def _fetch_js_code(self) -> str:
        """Fetch and combine JavaScript files"""
        html = self._fetch_html()
        js_files = list(set(re.findall(r'src="([^"]+\.js)"', html)))[:5]
        
        combined_js = ""
        for js_file in js_files:
            try:
                url = urljoin(self.cex_url, js_file)
                combined_js += self.session.get(url, timeout=10).text + "\n"
                time.sleep(self.request_delay)
            except:
                continue
        return combined_js

    def _match_patterns(self, content: str, patterns: List[tuple], context: str):
        """Match vulnerability patterns against content"""
        for pattern, title, desc in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                self._add_finding(
                    title,
                    desc,
                    Severity.CRITICAL,
                    context
                )

    def _add_finding(self, title: str, desc: str, severity: Severity, location: str):
        """Record a new security finding"""
        self.findings.append({
            "title": title,
            "description": desc,
            "severity": severity.name,
            "location": location
        })

    def _generate_report(self) -> Dict:
        """Generate comprehensive report"""
        return {
            "metadata": {
                "url": self.cex_url,
                "timestamp": int(time.time()),
                "endpoints_scanned": len(self.api_endpoints)
            },
            "findings": sorted(
                self.findings,
                key=lambda x: Severity[x['severity']].value,
                reverse=True
            ),
            "summary": {
                "critical": sum(1 for f in self.findings if f['severity'] == "CRITICAL"),
                "high": sum(1 for f in self.findings if f['severity'] == "HIGH"),
                "total": len(self.findings)
            }
        }

def print_banner():
    """Display tool banner"""
    print("""
    ██████╗███████╗██╗  ██╗    ███████╗██████╗ ███████╗██╗    ██╗
    ██╔════╝██╔════╝╚██╗██╔╝    ██╔════╝██╔══██╗██╔════╝██║    ██║
    ██║     █████╗   ╚███╔╝     ███████╗██████╔╝█████╗  ██║ █╗ ██║
    ██║     ██╔══╝   ██╔██╗     ╚════██║██╔═══╝ ██╔══╝  ██║███╗██║
    ╚██████╗███████╗██╔╝ ██╗    ███████║██║     ███████╗╚███╔███╔╝
     ╚═════╝╚══════╝╚═╝  ╚═╝    ╚══════╝╚═╝     ╚══════╝ ╚══╝╚══╝ 
    CEX Security Scanner v1.0 | Critical Vulnerability Detection
    """)

def main():
    print_banner()
    parser = argparse.ArgumentParser(description='Scan CEX for critical vulnerabilities')
    parser.add_argument('-u', '--url', required=True, help='CEX URL (e.g., https://exchange.com)')
    parser.add_argument('-o', '--output', help='Save report to JSON file')
    args = parser.parse_args()

    try:
        scanner = CEXScanner(args.url)
        report = scanner.scan_all()
        
        print("\n=== Critical Findings ===")
        for finding in report['findings']:
            if finding['severity'] == "CRITICAL":
                print(f"\n[CRITICAL] {finding['title']}")
                print(f"• {finding['description']}")
                print(f"• Location: {finding['location']}")
        
        stats = report['summary']
        print(f"\n» Total Findings: {stats['total']} | Critical: {stats['critical']}")
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\nReport saved to {args.output}")
            
    except Exception as e:
        print(f"\n[✗] Fatal Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
