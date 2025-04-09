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
import time
from selenium import webdriver
from selenium.common.exceptions import WebDriverException

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
        self.use_selenium = True  # Will be set to False if Selenium fails
        
    def check_robots_txt(self):
        """Check and display robots.txt contents"""
        robots_url = urljoin(self.target_url, '/robots.txt')
        try:
            response = self.session.get(robots_url, timeout=self.timeout)
            print("[*] robots.txt contents:")
            print(response.text)
        except Exception as e:
            print(f"[-] No robots.txt found or error accessing it: {e}")

    def init_selenium(self):
        """Initialize Selenium WebDriver with error handling"""
        try:
            options = webdriver.ChromeOptions()
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            return webdriver.Chrome(options=options)
        except WebDriverException as e:
            print(f"[!] Selenium initialization failed: {e}")
            print("[*] Falling back to requests-only mode (limited JavaScript support)")
            self.use_selenium = False
            return None
    
    def load_payloads(self, payload_file):
        """Load payloads from JSON file"""
        try:
            with open(payload_file) as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading payloads: {e}")
            return {}
    
    def crawl(self, url=None):
        """Web crawler with Selenium fallback to requests"""
        if url is None:
            url = self.target_url
            
        if url in self.crawled_urls:
            return
        self.crawled_urls.add(url)
        
        if self.use_selenium:
            driver = self.init_selenium()
            if driver:
                try:
                    driver.get(url)
                    time.sleep(2)  # Wait for JavaScript to load
                    html = driver.page_source
                    self.parse_links(url, html)
                except Exception as e:
                    print(f"Selenium error crawling {url}: {e}")
                    self.use_selenium = False  # Disable Selenium after failure
                    self.crawl_with_requests(url)
                finally:
                    if driver:
                        driver.quit()
            else:
                self.crawl_with_requests(url)
        else:
            self.crawl_with_requests(url)
    
    def crawl_with_requests(self, url):
        """Fallback crawler using requests only"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            self.parse_links(url, response.text)
        except Exception as e:
            print(f"Error crawling {url}: {e}")
    
    def parse_links(self, base_url, html):
        """Parse links from HTML content"""
        soup = BeautifulSoup(html, 'html.parser')
        
        # Extract all links
        for link in soup.find_all('a', href=True):
            absolute_url = urljoin(base_url, link['href'])
            if self.target_url in absolute_url and absolute_url not in self.discovered_urls:
                self.discovered_urls.add(absolute_url)
        
        # Extract forms
        for form in soup.find_all('form'):
            form_action = form.get('action')
            if form_action:
                absolute_url = urljoin(base_url, form_action)
                if self.target_url in absolute_url and absolute_url not in self.discovered_urls:
                    self.discovered_urls.add(absolute_url)

    # [Rest of your scan methods remain exactly the same as in previous version]
    # ...

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
