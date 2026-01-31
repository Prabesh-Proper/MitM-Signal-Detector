#!/usr/bin/env python3
"""
Rogue Internet Behavior Detector
Detects fake captive portals, DNS hijacking, transparent proxies
Compares expected vs observed internet behavior
"""

import requests
import socket
import ssl
import subprocess
import sys
import json
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import time

class RogueDetector:
    def __init__(self):
        self.known_good_dns = ['8.8.8.8', '1.1.1.1', '208.67.222.222']
        self.trust_anchors = [
            'cloudflare.com', 'google.com', 'microsoft.com',
            'apple.com', 'amazon.com', 'github.com'
        ]
        self.captive_portal_tests = [
            "http://detectportal.firefox.com/success.txt",
            "http://connectivitycheck.gstatic.com/generate_204",
            "http://www.msftconnecttest.com/connecttest.txt",
            "http://captive.apple.com/hotspot-detect.html"
        ]

    def test_dns_resolution(self, domain, dns_server=None):
        """Test DNS resolution consistency across servers"""
        try:
            if dns_server:
                result = subprocess.run(
                    ['dig', f'+short', domain, '@' + dns_server],
                    capture_output=True, text=True, timeout=5
                )
                return result.stdout.strip().split('\n')[0] if result.returncode == 0 else None
            else:
                # Use system resolver
                return socket.gethostbyname(domain)
        except:
            return None

    def detect_dns_hijacking(self):
        """Detect DNS hijacking by comparing resolutions"""
        print("[+] Testing DNS consistency...")
        issues = []
        
        for domain in self.trust_anchors:
            expected_ips = []
            observed_ip = self.test_dns_resolution(domain)
            
            # Test against known good DNS
            for dns in self.known_good_dns:
                good_ip = self.test_dns_resolution(domain, dns)
                if good_ip and good_ip not in expected_ips:
                    expected_ips.append(good_ip)
            
            if observed_ip and observed_ip not in expected_ips:
                issues.append(f"DNS HIJACK: {domain} resolves to {observed_ip} "
                            f"(expected: {expected_ips})")
        
        return issues

    def detect_captive_portal(self):
        """Detect fake captive portals"""
        print("[+] Testing for captive portals...")
        issues = []
        
        for test_url in self.captive_portal_tests:
            try:
                resp = requests.get(test_url, timeout=5, allow_redirects=True)
                if "success" not in resp.text.lower() and resp.status_code == 200:
                    issues.append(f"CAPTIVE PORTAL: {test_url} returned unexpected content")
                elif resp.status_code == 302 or resp.status_code == 301:
                    issues.append(f"CAPTIVE REDIRECT: {test_url} -> {resp.url}")
            except Exception as e:
                issues.append(f"CAPTIVE BLOCK: {test_url} ({str(e)[:50]})")
        
        return issues

    def detect_transparent_proxy(self):
        """Detect transparent proxies via HTTP headers and behavior"""
        print("[+] Testing for transparent proxies...")
        issues = []
        
        test_sites = [
            "http://httpbin.org/headers",
            "http://httpbin.org/ip",
            "https://httpbin.org/headers"
        ]
        
        for url in test_sites:
            try:
                resp = requests.get(url, timeout=10)
                headers = resp.headers
                
                # Check for proxy headers
                proxy_headers = ['via', 'x-forwarded-for', 'x-real-ip', 
                               'x-forwarded-host', 'forwarded']
                for header in proxy_headers:
                    if header.lower() in headers:
                        issues.append(f"PROXY DETECTED: {header} = {headers.get(header, '')}")
                
                # Check for proxy behavior (different IP than expected)
                if 'origin' in resp.json():
                    observed_ip = resp.json()['origin']
                    # Quick check against external IP services
                    external_resp = requests.get("https://api.ipify.org", timeout=5)
                    expected_ip = external_resp.text.strip()
                    if observed_ip != expected_ip:
                        issues.append(f"PROXY IP MISMATCH: reported {observed_ip} != actual {expected_ip}")
                        
            except:
                continue
        
        return issues

    def test_ssl_interception(self):
        """Detect SSL/TLS interception"""
        print("[+] Testing SSL certificate chain...")
        issues = []
        
        test_hosts = ['www.google.com', 'github.com']
        
        for host in test_hosts:
            try:
                context = ssl.create_default_context()
                with socket.create_connection((host, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert()
                        
                        # Check issuer - suspicious if not from known CAs
                        issuer = dict(x[0] for x in cert['issuer'])
                        suspicious_cas = ['Transparent', 'Proxy', 'Mitmproxy', 'Charles']
                        for ca in suspicious_cas:
                            if ca.lower() in str(issuer).lower():
                                issues.append(f"SSL INTERCEPTION: {host} (issuer: {issuer.get('organizationName', 'unknown')})")
                        
            except Exception as e:
                issues.append(f"SSL TEST FAILED: {host} ({str(e)})")
        
        return issues

    def check_network_routes(self):
        """Check for suspicious routing"""
        print("[+] Checking routing table...")
        issues = []
        
        try:
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True)
            routes = result.stdout
            
            # Look for suspicious default gateways
            suspicious_gateways = ['192.168', '10.', '172.16', '172.17', '172.18']
            for line in routes.split('\n'):
                if 'default via' in line:
                    gateway = line.split('via')[-1].split()[0]
                    for sg in suspicious_gateways:
                        if sg in gateway:
                            issues.append(f"SUSPICIOUS GATEWAY: {gateway}")
        except:
            pass
        
        return issues

    def run_full_scan(self):
        """Run complete rogue behavior detection"""
        print("🔍 Rogue Internet Behavior Detector")
        print("=" * 50)
        
        all_issues = []
        tests = [
            ("DNS Hijacking", self.detect_dns_hijacking),
            ("Captive Portals", self.detect_captive_portal),
            ("Transparent Proxies", self.detect_transparent_proxy),
            ("SSL Interception", self.test_ssl_interception),
            ("Routing Issues", self.check_network_routes)
        ]
        
        for name, test_func in tests:
            print(f"\n[{name}]")
            issues = test_func()
            all_issues.extend(issues)
            for issue in issues:
                print(f"  ❌ {issue}")
        
        print("\n" + "=" * 50)
        print(f"📊 SUMMARY: {len(all_issues)} issues detected")
        
        if all_issues:
            print("\n🚨 POTENTIAL MITM DETECTED - Review issues above")
            return 1
        else:
            print("\n✅ Network behavior appears normal")
            return 0

if __name__ == "__main__":
    detector = RogueDetector()
    sys.exit(detector.run_full_scan())
