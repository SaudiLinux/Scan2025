#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Israeli Domain Enumerator
وحدة تعداد الدومينات الإسرائيلية
Created by SayerLinux (SayerLinux1@gmail.com)
"""

import requests
import dns.resolver
import socket
import concurrent.futures
import json
import time
from urllib.parse import urlparse
from datetime import datetime
import whois
import subprocess
import re

class IsraeliDomainEnumerator:
    def __init__(self):
        self.israeli_tlds = [
            '.il', '.co.il', '.org.il', '.ac.il', '.gov.il', 
            '.muni.il', '.net.il', '.k12.il', '.idf.il'
        ]
        
        # Common Israeli subdomains
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'shop', 'store', 'news',
            'secure', 'login', 'portal', 'api', 'app', 'mobile', 'cdn',
            'support', 'help', 'docs', 'wiki', 'forum', 'chat', 'video',
            'images', 'img', 'static', 'assets', 'media', 'files', 'download',
            'upload', 'dev', 'test', 'staging', 'demo', 'beta', 'alpha',
            'vpn', 'remote', 'ssh', 'sftp', 'webmail', 'email', 'smtp',
            'pop', 'imap', 'mx', 'ns', 'ns1', 'ns2', 'dns', 'dns1', 'dns2',
            'server', 'srv', 'host', 'hosting', 'web', 'web1', 'web2',
            'db', 'database', 'mysql', 'postgres', 'mongo', 'redis',
            'cache', 'redis', 'memcached', 'elastic', 'search', 'es',
            'monitor', 'monitoring', 'stats', 'analytics', 'metrics',
            'backup', 'backups', 'archive', 'storage', 's3', 'cloud'
        ]
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
    def is_israeli_domain(self, domain):
        """Check if domain is Israeli"""
        domain_lower = domain.lower()
        return any(domain_lower.endswith(tld) for tld in self.israeli_tlds)
        
    def generate_domain_variations(self, base_name):
        """Generate variations of Israeli domains"""
        variations = []
        
        # Common Israeli organization suffixes
        israeli_suffixes = [
            '', 'israel', 'il', 'co', 'org', 'net', 'gov', 'ac', 'muni',
            'jerusalem', 'telaviv', 'haifa', 'beer', 'netanya', 'holon',
            'rishon', 'petah', 'ashdod', 'batyam', 'herzliya'
        ]
        
        # Generate combinations
        for suffix in israeli_suffixes:
            for tld in self.israeli_tlds:
                if suffix:
                    variations.append(f"{base_name}{suffix}{tld}")
                    variations.append(f"{base_name}-{suffix}{tld}")
                else:
                    variations.append(f"{base_name}{tld}")
                    
        return list(set(variations))  # Remove duplicates
        
    def check_domain_exists(self, domain):
        """Check if domain exists and is active"""
        try:
            # DNS resolution check
            answers = dns.resolver.resolve(domain, 'A')
            if answers:
                return True
        except:
            pass
            
        try:
            # HTTP check
            response = self.session.get(f"http://{domain}", timeout=5, allow_redirects=True)
            return response.status_code < 500
        except:
            pass
            
        return False
        
    def enumerate_subdomains(self, domain):
        """Enumerate subdomains for a given domain"""
        found_subdomains = []
        
        def check_subdomain(subdomain):
            full_domain = f"{subdomain}.{domain}"
            if self.check_domain_exists(full_domain):
                return full_domain
            return None
            
        # Use ThreadPool for faster enumeration
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            future_to_subdomain = {
                executor.submit(check_subdomain, sub): sub 
                for sub in self.common_subdomains
            }
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    found_subdomains.append(result)
                    
        return found_subdomains
        
    def get_certificate_transparency_logs(self, domain):
        """Get domains from Certificate Transparency logs"""
        found_domains = []
        
        try:
            # Query crt.sh API
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    # Split multiple domains
                    domains = name_value.split('\n')
                    for d in domains:
                        d = d.strip().lower()
                        if d and self.is_israeli_domain(d) and d not in found_domains:
                            found_domains.append(d)
                            
        except Exception as e:
            print(f"[-] Error querying CT logs: {e}")
            
        return found_domains
        
    def search_engines_discovery(self, domain):
        """Discover domains using search engines"""
        found_domains = []
        
        search_queries = [
            f"site:{domain}",
            f"site:*.{domain}",
            f"inurl:{domain}",
            f"\"{domain}\""
        ]
        
        for query in search_queries:
            try:
                # Using Bing search API (you'll need an API key)
                # For now, we'll use a simple Google search simulation
                url = f"https://www.google.com/search?q={query}"
                response = self.session.get(url, timeout=10)
                
                if response.status_code == 200:
                    # Extract domains from response (simplified)
                    domain_pattern = r'([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}'
                    matches = re.findall(domain_pattern, response.text)
                    
                    for match in matches:
                        if self.is_israeli_domain(match) and match not in found_domains:
                            found_domains.append(match)
                            
            except Exception as e:
                print(f"[-] Error with search engine query '{query}': {e}")
                
        return found_domains
        
    def whois_lookup(self, domain):
        """Perform WHOIS lookup"""
        try:
            w = whois.whois(domain)
            return {
                'domain': domain,
                'registrar': w.registrar,
                'creation_date': w.creation_date,
                'expiration_date': w.expiration_date,
                'name_servers': w.name_servers,
                'status': w.status,
                'emails': w.emails
            }
        except Exception as e:
            print(f"[-] WHOIS lookup failed for {domain}: {e}")
            return None
            
    def dns_zone_transfer(self, domain):
        """Attempt DNS zone transfer"""
        try:
            # Get NS records
            ns_answers = dns.resolver.resolve(domain, 'NS')
            
            zone_data = []
            for ns in ns_answers:
                ns_name = str(ns)
                try:
                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_name, domain))
                    for name, node in zone.nodes.items():
                        zone_data.append({
                            'name': str(name),
                            'data': str(node.to_text())
                        })
                except Exception as e:
                    print(f"[-] Zone transfer failed for {ns_name}: {e}")
                    
            return zone_data
            
        except Exception as e:
            print(f"[-] DNS zone transfer failed for {domain}: {e}")
            return []
            
    def enumerate_israeli_domains(self, keyword, max_domains=100):
        """Main function to enumerate Israeli domains"""
        print(f"[*] Starting Israeli domain enumeration for keyword: {keyword}")
        
        all_domains = []
        
        # Generate domain variations
        print("[*] Generating domain variations...")
        variations = self.generate_domain_variations(keyword)
        print(f"[+] Generated {len(variations)} domain variations")
        
        # Check which domains exist
        print("[*] Checking domain existence...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_domain = {
                executor.submit(self.check_domain_exists, domain): domain 
                for domain in variations[:max_domains]
            }
            
            for future in concurrent.futures.as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    if future.result():
                        all_domains.append(domain)
                        print(f"[+] Found active domain: {domain}")
                except Exception as e:
                    print(f"[-] Error checking {domain}: {e}")
                    
        # Get subdomains for found domains
        print("[*] Enumerating subdomains...")
        all_subdomains = []
        for domain in all_domains[:10]:  # Limit to avoid too many requests
            subdomains = self.enumerate_subdomains(domain)
            all_subdomains.extend(subdomains)
            print(f"[+] Found {len(subdomains)} subdomains for {domain}")
            
        # Certificate Transparency logs
        print("[*] Querying Certificate Transparency logs...")
        ct_domains = []
        for domain in all_domains[:5]:  # Limit to avoid rate limiting
            ct_found = self.get_certificate_transparency_logs(domain)
            ct_domains.extend(ct_found)
            print(f"[+] Found {len(ct_found)} domains in CT logs for {domain}")
            
        # Combine all results
        final_domains = list(set(all_domains + all_subdomains + ct_domains))
        
        # Filter only Israeli domains
        israeli_domains = [d for d in final_domains if self.is_israeli_domain(d)]
        
        print(f"[+] Total Israeli domains found: {len(israeli_domains)}")
        
        return {
            'keyword': keyword,
            'timestamp': datetime.now().isoformat(),
            'total_domains': len(israeli_domains),
            'domains': israeli_domains,
            'subdomains': all_subdomains,
            'ct_domains': ct_domains
        }
        
    def save_results(self, results, filename):
        """Save enumeration results to file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            print(f"[+] Results saved to {filename}")
            return True
        except Exception as e:
            print(f"[-] Error saving results: {e}")
            return False

if __name__ == "__main__":
    enumerator = IsraeliDomainEnumerator()
    
    # Test with a sample keyword
    test_keyword = "mossad"
    results = enumerator.enumerate_israeli_domains(test_keyword)
    
    # Save results
    filename = f"israeli_domains_{test_keyword}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    enumerator.save_results(results, filename)
    
    print(f"\n[+] Domain enumeration completed!")
    print(f"[+] Found {results['total_domains']} Israeli domains")
    print(f"[+] Results saved to: {filename}")