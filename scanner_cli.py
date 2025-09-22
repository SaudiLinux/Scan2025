#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Israeli Domain Security Scanner - CLI Version
أداة اختبار اختراق الدومينات الإسرائيلية - نسخة سطر الأوامر
"""

import sys
import json
import argparse
from datetime import datetime
from colorama import Fore, Style, init

# Import scanner modules
from domain_enumerator import IsraeliDomainEnumerator
from vulnerability_scanner import IsraeliVulnerabilityScanner
from report_generator import ReportGenerator

# Initialize colorama
init(autoreset=True)

class IsraeliDomainScannerCLI:
    def __init__(self):
        self.domain_enumerator = IsraeliDomainEnumerator()
        self.vulnerability_scanner = IsraeliVulnerabilityScanner()
        self.report_generator = ReportGenerator()
        
    def print_banner(self):
        """Print the scanner banner"""
        banner = f"""
{Fore.BLUE}╔═══════════════════════════════════════════════════════════════════════╗
║                    Israeli Domain Security Scanner                   ║
║                    ماسح الدومينات الإسرائيلية الأمني                ║
╚═══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
{Fore.CYAN}By: 𝙃𝙖𝙘𝙠𝙞𝙣𝙜 𝙏𝙚𝙘𝙝𝙣𝙤𝙡𝙤𝙜𝙮 🇵🇸{Style.RESET_ALL}
        """
        print(banner)
        
    def enumerate_domains(self, keyword):
        """Enumerate Israeli domains based on keyword"""
        print(f"{Fore.YELLOW}[*] Starting domain enumeration for keyword: {keyword}{Style.RESET_ALL}")
        
        results = self.domain_enumerator.enumerate_israeli_domains(keyword)
        
        if results:
            if isinstance(results, dict) and 'domains' in results:
                domains = results['domains']
                print(f"{Fore.GREEN}[+] Found {len(domains)} Israeli domains{Style.RESET_ALL}")
                for domain in domains[:10]:  # Show first 10 results
                    print(f"  - {domain}")
                if len(domains) > 10:
                    print(f"  ... and {len(domains) - 10} more")
            elif isinstance(results, list):
                print(f"{Fore.GREEN}[+] Found {len(results)} Israeli domains{Style.RESET_ALL}")
                for domain in results[:10]:  # Show first 10 results
                    print(f"  - {domain}")
                if len(results) > 10:
                    print(f"  ... and {len(results) - 10} more")
            else:
                print(f"{Fore.GREEN}[+] Found results: {results}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[-] No Israeli domains found{Style.RESET_ALL}")
            
        return results
        
    def scan_vulnerabilities(self, domains):
        """Scan domains for vulnerabilities"""
        if not domains:
            print(f"{Fore.RED}[-] No domains to scan{Style.RESET_ALL}")
            return []
            
        print(f"{Fore.YELLOW}[*] Starting vulnerability scan for {len(domains)} domains{Style.RESET_ALL}")
        
        vulnerabilities = []
        for i, domain in enumerate(domains, 1):
            print(f"{Fore.CYAN}[*] Scanning domain {i}/{len(domains)}: {domain}{Style.RESET_ALL}")
            
            # Scan for vulnerabilities
            vulns = self.vulnerability_scanner.scan_domain(domain)
            if vulns:
                vulnerabilities.extend(vulns)
                print(f"{Fore.RED}[!] Found {len(vulns)} vulnerabilities in {domain}{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[+] No vulnerabilities found in {domain}{Style.RESET_ALL}")
                
        return vulnerabilities
        
    def generate_report(self, domains, vulnerabilities, keyword):
        """Generate comprehensive report"""
        print(f"{Fore.YELLOW}[*] Generating report...{Style.RESET_ALL}")
        
        # Prepare data for report
        report_data = {
            'scan_info': {
                'keyword': keyword,
                'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'total_domains_found': len(domains),
                'total_vulnerabilities': len(vulnerabilities),
                'scanner_version': '1.0.0'
            },
            'domains': domains,
            'vulnerabilities': vulnerabilities
        }
        
        # Generate reports in different formats
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_filename = f"israeli_scan_report_{keyword}_{timestamp}"
        
        # JSON report
        json_file = f"{base_filename}.json"
        self.report_generator.export_to_json(report_data, json_file)
        print(f"{Fore.GREEN}[+] JSON report saved: {json_file}{Style.RESET_ALL}")
        
        # CSV report
        if domains:
            csv_file = f"{base_filename}_domains.csv"
            self.report_generator.export_to_csv(domains, csv_file)
            print(f"{Fore.GREEN}[+] CSV report saved: {csv_file}{Style.RESET_ALL}")
            
        # PDF report
        pdf_file = f"{base_filename}.pdf"
        self.report_generator.export_to_pdf(report_data, pdf_file)
        print(f"{Fore.GREEN}[+] PDF report saved: {pdf_file}{Style.RESET_ALL}")
        
        # HTML report
        html_file = f"{base_filename}.html"
        self.report_generator.export_to_html(report_data, html_file)
        print(f"{Fore.GREEN}[+] HTML report saved: {html_file}{Style.RESET_ALL}")
        
        return base_filename
        
    def run_full_scan(self, keyword):
        """Run complete scan process"""
        print(f"{Fore.BLUE}[*] Starting full security scan for Israeli domains{Style.RESET_ALL}")
        
        # Step 1: Domain enumeration
        results = self.enumerate_domains(keyword)
        
        # Extract domains from results
        if isinstance(results, dict) and 'domains' in results:
            domains = results['domains']
        elif isinstance(results, list):
            domains = results
        else:
            domains = []
            
        if not domains:
            print(f"{Fore.RED}[-] Scan completed. No domains found.{Style.RESET_ALL}")
            return
            
        # Step 2: Vulnerability scanning
        vulnerabilities = self.scan_vulnerabilities(domains)
        
        # Step 3: Report generation
        report_filename = self.generate_report(domains, vulnerabilities, keyword)
        
        # Summary
        print(f"\n{Fore.BLUE}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Scan completed successfully!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[+] Total domains found: {len(domains)}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[+] Total vulnerabilities found: {len(vulnerabilities)}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[+] Reports saved with prefix: {report_filename}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}{'='*60}{Style.RESET_ALL}")
        
def main():
    parser = argparse.ArgumentParser(
        description='Israeli Domain Security Scanner - CLI Version',
        epilog='Example: python scanner_cli.py -k mossad'
    )
    
    parser.add_argument(
        '-k', '--keyword',
        required=True,
        help='Keyword to search for Israeli domains (e.g., mossad, idf, security)'
    )
    
    parser.add_argument(
        '-e', '--enumerate-only',
        action='store_true',
        help='Only enumerate domains without vulnerability scanning'
    )
    
    parser.add_argument(
        '-s', '--scan-only',
        help='Only scan provided domains (comma-separated list)'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='scan_results',
        help='Output directory for reports (default: scan_results)'
    )
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = IsraeliDomainScannerCLI()
    scanner.print_banner()
    
    try:
        if args.scan_only:
            # Scan only mode
            domains = args.scan_only.split(',')
            domains = [d.strip() for d in domains]
            vulnerabilities = scanner.scan_vulnerabilities(domains)
            report_filename = scanner.generate_report(domains, vulnerabilities, 'custom_scan')
            
        elif args.enumerate_only:
            # Enumerate only mode
            domains = scanner.enumerate_domains(args.keyword)
            if domains:
                print(f"{Fore.GREEN}[+] Found {len(domains)} domains{Style.RESET_ALL}")
                for domain in domains:
                    print(f"  - {domain}")
                    
        else:
            # Full scan mode
            scanner.run_full_scan(args.keyword)
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == '__main__':
    main()