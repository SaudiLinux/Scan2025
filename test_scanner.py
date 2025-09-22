#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from domain_enumerator import IsraeliDomainEnumerator
from vulnerability_scanner import IsraeliVulnerabilityScanner
from report_generator import ReportGenerator

def test_scanner():
    print("Testing Israeli Domain Security Scanner...")
    
    # Test domain enumerator
    print("\n1. Testing Domain Enumerator:")
    enumerator = IsraeliDomainEnumerator()
    results = enumerator.enumerate_israeli_domains('mossad')
    
    if isinstance(results, dict):
        if 'domains' in results:
            domains = results['domains']
            print(f"Found {len(domains)} domains:")
            for domain in domains:
                print(f"  - {domain}")
        else:
            print("Available keys in results:")
            for key in results.keys():
                print(f"  - {key}: {type(results[key])}")
    
    # Test vulnerability scanner
    print("\n2. Testing Vulnerability Scanner:")
    scanner = IsraeliVulnerabilityScanner()
    
    # Test with a few domains
    test_domains = ['www.mossad.gov.il', 'mossad.org.il']
    all_vulnerabilities = []
    
    for domain in test_domains:
        print(f"Scanning {domain}...")
        vulns = scanner.scan_domain(domain)
        if vulns:
            print(f"Found {len(vulns)} vulnerabilities")
            all_vulnerabilities.extend(vulns)
        else:
            print("No vulnerabilities found")
    
    # Test report generator
    print("\n3. Testing Report Generator:")
    report_gen = ReportGenerator()
    
    report_data = {
        'scan_info': {
            'keyword': 'mossad',
            'scan_date': '2025-09-22 19:20:00',
            'total_domains_found': len(domains) if 'domains' in locals() else 0,
            'total_vulnerabilities': len(all_vulnerabilities),
            'scanner_version': '1.0.0'
        },
        'domains': domains if 'domains' in locals() else [],
        'vulnerabilities': all_vulnerabilities
    }
    
    # Generate JSON report
    import json
    with open('test_report.json', 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)
    print("JSON report saved: test_report.json")
    
    print("\nTest completed successfully!")

if __name__ == '__main__':
    test_scanner()