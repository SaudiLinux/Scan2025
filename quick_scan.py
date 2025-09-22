#!/usr/bin/env python3
"""
أداة فحص سريع لدومين إسرائيلي محدد
Quick Israeli Domain Scanner
"""

import sys
import json
from datetime import datetime
from colorama import init, Fore, Style

# Import الماسحات
from vulnerability_scanner import IsraeliVulnerabilityScanner
from domain_enumerator import IsraeliDomainEnumerator
from report_generator import ReportGenerator

init(autoreset=True)

def scan_israeli_domain(domain):
    """فحص دومين إسرائيلي محدد"""
    print(f"{Fore.CYAN}╔══════════════════════════════════════════════╗")
    print(f"{Fore.CYAN}║     فحص دومين إسرائيلي - Israeli Domain Scanner     ║")
    print(f"{Fore.CYAN}╚══════════════════════════════════════════════╝")
    print(f"{Fore.YELLOW}الهدف: {domain}")
    print(f"الوقت: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)
    
    # فحص الدومين
    scanner = IsraeliVulnerabilityScanner()
    
    # إنشاء قائمة بنتائج الفحص
    all_vulnerabilities = []
    
    # فحص الصفحة الرئيسية
    print(f"{Fore.BLUE}[*] فحص الصفحة الرئيسية...")
    try:
        # اختبار SQL Injection
        sql_vulns = scanner.test_sql_injection(f"http://{domain}")
        all_vulnerabilities.extend(sql_vulns)
        
        # اختبار XSS
        xss_vulns = scanner.test_xss(f"http://{domain}")
        all_vulnerabilities.extend(xss_vulns)
        
        # اختبار LFI
        lfi_vulns = scanner.test_lfi(f"http://{domain}")
        all_vulnerabilities.extend(lfi_vulns)
        
        # اختبار Command Injection
        cmd_vulns = scanner.test_command_injection(f"http://{domain}")
        all_vulnerabilities.extend(cmd_vulns)
        
        # اختبار SSRF
        ssrf_vulns = scanner.test_ssrf(f"http://{domain}")
        all_vulnerabilities.extend(ssrf_vulns)
        
    except Exception as e:
        print(f"{Fore.RED}خطأ في فحص http://{domain}: {e}")
    
    # فحص HTTPS أيضًا
    print(f"{Fore.BLUE}[*] فحص HTTPS...")
    try:
        # اختبار SQL Injection
        sql_vulns = scanner.test_sql_injection(f"https://{domain}")
        all_vulnerabilities.extend(sql_vulns)
        
        # اختبار XSS
        xss_vulns = scanner.test_xss(f"https://{domain}")
        all_vulnerabilities.extend(xss_vulns)
        
        # اختبار LFI
        lfi_vulns = scanner.test_lfi(f"https://{domain}")
        all_vulnerabilities.extend(lfi_vulns)
        
        # اختبار Command Injection
        cmd_vulns = scanner.test_command_injection(f"https://{domain}")
        all_vulnerabilities.extend(cmd_vulns)
        
        # اختبار SSRF
        ssrf_vulns = scanner.test_ssrf(f"https://{domain}")
        all_vulnerabilities.extend(ssrf_vulns)
        
    except Exception as e:
        print(f"{Fore.RED}خطأ في فحص https://{domain}: {e}")
    
    # إحصائيات
    critical = len([v for v in all_vulnerabilities if v.get('severity') == 'Critical'])
    high = len([v for v in all_vulnerabilities if v.get('severity') == 'High'])
    medium = len([v for v in all_vulnerabilities if v.get('severity') == 'Medium'])
    low = len([v for v in all_vulnerabilities if v.get('severity') == 'Low'])
    
    results = {
        'domain': domain,
        'scan_time': datetime.now().isoformat(),
        'total_vulnerabilities': len(all_vulnerabilities),
        'critical': critical,
        'high': high,
        'medium': medium,
        'low': low,
        'vulnerabilities': all_vulnerabilities
    }
    
    # عرض النتائج
    print(f"\n{Fore.GREEN}✅ تم اكتمال الفحص!")
    print(f"{Fore.CYAN}إحصائيات الفحص:")
    print(f"  • الدومين: {domain}")
    print(f"  • الثغرات الحرجة: {results.get('critical', 0)}")
    print(f"  • الثغرات عالية الخطورة: {results.get('high', 0)}")
    print(f"  • الثغرات متوسطة الخطورة: {results.get('medium', 0)}")
    print(f"  • الثغرات منخفضة الخطورة: {results.get('low', 0)}")
    
    if results.get('vulnerabilities'):
        print(f"\n{Fore.RED}🚨 الثغرات المكتشفة:")
        for vuln in results['vulnerabilities']:
            severity_color = Fore.RED if vuln['severity'] == 'Critical' else Fore.YELLOW
            print(f"{severity_color}  • [{vuln['severity']}] {vuln['type']} - {vuln['description']}")
    else:
        print(f"\n{Fore.GREEN}✅ لم يتم اكتشاف ثغرات أمنية")
    
    # حفظ النتائج
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"quick_scan_{domain.replace('.', '_')}_{timestamp}.json"
    
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    
    print(f"\n{Fore.CYAN}💾 تم حفظ النتائج في: {filename}")
    return results

if __name__ == "__main__":
    if len(sys.argv) > 1:
        domain = sys.argv[1]
        # إزالة http:// أو https:// إذا موجود
        domain = domain.replace('http://', '').replace('https://', '').rstrip('/')
        scan_israeli_domain(domain)
    else:
        print(f"{Fore.RED}الاستخدام: python quick_scan.py <domain>")
        print(f"{Fore.YELLOW}مثال: python quick_scan.py support.bankjerusalem.co.il")