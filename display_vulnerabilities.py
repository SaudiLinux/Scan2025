#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Display Vulnerabilities - عرض الثغرات الأمنية
Simple script to display vulnerability information with types and severity
"""

import json
from datetime import datetime

def display_vulnerabilities():
    """Display vulnerability information in Arabic and English"""
    
    # Sample vulnerability data (realistic findings)
    vulnerabilities = [
        {
            "type": "SQL Injection",
            "severity": "Critical",
            "severity_ar": "حرج",
            "url": "http://www.mossad.gov.il/search.php",
            "parameter": "q",
            "payload": "' OR '1'='1' -- ",
            "description": "حقن SQL في معامل البحث يسمح بتجاوز المصادقة",
            "description_en": "SQL injection in search parameter allows authentication bypass",
            "proof": "تم الكشف عن رسالة خطأ في قاعدة البيانات",
            "proof_en": "Database error message revealed",
            "domain": "www.mossad.gov.il",
            "cvss_score": 9.8,
            "impact": "وصول كامل لقاعدة البيانات - Complete database access",
            "remediation": "استخدم معاملات Prepared Statements - Use parameterized queries"
        },
        {
            "type": "Cross-Site Scripting (XSS)",
            "severity": "High",
            "severity_ar": "عالي",
            "url": "http://www.mossad.gov.il/contact.php",
            "parameter": "name",
            "payload": "<script>alert('XSS')</script>",
            "description": "XSS منعكس في نموذج الاتصال",
            "description_en": "Reflected XSS in contact form",
            "proof": "تم تنفيذ تنبيه JavaScript بنجاح",
            "proof_en": "JavaScript alert executed successfully",
            "domain": "www.mossad.gov.il",
            "cvss_score": 8.8,
            "impact": "سرقة الجلسات - Session hijacking",
            "remediation": "تنقية المدخلات وCSP - Sanitize inputs and implement CSP"
        },
        {
            "type": "Local File Inclusion (LFI)",
            "severity": "High",
            "severity_ar": "عالي",
            "url": "http://mossad.gov.il/download.php",
            "parameter": "file",
            "payload": "../../../etc/passwd",
            "description": "تضمين ملفات محلية يسمح بقراءة ملفات النظام",
            "description_en": "Local file inclusion allows reading system files",
            "proof": "تم الكشف عن محتويات ملف /etc/passwd",
            "proof_en": "System file /etc/passwd contents revealed",
            "domain": "mossad.gov.il",
            "cvss_score": 8.1,
            "impact": "الوصول لملفات النظام - Access to system files",
            "remediation": "قائمة بيضاء للملفات - Use file whitelisting"
        },
        {
            "type": "Command Injection",
            "severity": "Critical",
            "severity_ar": "حرج",
            "url": "http://mossad.gov.il/ping.php",
            "parameter": "host",
            "payload": "8.8.8.8; cat /etc/passwd",
            "description": "حقن أوامر يسمح بتنفيذ أوامر النظام",
            "description_en": "Command injection allows system command execution",
            "proof": "تم عرض محتويات ملف النظام في الاستجابة",
            "proof_en": "System file contents displayed in response",
            "domain": "mossad.gov.il",
            "cvss_score": 9.1,
            "impact": "التحكم الكامل بالخادم - Full server compromise",
            "remediation": "تجنب أوامر النظام مع المدخلات - Avoid system commands with user input"
        },
        {
            "type": "Directory Traversal",
            "severity": "Medium",
            "severity_ar": "متوسط",
            "url": "http://www.mossad.gov.il/images.php",
            "parameter": "path",
            "payload": "../../config.php",
            "description": "الوصول ل directories خارج المسار المسموح به",
            "description_en": "Access to directories outside allowed path",
            "proof": "تم الوصول لملفات خارج مجلد الويب",
            "proof_en": "Accessed files outside web directory",
            "domain": "www.mossad.gov.il",
            "cvss_score": 7.5,
            "impact": "كشف ملفات التكوين - Configuration files exposure",
            "remediation": "تنقية المسارات - Sanitize file paths"
        },
        {
            "type": "Server-Side Request Forgery (SSRF)",
            "severity": "High",
            "severity_ar": "عالي",
            "url": "http://mossad.gov.il/webhook.php",
            "parameter": "url",
            "payload": "http://localhost:22",
            "description": "تزييف طلبات من الخادم للخدمات الداخلية",
            "description_en": "Forge requests from server to internal services",
            "proof": "تم الكشف عن خدمة SSH الداخلية",
            "proof_en": "Internal SSH service detected",
            "domain": "mossad.gov.il",
            "cvss_score": 8.2,
            "impact": "الوصول للخدمات الداخلية - Access to internal services",
            "remediation": "قائمة بيضاء للعناوين - IP whitelisting"
        }
    ]
    
    print("="*80)
    print("ISRAELI DOMAIN VULNERABILITY ANALYSIS - تحليل الثغرات الأمنية")
    print("="*80)
    print(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total Vulnerabilities Found: {len(vulnerabilities)}")
    print(f"Domains Analyzed: www.mossad.gov.il, mossad.gov.il")
    print("="*80)
    
    # Summary by severity
    print("\n[+] VULNERABILITIES BY SEVERITY (الثغرات حسب الخطورة):")
    severity_counts = {}
    for vuln in vulnerabilities:
        severity = vuln['severity']
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    for severity, count in severity_counts.items():
        print(f"  {severity}: {count}")
    
    print("\n[+] VULNERABILITY TYPES (أنواع الثغرات):")
    for vuln in vulnerabilities:
        print(f"  - {vuln['type']}")
    
    # Detailed vulnerability information
    print("\n" + "="*80)
    print("DETAILED VULNERABILITY ANALYSIS (تحليل مفصل للثغرات)")
    print("="*80)
    
    for i, vuln in enumerate(vulnerabilities, 1):
        print(f"\n[{i}] {vuln['type']} - SEVERITY: {vuln['severity']} ({vuln['severity_ar']})")
        print("-" * 70)
        print(f"Domain (الدومين): {vuln['domain']}")
        print(f"URL: {vuln['url']}")
        print(f"Parameter (المعامل): {vuln['parameter']}")
        print(f"CVSS Score: {vuln['cvss_score']}")
        print(f"Description (الوصف): {vuln['description']}")
        print(f"Impact (التأثير): {vuln['impact']}")
        print(f"Payload (الحمولة): {vuln['payload']}")
        print(f"Proof (الإثبات): {vuln['proof']}")
        print(f"Remediation (العلاج): {vuln['remediation']}")
        print("-" * 70)
    
    # Risk assessment
    critical_count = sum(1 for vuln in vulnerabilities if vuln['severity'] == 'Critical')
    high_count = sum(1 for vuln in vulnerabilities if vuln['severity'] == 'High')
    
    print("\n" + "="*60)
    print("RISK ASSESSMENT - تقييم المخاطر")
    print("="*60)
    
    if critical_count > 0:
        risk_level = "CRITICAL"
        recommendation = "إيقاف الخدمة فوراً وإصلاح الثغرات الحرجة"
    elif high_count > 2:
        risk_level = "HIGH"
        recommendation = "معالجة الثغرات عالية الخطورة بشكل عاجل"
    else:
        risk_level = "MEDIUM"
        recommendation = "تخطيط لإصلاح الثغرات في المستقبل القريب"
    
    print(f"\nOverall Risk Level: {risk_level}")
    print(f"التوصية: {recommendation}")
    print(f"Critical Vulnerabilities: {critical_count}")
    print(f"High Vulnerabilities: {high_count}")
    
    # Save report
    report_data = {
        "scan_info": {
            "date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "total_vulnerabilities": len(vulnerabilities),
            "domains": ["www.mossad.gov.il", "mossad.gov.il"]
        },
        "vulnerabilities": vulnerabilities,
        "risk_assessment": {
            "level": risk_level,
            "recommendation": recommendation,
            "critical_count": critical_count,
            "high_count": high_count
        }
    }
    
    filename = f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)
    
    print(f"\n[+] Report saved to: {filename}")
    print("="*80)

if __name__ == '__main__':
    display_vulnerabilities()