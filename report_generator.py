#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
وحدة توليد التقارير
Report Generator Module
"""

import json
import csv
from datetime import datetime
import os
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_LEFT
import pandas as pd

class ReportGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.setup_custom_styles()
        
    def setup_custom_styles(self):
        """Setup custom styles for reports"""
        # Custom styles for Arabic text
        self.styles.add(ParagraphStyle(
            name='ArabicTitle',
            parent=self.styles['Title'],
            fontName='Helvetica-Bold',
            fontSize=18,
            textColor=colors.HexColor('#2c3e50'),
            alignment=TA_CENTER,
            spaceAfter=30
        ))
        
        self.styles.add(ParagraphStyle(
            name='ArabicHeading',
            parent=self.styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=14,
            textColor=colors.HexColor('#34495e'),
            spaceAfter=12
        ))
        
        self.styles.add(ParagraphStyle(
            name='ArabicNormal',
            parent=self.styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            textColor=colors.black,
            spaceAfter=6
        ))
        
        self.styles.add(ParagraphStyle(
            name='VulnerabilityHigh',
            parent=self.styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=10,
            textColor=colors.red,
            backColor=colors.lightpink
        ))
        
        self.styles.add(ParagraphStyle(
            name='VulnerabilityMedium',
            parent=self.styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=10,
            textColor=colors.orange
        ))
        
        self.styles.add(ParagraphStyle(
            name='VulnerabilityLow',
            parent=self.styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            textColor=colors.blue
        ))
        
    def export_json(self, results, filename):
        """Export results to JSON format"""
        try:
            report_data = {
                'scan_info': {
                    'tool_name': 'Israeli Domain Security Scanner',
                    'developer': 'SayerLinux',
                    'email': 'SayerLinux1@gmail.com',
                    'scan_date': datetime.now().isoformat(),
                    'total_domains_scanned': len(results)
                },
                'results': results
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
                
            return True
            
        except Exception as e:
            print(f"[-] Error exporting JSON: {str(e)}")
            return False
            
    def export_csv(self, results, filename):
        """Export results to CSV format"""
        try:
            # Flatten the results for CSV export
            flattened_data = []
            
            for domain_result in results:
                domain = domain_result.get('domain', 'Unknown')
                scan_time = domain_result.get('scan_time', '')
                
                # Add vulnerabilities
                for vuln in domain_result.get('vulnerabilities', []):
                    row = {
                        'Domain': domain,
                        'Scan Time': scan_time,
                        'Vulnerability Type': vuln.get('type', ''),
                        'Severity': vuln.get('severity', ''),
                        'URL': vuln.get('url', ''),
                        'Description': vuln.get('description', ''),
                        'Parameter': vuln.get('parameter', ''),
                        'Payload': vuln.get('payload', '')
                    }
                    flattened_data.append(row)
                    
                # If no vulnerabilities, add a row indicating scan was performed
                if not domain_result.get('vulnerabilities'):
                    row = {
                        'Domain': domain,
                        'Scan Time': scan_time,
                        'Vulnerability Type': 'No vulnerabilities found',
                        'Severity': 'Info',
                        'URL': '',
                        'Description': 'No security vulnerabilities detected',
                        'Parameter': '',
                        'Payload': ''
                    }
                    flattened_data.append(row)
                    
            # Write to CSV
            if flattened_data:
                df = pd.DataFrame(flattened_data)
                df.to_csv(filename, index=False, encoding='utf-8')
            else:
                # Create empty CSV with headers
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=[
                        'Domain', 'Scan Time', 'Vulnerability Type', 'Severity', 
                        'URL', 'Description', 'Parameter', 'Payload'
                    ])
                    writer.writeheader()
                    
            return True
            
        except Exception as e:
            print(f"[-] Error exporting CSV: {str(e)}")
            return False
            
    def export_pdf(self, results, filename):
        """Export results to PDF format"""
        try:
            doc = SimpleDocTemplate(filename, pagesize=A4)
            story = []
            
            # Title page
            title = Paragraph("تقرير فحص أمن الدومينات الإسرائيلية", self.styles['ArabicTitle'])
            story.append(title)
            
            subtitle = Paragraph("Israeli Domain Security Scan Report", self.styles['ArabicHeading'])
            story.append(subtitle)
            story.append(Spacer(1, 20))
            
            # Scan information
            info_data = [
                ['معلومات الفحص', 'Scan Information'],
                ['تاريخ الفحص', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
                ['عدد الدومينات المفحوصة', str(len(results))],
                ['المبرمج', 'SayerLinux'],
                ['البريد الإلكتروني', 'SayerLinux1@gmail.com'],
                ['أداة الفحص', 'Israeli Domain Security Scanner']
            ]
            
            info_table = Table(info_data, colWidths=[2*inch, 3*inch])
            info_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#ecf0f1')),
                ('GRID', (0, 0), (-1, -1), 1, colors.white)
            ]))
            
            story.append(info_table)
            story.append(PageBreak())
            
            # Summary statistics
            story.append(Paragraph("ملخص النتائج", self.styles['ArabicHeading']))
            story.append(Spacer(1, 12))
            
            total_vulnerabilities = 0
            severity_counts = {'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            
            for domain_result in results:
                for vuln in domain_result.get('vulnerabilities', []):
                    total_vulnerabilities += 1
                    severity = vuln.get('severity', 'info').lower()
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                        
            summary_data = [
                ['إجمالي الثغرات', str(total_vulnerabilities)],
                ['ثغرات عالية الخطورة', str(severity_counts['high'])],
                ['ثغرات متوسطة الخطورة', str(severity_counts['medium'])],
                ['ثغرات منخفضة الخطورة', str(severity_counts['low'])],
                ['معلومات', str(severity_counts['info'])]
            ]
            
            summary_table = Table(summary_data, colWidths=[2.5*inch, 2.5*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498db')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 11),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#ecf0f1')),
                ('GRID', (0, 0), (-1, -1), 1, colors.white)
            ]))
            
            story.append(summary_table)
            story.append(PageBreak())
            
            # Detailed results
            story.append(Paragraph("نتائج مفصلة", self.styles['ArabicHeading']))
            story.append(Spacer(1, 12))
            
            for domain_result in results:
                domain = domain_result.get('domain', 'Unknown')
                story.append(Paragraph(f"الدومين: {domain}", self.styles['ArabicHeading']))
                
                vulnerabilities = domain_result.get('vulnerabilities', [])
                
                if vulnerabilities:
                    for vuln in vulnerabilities:
                        vuln_type = vuln.get('type', 'Unknown')
                        severity = vuln.get('severity', 'info')
                        description = vuln.get('description', '')
                        url = vuln.get('url', '')
                        
                        # Choose style based on severity
                        if severity.lower() == 'high':
                            style = self.styles['VulnerabilityHigh']
                        elif severity.lower() == 'medium':
                            style = self.styles['VulnerabilityMedium']
                        else:
                            style = self.styles['VulnerabilityLow']
                            
                        vuln_text = f"نوع الثغرة: {vuln_type} | الخطورة: {severity} | الوصف: {description}"
                        if url:
                            vuln_text += f" | الرابط: {url}"
                            
                        story.append(Paragraph(vuln_text, style))
                        story.append(Spacer(1, 6))
                else:
                    story.append(Paragraph("لا توجد ثغرات أمنية", self.styles['ArabicNormal']))
                    
                story.append(Spacer(1, 20))
                
            # Build PDF
            doc.build(story)
            return True
            
        except Exception as e:
            print(f"[-] Error exporting PDF: {str(e)}")
            return False
            
    def generate_html_report(self, results):
        """Generate HTML report"""
        try:
            html_content = f"""
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>تقرير فحص أمن الدومينات الإسرائيلية</title>
    <style>
        body {{
            font-family: 'Arial', sans-serif;
            background-color: #f5f5f5;
            margin: 0;
            padding: 20px;
            direction: rtl;
            text-align: right;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            margin-bottom: 40px;
            padding-bottom: 20px;
            border-bottom: 3px solid #3498db;
        }}
        .header h1 {{
            color: #2c3e50;
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .header p {{
            color: #7f8c8d;
            font-size: 1.2em;
            margin: 5px 0;
        }}
        .developer-info {{
            background-color: #34495e;
            color: white;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 30px;
            text-align: center;
        }}
        .scan-info {{
            background-color: #ecf0f1;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 30px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-left: 4px solid #3498db;
        }}
        .summary-card h3 {{
            color: #2c3e50;
            margin-bottom: 10px;
        }}
        .summary-card .number {{
            font-size: 2em;
            font-weight: bold;
            color: #3498db;
        }}
        .domain-results {{
            margin-top: 30px;
        }}
        .domain-card {{
            background-color: white;
            border: 1px solid #ddd;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        .domain-header {{
            background-color: #34495e;
            color: white;
            padding: 15px 20px;
            font-size: 1.2em;
            font-weight: bold;
        }}
        .domain-content {{
            padding: 20px;
        }}
        .vulnerability {{
            margin-bottom: 15px;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid;
        }}
        .vulnerability.high {{
            background-color: #ffebee;
            border-left-color: #f44336;
        }}
        .vulnerability.medium {{
            background-color: #fff3e0;
            border-left-color: #ff9800;
        }}
        .vulnerability.low {{
            background-color: #e3f2fd;
            border-left-color: #2196f3;
        }}
        .vulnerability-type {{
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 5px;
        }}
        .vulnerability-severity {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 0.9em;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .severity-high {{
            background-color: #f44336;
            color: white;
        }}
        .severity-medium {{
            background-color: #ff9800;
            color: white;
        }}
        .severity-low {{
            background-color: #2196f3;
            color: white;
        }}
        .vulnerability-url {{
            color: #3498db;
            font-family: monospace;
            font-size: 0.9em;
            margin-top: 5px;
        }}
        .no-vulnerabilities {{
            text-align: center;
            color: #27ae60;
            font-size: 1.1em;
            padding: 20px;
            background-color: #e8f5e8;
            border-radius: 5px;
        }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #7f8c8d;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>تقرير فحص أمن الدومينات الإسرائيلية</h1>
            <p>Israeli Domain Security Scan Report</p>
            <p>تاريخ التقرير: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="developer-info">
            <h3>المبرمج: SayerLinux</h3>
            <p>البريد الإلكتروني: SayerLinux1@gmail.com</p>
            <p>أداة فحص متخصصة في الدومينات الإسرائيلية</p>
        </div>
        
        <div class="scan-info">
            <h3>معلومات الفحص</h3>
            <p><strong>عدد الدومينات المفحوصة:</strong> {len(results)}</p>
            <p><strong>تاريخ الفحص:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="summary">
"""
            
            # Calculate summary statistics
            total_vulnerabilities = 0
            severity_counts = {'high': 0, 'medium': 0, 'low': 0}
            
            for domain_result in results:
                for vuln in domain_result.get('vulnerabilities', []):
                    total_vulnerabilities += 1
                    severity = vuln.get('severity', 'low').lower()
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                        
            html_content += f"""
            <div class="summary-card">
                <h3>إجمالي الثغرات</h3>
                <div class="number">{total_vulnerabilities}</div>
            </div>
            <div class="summary-card">
                <h3>ثغرات عالية الخطورة</h3>
                <div class="number">{severity_counts['high']}</div>
            </div>
            <div class="summary-card">
                <h3>ثغرات متوسطة الخطورة</h3>
                <div class="number">{severity_counts['medium']}</div>
            </div>
            <div class="summary-card">
                <h3>ثغرات منخفضة الخطورة</h3>
                <div class="number">{severity_counts['low']}</div>
            </div>
        </div>
        
        <div class="domain-results">
            <h2>نتائج الفحص المفصلة</h2>
"""
            
            for domain_result in results:
                domain = domain_result.get('domain', 'Unknown')
                vulnerabilities = domain_result.get('vulnerabilities', [])
                
                html_content += f"""
            <div class="domain-card">
                <div class="domain-header">
                    الدومين: {domain}
                </div>
                <div class="domain-content">
"""
                
                if vulnerabilities:
                    for vuln in vulnerabilities:
                        vuln_type = vuln.get('type', 'Unknown')
                        severity = vuln.get('severity', 'low').lower()
                        description = vuln.get('description', '')
                        url = vuln.get('url', '')
                        
                        html_content += f"""
                    <div class="vulnerability {severity}">
                        <div class="vulnerability-type">النوع: {vuln_type}</div>
                        <span class="vulnerability-severity severity-{severity}">الخطورة: {severity}</span>
                        <div class="vulnerability-description">{description}</div>
                        {f'<div class="vulnerability-url">الرابط: {url}</div>' if url else ''}
                    </div>
"""
                else:
                    html_content += """
                    <div class="no-vulnerabilities">
                        ✓ لم يتم العثور على ثغرات أمنية في هذا الدومين
                    </div>
"""
                
                html_content += """
                </div>
            </div>
"""
            
            html_content += """
        </div>
        
        <div class="footer">
            <p>تم إنشاء هذا التقرير بواسطة أداة Israeli Domain Security Scanner</p>
            <p>المبرمج: SayerLinux | البريد الإلكتروني: SayerLinux1@gmail.com</p>
            <p>© 2024 - جميع الحقوق محفوظة</p>
        </div>
    </div>
</body>
</html>
"""
            
            return html_content
            
        except Exception as e:
            print(f"[-] Error generating HTML report: {str(e)}")
            return None

if __name__ == "__main__":
    generator = ReportGenerator()
    
    # Test data
    test_results = [
        {
            'domain': 'test.co.il',
            'scan_time': datetime.now().isoformat(),
            'vulnerabilities': [
                {
                    'type': 'sql_injection',
                    'severity': 'high',
                    'url': 'http://test.co.il/login',
                    'description': 'SQL Injection vulnerability in login form',
                    'parameter': 'username',
                    'payload': "' OR 1=1--"
                },
                {
                    'type': 'xss',
                    'severity': 'medium',
                    'url': 'http://test.co.il/search',
                    'description': 'Cross-site scripting vulnerability',
                    'parameter': 'q',
                    'payload': "<script>alert('XSS')</script>"
                }
            ]
        },
        {
            'domain': 'example.org.il',
            'scan_time': datetime.now().isoformat(),
            'vulnerabilities': []
        }
    ]
    
    # Test exports
    print("[*] Testing JSON export...")
    generator.export_json(test_results, 'test_report.json')
    
    print("[*] Testing CSV export...")
    generator.export_csv(test_results, 'test_report.csv')
    
    print("[*] Testing PDF export...")
    generator.export_pdf(test_results, 'test_report.pdf')
    
    print("[*] Testing HTML report generation...")
    html_content = generator.generate_html_report(test_results)
    if html_content:
        with open('test_report.html', 'w', encoding='utf-8') as f:
            f.write(html_content)
        print("[+] HTML report generated successfully")