#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
أداة متخصصة في البحث في الدومينات الإسرائيلية واستكشاف الثغرات الأمنية
Israeli Domain Security Scanner Tool
المبرمج: SayerLinux
الإيميل: SayerLinux1@gmail.com
"""

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
    TKINTER_AVAILABLE = True
except ImportError:
    print("تحذير: مكتبة tkinter غير متوفرة. سيتم تشغيل وضع سطر الأوامر فقط.")
    TKINTER_AVAILABLE = False

import threading
import time
import json
import csv
from datetime import datetime
import os
import sys

try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except ImportError:
    print("تحذير: مكتبة PIL غير متوفرة. سيتم تعطيل الصور.")
    PIL_AVAILABLE = False

import colorama
from colorama import Fore, Back, Style

# Import scanning modules
try:
    from domain_enumerator import IsraeliDomainEnumerator
    from vulnerability_scanner import IsraeliVulnerabilityScanner
    from report_generator import ReportGenerator
except ImportError as e:
    print(f"خطأ في استيراد الموديولات: {e}")
    print("تأكد من أن جميع الملفات المطلوبة موجودة في نفس المجلد.")
    sys.exit(1)

class IsraeliDomainScanner:
    def __init__(self):
        if not TKINTER_AVAILABLE:
            self.run_cli_mode()
            return
            
        self.setup_gui()
        self.scanner_thread = None
        self.is_scanning = False
        self.results = []
        
    def run_cli_mode(self):
        """وضع سطر الأوامر عندما لا تكون tkinter متوفرة"""
        print(f"{Fore.CYAN}Israeli Domain Security Scanner{Style.RESET_ALL}")
        print(f"{Fore.CYAN}المبرمج: SayerLinux | Email: SayerLinux1@gmail.com{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}تشغيل وضع سطر الأوامر...{Style.RESET_ALL}")
        
        domain = input("أدخل الدومين أو كلمة البحث (مثال: mossad): ").strip()
        if not domain:
            print(f"{Fore.RED}خطأ: يرجى إدخال دومين أو كلمة بحث!{Style.RESET_ALL}")
            return
            
        print(f"\n{Fore.GREEN}بدء الفحص للهدف: {domain}{Style.RESET_ALL}")
        
        try:
            # تشغيل الماسحات المختلفة
            enumerator = IsraeliDomainEnumerator()
            vuln_scanner = IsraeliVulnerabilityScanner()
            
            # اكتشاف الدومينات
            print(f"{Fore.BLUE}جاري اكتشاف الدومينات...{Style.RESET_ALL}")
            domains = enumerator.enumerate_israeli_domains(domain)
            print(f"{Fore.GREEN}تم العثور على {len(domains)} دومين{Style.RESET_ALL}")
            
            # فحص الثغرات
            print(f"{Fore.BLUE}جاري فحص الثغرات...{Style.RESET_ALL}")
            all_vulnerabilities = []
            
            # فحص أول 5 دومينات فقط
            if isinstance(domains, list) and domains:
                domains_to_scan = domains[:5]
            else:
                domains_to_scan = domains if isinstance(domains, list) else []
                
            for domain_info in domains_to_scan:
                domain_name = domain_info.get('domain', '')
                if domain_name:
                    print(f"{Fore.YELLOW}فحص: {domain_name}{Style.RESET_ALL}")
                    vuln_results = vuln_scanner.scan_domain(domain_name)
                    all_vulnerabilities.extend(vuln_results.get('vulnerabilities', []))
            
            # عرض النتائج
            print(f"\n{Fore.GREEN}نتائج الفحص:{Style.RESET_ALL}")
            print(f"إجمالي الثغرات المكتشفة: {len(all_vulnerabilities)}")
            
            if all_vulnerabilities:
                print(f"\n{Fore.RED}الثغرات المكتشفة:{Style.RESET_ALL}")
                for vuln in all_vulnerabilities:
                    severity_color = Fore.RED if vuln.get('severity') == 'critical' else Fore.YELLOW
                    print(f"{severity_color}- {vuln.get('type', 'Unknown')}: {vuln.get('url', 'N/A')}{Style.RESET_ALL}")
            
            # حفظ النتائج
            save_results = input("\nهل تريد حفظ النتائج؟ (نعم/لا): ").strip()
            if save_results.lower() in ['نعم', 'yes', 'y']:
                filename = f"scan_results_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump({
                        'scan_date': datetime.now().isoformat(),
                        'target': domain,
                        'domains_found': len(domains),
                        'vulnerabilities': all_vulnerabilities
                    }, f, ensure_ascii=False, indent=2)
                print(f"{Fore.GREEN}تم حفظ النتائج في: {filename}{Style.RESET_ALL}")
                
        except Exception as e:
            print(f"{Fore.RED}خطأ أثناء الفحص: {e}{Style.RESET_ALL}")
            
        print(f"\n{Fore.CYAN}انتهى الفحص!{Style.RESET_ALL}")
        
    def setup_gui(self):
        self.root = tk.Tk()
        self.root.title("Israeli Domain Security Scanner - SayerLinux")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2c3e50')
        
        # Set window icon
        try:
            self.root.iconbitmap('scanner_icon.ico')
        except:
            pass
            
        # Create main frame
        main_frame = tk.Frame(self.root, bg='#2c3e50')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header with logo and title
        header_frame = tk.Frame(main_frame, bg='#34495e')
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        if PIL_AVAILABLE:
            try:
                logo_img = Image.open("scanner_logo.png")
                logo_img = logo_img.resize((60, 60), Image.Resampling.LANCZOS)
                self.logo = ImageTk.PhotoImage(logo_img)
                logo_label = tk.Label(header_frame, image=self.logo, bg='#34495e')
                logo_label.pack(side=tk.LEFT, padx=10, pady=5)
            except:
                pass
            
        title_frame = tk.Frame(header_frame, bg='#34495e')
        title_frame.pack(side=tk.LEFT, padx=10)
        
        title_label = tk.Label(title_frame, text="Israeli Domain Security Scanner", 
                              font=('Arial', 20, 'bold'), fg='white', bg='#34495e')
        title_label.pack()
        
        subtitle_label = tk.Label(title_frame, text="أداة متخصصة في البحث في الدومينات الإسرائيلية واستكشاف الثغرات الأمنية", 
                                 font=('Arial', 12), fg='#ecf0f1', bg='#34495e')
        subtitle_label.pack()
        
        dev_label = tk.Label(title_frame, text="المبرمج: SayerLinux | Email: SayerLinux1@gmail.com", 
                            font=('Arial', 10), fg='#bdc3c7', bg='#34495e')
        dev_label.pack()
        
        # Control panel
        control_frame = tk.LabelFrame(main_frame, text="إعدادات الفحص", font=('Arial', 12, 'bold'), 
                                     bg='#34495e', fg='white', padx=10, pady=10)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Domain input
        domain_frame = tk.Frame(control_frame, bg='#34495e')
        domain_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(domain_frame, text="الدومين أو كلمة البحث:", font=('Arial', 11), 
                fg='white', bg='#34495e').pack(side=tk.RIGHT, padx=5)
        
        self.domain_entry = tk.Entry(domain_frame, font=('Arial', 11), width=40)
        self.domain_entry.pack(side=tk.RIGHT, padx=5)
        self.domain_entry.insert(0, "example")
        
        # Scan options
        options_frame = tk.Frame(control_frame, bg='#34495e')
        options_frame.pack(fill=tk.X, pady=10)
        
        # Checkboxes for scan types
        self.scan_vars = {}
        scan_types = [
            ("العديد من الدومينات (.il, .co.il, .org.il)", "enumerate_domains"),
            ("فحص ثغرات SQL Injection", "sql_injection"),
            ("فحص ثغرات XSS", "xss"),
            ("فحص الدلائل والملفات", "directory_scan"),
            ("فحص منافذ الشبكة", "port_scan"),
            ("فحص تقنيات الويب", "technology_scan"),
            ("فحص شهادات SSL/TLS", "ssl_scan"),
            ("فحص DNS", "dns_scan")
        ]
        
        for i, (text, var_name) in enumerate(scan_types):
            self.scan_vars[var_name] = tk.BooleanVar(value=True)
            cb = tk.Checkbutton(options_frame, text=text, variable=self.scan_vars[var_name], 
                               font=('Arial', 10), bg='#34495e', fg='white', selectcolor='#2c3e50')
            cb.grid(row=i//2, column=i%2, sticky='w', padx=10, pady=2)
        
        # Buttons frame
        button_frame = tk.Frame(control_frame, bg='#34495e')
        button_frame.pack(fill=tk.X, pady=10)
        
        self.start_button = tk.Button(button_frame, text="ابدأ الفحص", 
                                     command=self.start_scan, bg='#27ae60', fg='white',
                                     font=('Arial', 12, 'bold'), padx=20, pady=5)
        self.start_button.pack(side=tk.RIGHT, padx=5)
        
        self.stop_button = tk.Button(button_frame, text="إيقاف الفحص", 
                                    command=self.stop_scan, bg='#e74c3c', fg='white',
                                    font=('Arial', 12, 'bold'), padx=20, pady=5, state=tk.DISABLED)
        self.stop_button.pack(side=tk.RIGHT, padx=5)
        
        self.export_button = tk.Button(button_frame, text="تصدير النتائج", 
                                      command=self.export_results, bg='#3498db', fg='white',
                                      font=('Arial', 12, 'bold'), padx=20, pady=5)
        self.export_button.pack(side=tk.LEFT, padx=5)
        
        # Progress frame
        progress_frame = tk.Frame(control_frame, bg='#34495e')
        progress_frame.pack(fill=tk.X, pady=5)
        
        self.progress_var = tk.StringVar(value="جاهز للفحص...")
        self.progress_label = tk.Label(progress_frame, textvariable=self.progress_var, 
                                      font=('Arial', 10), fg='#ecf0f1', bg='#34495e')
        self.progress_label.pack(side=tk.RIGHT)
        
        self.progress_bar = ttk.Progressbar(progress_frame, mode='indeterminate', length=200)
        self.progress_bar.pack(side=tk.LEFT, padx=5)
        
        # Results display
        results_frame = tk.LabelFrame(main_frame, text="نتائج الفحص", font=('Arial', 12, 'bold'), 
                                     bg='#34495e', fg='white', padx=10, pady=10)
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create scrolled text widget for results
        self.results_text = tk.Text(results_frame, height=20, width=80, font=('Courier', 10),
                                   bg='#2c3e50', fg='white', insertbackground='white')
        
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_text.yview)
        self.results_text.configure(yscrollcommand=scrollbar.set)
        
        self.results_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Status bar
        self.status_bar = tk.Label(self.root, text="جاهز", bd=1, relief=tk.SUNKEN, anchor=tk.W,
                                  bg='#34495e', fg='white')
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def log_message(self, message, message_type="info"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        colors = {
            "info": "#3498db",
            "success": "#27ae60", 
            "warning": "#f39c12",
            "error": "#e74c3c",
            "vulnerability": "#e74c3c"
        }
        
        self.results_text.insert(tk.END, f"[{timestamp}] ", colors.get(message_type, "white"))
        self.results_text.insert(tk.END, f"{message}\n", colors.get(message_type, "white"))
        self.results_text.see(tk.END)
        self.root.update_idletasks()
        
    def start_scan(self):
        if self.is_scanning:
            messagebox.showwarning("تحذير", "الفحص قيد التشغيل بالفعل!")
            return
            
        domain = self.domain_entry.get().strip()
        if not domain:
            messagebox.showerror("خطأ", "يرجى إدخال دومين أو كلمة بحث!")
            return
            
        self.is_scanning = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results = []
        
        self.log_message(f"بدء الفحص للهدف: {domain}", "info")
        self.progress_bar.start()
        
        # Start scanning in separate thread
        self.scanner_thread = threading.Thread(target=self.run_scan, args=(domain,))
        self.scanner_thread.daemon = True
        self.scanner_thread.start()
        
    def stop_scan(self):
        if not self.is_scanning:
            return
            
        self.is_scanning = False
        self.log_message("تم إيقاف الفحص", "warning")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress_bar.stop()
        
    def run_scan(self, target):
        try:
            # Domain enumeration
            if self.scan_vars["enumerate_domains"].get():
                self.progress_var.set("جاري تعداد الدومينات الإسرائيلية...")
                enumerator = IsraeliDomainEnumerator()
                domains = enumerator.enumerate_israeli_domains(target)
                
                if domains:
                    self.log_message(f"تم العثور على {len(domains)} دومين إسرائيلي", "success")
                    
                    # Scan each domain for vulnerabilities
                    scanner = IsraeliVulnerabilityScanner()
                    
                    for i, domain in enumerate(domains):
                        if not self.is_scanning:
                            break
                            
                        self.progress_var.set(f"فحص الدومين {i+1}/{len(domains)}: {domain}")
                        self.log_message(f"فحص الدومين: {domain}", "info")
                        
                        domain_results = {
                            'domain': domain,
                            'scan_time': datetime.now().isoformat(),
                            'vulnerabilities': []
                        }
                        
                        # Run vulnerability scans
                        if self.scan_vars["sql_injection"].get():
                            sql_results = scanner.scan_sql_injection(domain)
                            if sql_results:
                                domain_results['vulnerabilities'].extend(sql_results)
                                self.log_message(f"تم العثور على {len(sql_results)} ثغرة SQL Injection", "vulnerability")
                                
                        if self.scan_vars["xss"].get():
                            xss_results = scanner.scan_xss(domain)
                            if xss_results:
                                domain_results['vulnerabilities'].extend(xss_results)
                                self.log_message(f"تم العثور على {len(xss_results)} ثغرة XSS", "vulnerability")
                                
                        if self.scan_vars["directory_scan"].get():
                            dir_results = scanner.scan_directories(domain)
                            if dir_results:
                                domain_results['vulnerabilities'].extend(dir_results)
                                self.log_message(f"تم العثور على {len(dir_results)} دليل/ملف حساس", "vulnerability")
                                
                        if self.scan_vars["port_scan"].get():
                            port_results = scanner.scan_ports(domain)
                            if port_results:
                                domain_results['vulnerabilities'].extend(port_results)
                                self.log_message(f"تم العثور على {len(port_results)} منفذ مفتوح", "warning")
                                
                        if self.scan_vars["technology_scan"].get():
                            tech_results = scanner.scan_technologies(domain)
                            if tech_results:
                                domain_results['technologies'] = tech_results
                                self.log_message(f"تم التعرف على {len(tech_results)} تقنية ويب", "info")
                                
                        if self.scan_vars["ssl_scan"].get():
                            ssl_results = scanner.scan_ssl(domain)
                            if ssl_results:
                                domain_results['ssl_info'] = ssl_results
                                self.log_message("تم فحص شهادة SSL/TLS", "info")
                                
                        if self.scan_vars["dns_scan"].get():
                            dns_results = scanner.scan_dns(domain)
                            if dns_results:
                                domain_results['dns_info'] = dns_results
                                self.log_message("تم فحص معلومات DNS", "info")
                        
                        self.results.append(domain_results)
                        
            else:
                # Single domain scan
                self.log_message(f"فحص الدومين المحدد: {target}", "info")
                scanner = IsraeliVulnerabilityScanner()
                
                domain_results = {
                    'domain': target,
                    'scan_time': datetime.now().isoformat(),
                    'vulnerabilities': []
                }
                
                # Run selected vulnerability scans
                if self.scan_vars["sql_injection"].get():
                    sql_results = scanner.scan_sql_injection(target)
                    if sql_results:
                        domain_results['vulnerabilities'].extend(sql_results)
                        self.log_message(f"تم العثور على {len(sql_results)} ثغرة SQL Injection", "vulnerability")
                        
                if self.scan_vars["xss"].get():
                    xss_results = scanner.scan_xss(target)
                    if xss_results:
                        domain_results['vulnerabilities'].extend(xss_results)
                        self.log_message(f"تم العثور على {len(xss_results)} ثغرة XSS", "vulnerability")
                        
                if self.scan_vars["directory_scan"].get():
                    dir_results = scanner.scan_directories(target)
                    if dir_results:
                        domain_results['vulnerabilities'].extend(dir_results)
                        self.log_message(f"تم العثور على {len(dir_results)} دليل/ملف حساس", "vulnerability")
                        
                if self.scan_vars["port_scan"].get():
                    port_results = scanner.scan_ports(target)
                    if port_results:
                        domain_results['vulnerabilities'].extend(port_results)
                        self.log_message(f"تم العثور على {len(port_results)} منفذ مفتوح", "warning")
                        
                if self.scan_vars["technology_scan"].get():
                    tech_results = scanner.scan_technologies(target)
                    if tech_results:
                        domain_results['technologies'] = tech_results
                        self.log_message(f"تم التعرف على {len(tech_results)} تقنية ويب", "info")
                        
                if self.scan_vars["ssl_scan"].get():
                    ssl_results = scanner.scan_ssl(target)
                    if ssl_results:
                        domain_results['ssl_info'] = ssl_results
                        self.log_message("تم فحص شهادة SSL/TLS", "info")
                        
                if self.scan_vars["dns_scan"].get():
                    dns_results = scanner.scan_dns(target)
                    if dns_results:
                        domain_results['dns_info'] = dns_results
                        self.log_message("تم فحص معلومات DNS", "info")
                
                self.results.append(domain_results)
            
            self.log_message("اكتمل الفحص بنجاح!", "success")
            
        except Exception as e:
            self.log_message(f"حدث خطأ أثناء الفحص: {str(e)}", "error")
            
        finally:
            self.is_scanning = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.progress_bar.stop()
            self.progress_var.set("اكتمل الفحص")
            
    def export_results(self):
        if not self.results:
            messagebox.showwarning("تحذير", "لا توجد نتائج للتصدير!")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("CSV files", "*.csv"), ("PDF files", "*.pdf"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                generator = ReportGenerator()
                
                if file_path.endswith('.json'):
                    generator.export_json(self.results, file_path)
                elif file_path.endswith('.csv'):
                    generator.export_csv(self.results, file_path)
                elif file_path.endswith('.pdf'):
                    generator.export_pdf(self.results, file_path)
                else:
                    generator.export_json(self.results, file_path)
                    
                messagebox.showinfo("نجاح", f"تم تصدير النتائج إلى: {file_path}")
                self.log_message(f"تم تصدير النتائج إلى: {file_path}", "success")
                
            except Exception as e:
                messagebox.showerror("خطأ", f"فشل تصدير النتائج: {str(e)}")
                self.log_message(f"فشل تصدير النتائج: {str(e)}", "error")
                
    def run(self):
        if TKINTER_AVAILABLE:
            self.root.mainloop()
        else:
            # وضع سطر الأوامر تم تشغيله بالفعل في __init__
            pass

if __name__ == "__main__":
    colorama.init()
    try:
        app = IsraeliDomainScanner()
        app.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}تم إيقاف البرنامج بواسطة المستخدم.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}خطأ غير متوقع: {e}{Style.RESET_ALL}")
        sys.exit(1)