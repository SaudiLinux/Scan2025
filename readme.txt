ISRAELI DOMAIN SECURITY SCANNER
ماسح الأمن الإلكتروني للدومينات الإسرائيلية
==============================================

نظرة عامة:
أداة احترافية لمسح وتحليل الأمن الإلكتروني للدومينات الإسرائيلية،
مخصصة لاكتشاف الثغرات الأمنية وتحليل البنية التحتية للويب الإسرائيلية.

المميزات الرئيسية:
==================
🔍 قدرات المسح:
- اكتشاف الدومينات الإسرائيلية (.il, .co.il, .org.il, .gov.il)
- مسح الثغرات الأمنية (SQL Injection، XSS، LFI، Command Injection، SSRF)
- تحليل الشهادات الأمنية SSL/TLS
- البحث عن الملفات الحساسة

🌍 الدعم اللغوي:
- واجهة عربية كاملة
- تقارير متعددة اللغات (عربية وإنجليزية)
- واجهة سهلة الاستخدام

📊 التقارير والتصدير:
- تقارير PDF احترافية
- تصدير إلى CSV وJSON
- تقارير HTML تفاعلية
- إحصائيات وتحليلات مفصلة

متطلبات النظام:
===============
- Python 3.7 أو أحدث
- نظام تشغيل Windows/Linux/macOS
- اتصال إنترنت نشط
- مساحة قرص 100MB كحد أدنى

طريقة التثبيت:
==============
1. تثبيت Python 3.7+
2. تثبيت المكتبات:
   pip install -r requirements.txt
3. التحقق من التثبيت:
   python IsraeliDomainScanner.py

طريقة الاستخدام:
===============

الواجهة الرسومية (GUI):
python IsraeliDomainScanner.py

سطر الأوامر (CLI):
مسح دومين واحد:
python vulnerability_scanner.py --domain "target.co.il"

اكتشاف دومينات:
python domain_enumerator.py --keyword "mossad" --output "results.json"

تحليل الثغرات المتقدم:
python display_vulnerabilities.py

تحليل ملف نتائج:
python advanced_vulnerability_analyzer.py results.json

أنواع الثغرات المكتشفة:
=======================
1. SQL Injection - حقن قواعد البيانات
2. Cross-Site Scripting (XSS) - سكريبتات عبر المواقع
3. Local File Inclusion (LFI) - تضمين الملفات المحلية
4. Command Injection - حقن الأوامر
5. Server-Side Request Forgery (SSRF) - تزوير الطلبات من الخادم
6. Directory Traversal - تجاوز المسارات
7. SSL/TLS Issues - مشاكل الشهادات الأمنية

تصنيفات الخطورة:
================
- حرج (Critical): ثغرات خطيرة تسمح بالوصول الكامل
- عالي (High): ثغرات خطيرة تتطلب إصلاحًا فوريًا
- متوسط (Medium): ثغرات مهمة يجب إصلاحها
- منخفض (Low): مشاكل بسيطة يُنصح بإصلاحها

الملفات الرئيسية:
=================
IsraeliDomainScanner.py          - الواجهة الرسومية الرئيسية
vulnerability_scanner.py         - ماسح الثغرات الأمنية
domain_enumerator.py            - ماسح الدومينات الإسرائيلية
report_generator.py             - مولد التقارير
scanner_cli.py                  - واجهة سطر الأوامر المتقدمة
display_vulnerabilities.py      - عارض الثغرات المتقدم
advanced_vulnerability_analyzer.py - محلل الثغرات المتقدم
vulnerability_demo.py           - عرض توضيحي للثغرات

أمثلة على الاستخدام:
====================

مثال 1: مسح دومين إسرائيلي
from vulnerability_scanner import IsraeliVulnerabilityScanner
scanner = IsraeliVulnerabilityScanner()
results = scanner.scan_domain("mossad.gov.il")
print(f"تم العثور على {results['total_vulnerabilities']} ثغرة")

مثال 2: تحليل الثغرات المتقدم
python display_vulnerabilities.py

مثال 3: اكتشاف دومينات
python domain_enumerator.py --keyword "idf" --output "domains.json"

التوصيات الأمنية:
=================
- قم بتحديث البرامج بانتظام
- استخدم معايير الأمان الحديثة
- راقب السجلات الأمنية
- نفذ اختبارات اختراق دورية

الأمان والمسؤولية:
===================
⚠️ تحذير: هذه الأداة مخصصة للاختبار الأمني المصرح به فقط.
استخدامها في أنشطة غير قانونية يعرضك للمسؤولية القانونية.

- استخدم فقط على الأنظمة التي تمتلك إذنًا باختبارها
- لا تستخدمها في أنشطة غير قانونية
- احترم قوانين الأمن الإلكتروني المحلية
- احصل على تصاريح رسمية قبل الاختبار

المعلومات والدعم:
=================
المؤلف: SayerLinux
البريد الإلكتروني: SayerLinux1@gmail.com
GitHub: github.com/SayerLinux

للدعم الفني أو الإبلاغ عن المشاكل:
1. افتح issue على GitHub
2. أرسل بريدًا إلكترونيًا مع تفاصيل المشكلة
3. تضمن سجلات الأخطاء إن أمكن

تم التطوير بواسطة SayerLinux - SayerLinux1@gmail.com
هذه الأداة مخصصة لأغراض الأمن الإلكتروني والبحث الأكاديمي.
نحث جميع المستخدمين على استخدامها بمسؤولية واحترام القوانين المحلية والدولية.