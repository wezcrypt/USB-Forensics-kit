# WezCrypt USB Forensics Kit

<div dir="rtl">

**أداة احترافية محمولة لجمع وتحليل الأدلة الجنائية الرقمية من أجهزة Windows، تعمل مباشرة من ذاكرة USB دون تثبيت.**

| البند | القيمة |
|---|---|
| اسم البرنامج | WezCrypt USB Forensics Kit |
| الإصدار | 1.0.0 |
| المطوّر | wezcrypt |
| الموقع الرسمي | https://wezcrypt.com |
| التصنيف | Digital Forensics & Incident Response (DFIR) |
| أنظمة التشغيل المستهدفة | Windows 10 / Windows 11 (x64) |
| لغة البرمجة | Python 3.12+ |
| الواجهات | واجهة رسومية GUI + واجهة أوامر CLI |
| الترخيص | MIT |

> ⚠️ **تنبيه قانوني:** استخدم الأداة فقط على الأجهزة التي تملك تصريحًا رسميًا بفحصها. تطلب الأداة تأكيد التصريح قبل كل عملية جمع، وتسجّل كل الإجراءات في سجل سلسلة الحيازة (Chain of Custody).

---

## المحتويات

1. [نظرة عامة](#overview)
2. [المزايا](#features)
3. [ضمانات الخصوصية وسلامة الأدلة](#guarantees)
4. [البنية المعمارية](#architecture)
5. [التشغيل السريع من USB](#quickstart)
6. [بناء النسخة المحمولة (EXE)](#build)
7. [التشغيل من الشيفرة المصدرية](#source)
8. [الواجهة الرسومية](#gui)
9. [واجهة الأوامر CLI](#cli)
10. [وحدات الجمع والصلاحيات](#modules)
11. [هيكل مجلد الجلسة](#layout)
12. [محرك التحليل](#analysis)
13. [التقارير](#reports)
14. [الإعدادات](#settings)
15. [العمليات التي تُجرى على النظام الحي](#live)
16. [الاختبارات](#tests)
17. [القيود المعروفة](#limits)
18. [حل المشكلات](#troubleshooting)
19. [الترخيص والأمان](#license)

---

<a id="overview"></a>
## 1. نظرة عامة

WezCrypt USB Forensics Kit أداة تحقيق جنائي رقمي متكاملة تقوم بـ:

1. **جمع الأدلة** من أجهزة Windows (سجلات الأحداث، Prefetch، Amcache، Shimcache، UserAssist، ShellBags، Jump Lists، LNK، الملفات الحديثة، تاريخ أجهزة USB، الريجستري، المهام المجدولة، الخدمات، برامج بدء التشغيل، البرامج المثبتة، العمليات الجارية، حالة الشبكة، نظام الملفات، سلة المحذوفات، والمتصفحات الخمسة).
2. **تحليل** نشاط النظام والمستخدم وربط الأحداث من مصادر متعددة.
3. **إنشاء خط زمني موحّد** مرتب زمنيًا بتوقيت UTC.
4. **اكتشاف مؤشرات الاختراق** وتصنيف النتائج حسب الخطورة مع ذكر الدليل الذي بُنيت عليه كل نتيجة.
5. **حفظ الأدلة** مع ضمان سلامتها عبر SHA-256 وملف Manifest وسجل حيازة مُسلسَل بالهاش.
6. **إصدار تقارير** بصيغ HTML وPDF وJSON وCSV.

---

<a id="features"></a>
## 2. المزايا

- **محمولة بالكامل:** بناء ONEDIR يعمل من الفلاشة مباشرة، دون تثبيت Python أو أي مكتبة على الجهاز المفحوص، ودون فك ملفات إلى `%TEMP%` (بخلاف بناء ONEFILE الذي يكتب على قرص الجهاز المفحوص).
- **اكتشاف مسار الفلاشة تلقائيًا** ونوع القرص (Removable/Fixed) مع تحذير إذا كان الإخراج على قرص النظام.
- **مجلد مستقل لكل جلسة** باسم يتضمن رقم القضية واسم الجهاز والوقت UTC ومعرّف UUID.
- **يعمل بصلاحيات المستخدم العادي أو المسؤول**، ويوضّح الأدلة التي تتطلب Administrator ويسجّل ما تعذّر جمعه بسبب الصلاحيات.
- **معالجة متوازية** للوحدات (قابلة للضبط 1–16)، مع عزل الأعطال: فشل وحدة لا يوقف بقية الوحدات.
- **إلغاء آمن** في أي لحظة: تُحذف النسخ الجزئية، ويُحسب Manifest لما جُمع فعلًا.
- **دعم الأسماء العربية والمسارات الطويلة** (`\\?\` على Windows)، وتقارير CSV بترميز UTF-8 مع BOM لتفتح في Excel بشكل صحيح، وPDF يدعم تشكيل النص العربي.
- **العمل دون اتصال بالإنترنت** بالكامل، بما في ذلك تقارير HTML.

---

<a id="guarantees"></a>
## 3. ضمانات الخصوصية وسلامة الأدلة

### الخصوصية (مفروضة في الشيفرة وليست إعدادًا اختياريًا)

- **لا يتم** قراءة أو استخراج كلمات المرور، أو قيم الكوكيز، أو رموز الجلسات، أو بيانات الملء التلقائي/البطاقات (`Login Data` و`Web Data` لا تُفتح أبدًا).
- من قواعد الكوكيز تُستخرج **البيانات الوصفية فقط** (المضيف، الاسم، المسار، أوقات الإنشاء/الوصول/الانتهاء، Secure/HttpOnly). أعمدة `value` و`encrypted_value` لا تُقرأ، وقاعدة الكوكيز نفسها **لا تُحفظ** ضمن الأدلة (لأنها تحوي قيمًا مشفرة)، بل تُنسخ إلى مجلد عمل مؤقت يُحذف فورًا.
- خلايا الريجستري **SAM** و**SECURITY** لا تُصدَّر أبدًا.
- لا رفع صلاحيات ولا تجاوز لـ UAC أو لصلاحيات Windows. الرفع يتم فقط عبر نافذة UAC الرسمية (`Run_as_Administrator.bat`).

### سلامة الأدلة

| الآلية | التفاصيل |
|---|---|
| نسخ للقراءة فقط | يُفتح المصدر للقراءة فقط؛ لا يُعدَّل أي ملف أصلي. |
| هاش أثناء النسخ | يُحسب SHA-256 للبيانات أثناء قراءتها، ثم يُعاد حساب هاش النسخة ومقارنته (أي اختلاف = خطأ سلامة). |
| عدم الكتابة فوق الأدلة | الوجهة تُفتح بنمط `x` (إنشاء حصري)، والأسماء المكررة تأخذ لاحقة رقمية. |
| Evidence Manifest | `manifest.json` يضم هاش وحجم كل ملف في `evidence/` و`parsed/` مع المصدر الأصلي وطريقة الجمع، و`manifest.sha256` يحمي ملف الـ Manifest نفسه. |
| Chain of Custody | `chain_of_custody.jsonl`: كل قيد يحتوي هاش القيد السابق (Hash Chain)، فأي تعديل أو حذف لقيد يُكتشف عند التحقق. |
| التوقيت | كل الأوقات بصيغة ISO-8601 UTC. الأوقات التي لا يخزّن مصدرها منطقة زمنية (مثل setupapi وأوقات DOS في ShellBags) تُعلَّم صراحة. |
| معرّف الجلسة | UUID فريد لكل جلسة + إصدار الأداة + حساب الفاحص + حالة الصلاحيات. |
| توثيق الأخطاء | `logs/errors.json`: كل ملف تعذّر الوصول إليه مع السبب (`locked` / `access_denied` / `requires_admin` / `not_found` / `error`). |
| التحقق بعد الجمع | يُعاد حساب كل الهاشات تلقائيًا بعد الجمع وتُسجَّل النتيجة في سجل الحيازة. |
| الجمع الحي | كل عملية قد تؤثر على حالة النظام تُوثَّق في `logs/live_actions.json` وفي التقرير. |

---

<a id="architecture"></a>
## 4. البنية المعمارية

```
WezCryptUFK.py                 نقطة الدخول (PyInstaller)
wezcrypt_ufk/
├── cli.py                     واجهة الأوامر (argparse)
├── core/                      النواة
│   ├── orchestrator.py        تشغيل الجلسة: جمع متوازٍ ← Manifest ← تحقق ← تحليل ← تقارير
│   ├── context.py             سياق الوحدة: نسخ الأدلة، كتابة السجلات JSONL، الخط الزمني، الأخطاء، الإلغاء
│   ├── acquire.py             نسخ آمن مع هاش وتحقق ومعالجة الملفات المقفلة
│   ├── integrity.py           إنشاء/التحقق من Manifest
│   ├── custody.py             سجل سلسلة الحيازة المُسلسَل بالهاش
│   ├── session.py             الجلسة: UUID، هيكل المجلدات، session.json
│   ├── winapi.py              ctypes: IsUserAnAdmin، GetDriveType، ADS، معلومات NTFS، فك ضغط MAM
│   ├── commands.py            تشغيل أدوات System32 بمسار مطلق ومهلة زمنية
│   ├── config.py / paths.py / timeutil.py / hashing.py / logging_setup.py / models.py
├── parsers/                   محللات صيغ الأدلة (مستقلة عن المنصة وقابلة للاختبار)
│   ├── registry.py            محلل خلايا REGF دون اتصال + واجهة موحدة للريجستري الحي
│   ├── winreg_artifacts.py    UserAssist, ShellBags, Shimcache, USB, Run keys, Services, Apps, Amcache, MRU
│   ├── shellitems.py  lnk.py  jumplist.py (OLE/CFB + DestList)  prefetch.py  recyclebin.py
│   ├── evtx_xml.py            محلل XML متدفق لأحداث Windows
│   ├── browsers.py            Chromium/Firefox: السجل، التنزيلات، المفضلة، الإضافات، كوكيز (بيانات وصفية)، الكاش
│   └── pe.py  tasks.py  setupapi.py
├── collectors/                وحدات الجمع (25 وحدة) — كل وحدة صنف مستقل مسجَّل تلقائيًا
├── analysis/                  محرك التحليل: الخط الزمني، القواعد، المؤشرات، الملخص والتوصيات
├── reporting/                 HTML (دون اتصال) / PDF / JSON / CSV
└── gui/                       واجهة Tkinter (الهوية البصرية: كحلي/فحمي + نحاسي)
tests/                         58 اختبارًا آليًا ببيانات صناعية
packaging/                     ملف PyInstaller spec، معلومات الإصدار، سكربتات مساعدة
build.bat                      بناء النسخة المحمولة بأمر واحد
```

**مبدأ التوسّع:** لإضافة وحدة جديدة أنشئ صنفًا يرث `Collector` وزيّنه بـ `@register` داخل `collectors/`؛ يظهر تلقائيًا في الواجهة الرسومية وCLI والتقارير. ولإضافة قاعدة تحليل أضف دالة مزينة بـ `@rule` في `analysis/rules.py`.

**مسار البيانات:**

```
المصدر (قراءة فقط) ──نسخ+SHA-256──> evidence/<module>/   (الدليل الأصلي محفوظ)
          │
          └──تحليل النسخة──> parsed/<module>/<artifact>.jsonl + _timeline.jsonl
                                     │
manifest.json  <──هاش evidence+parsed─┘
                                     │
analysis/timeline.jsonl, findings.json, observables.json, summary.json
                                     │
reports/report.html, report.pdf, report.json, csv/, browsers/<browser>.html
```

---

<a id="quickstart"></a>
## 5. التشغيل السريع من USB

1. ابنِ النسخة المحمولة مرة واحدة على جهاز الفاحص (انظر القسم 6)، أو استخدم نسخة جاهزة.
2. انسخ مجلد `dist\WezCryptUFK\` **بالكامل** إلى الفلاشة.
3. (موصى به) تحقق من سلامة الأداة نفسها بمقارنة `SHA256SUMS.txt`.
4. على الجهاز المفحوص:
   - للجمع الكامل: شغّل `Run_as_Administrator.bat` (يظهر طلب UAC الرسمي).
   - أو شغّل `WezCryptUFK.exe` كمستخدم عادي (جمع محدود وموثّق).
5. في صفحة **Evidence Collection** اختر الأدلة، أدخل رقم القضية واسم الفاحص، أكّد التصريح، ثم **Start collection**.
6. تُحفظ النتائج في `<الفلاشة>\WezCryptUFK\WezCrypt_Cases\<الجلسة>\`.

**محتوى الفلاشة بعد البناء:**

```
E:\WezCryptUFK\
├── WezCryptUFK.exe            الواجهة الرسومية
├── WezCryptUFK-cli.exe        واجهة الأوامر
├── _internal\                 بيئة Python والمكتبات (مضمّنة)
├── Run_as_Administrator.bat
├── examples\iocs_example.txt
├── README.md  LICENSE  CHANGELOG.md  SECURITY.md
├── SHA256SUMS.txt
├── wezcrypt_config.json       (يُنشأ عند حفظ الإعدادات)
├── WezCrypt_Cases\            جلسات التحقيق
└── WezCrypt_Logs\             سجل التطبيق
```

---

<a id="build"></a>
## 6. بناء النسخة المحمولة (EXE)

**المتطلبات على جهاز البناء فقط:** Windows 10/11 x64 + Python 3.12 أو أحدث (64-bit) من python.org.

```bat
build.bat            :: تثبيت المتطلبات في بيئة معزولة + تشغيل الاختبارات + البناء
build.bat notest     :: البناء دون تشغيل الاختبارات
```

يقوم `build.bat` بـ:
1. التحقق من إصدار Python ومعماريته.
2. إنشاء بيئة افتراضية `.venv-build` وتثبيت `requirements.txt` و`requirements-dev.txt`.
3. تشغيل الاختبارات (`pytest`) وإيقاف البناء عند فشلها.
4. البناء عبر `packaging\WezCryptUFK.spec` (ملفان تنفيذيان يتشاركان بيئة واحدة).
5. نسخ الوثائق والملفات المساعدة.
6. إنشاء `SHA256SUMS.txt` لكل ملفات الأداة.

الناتج: `dist\WezCryptUFK\` — هذا هو المجلد الذي يُنسخ إلى الفلاشة.

---

<a id="source"></a>
## 7. التشغيل من الشيفرة المصدرية (للتطوير)

```bat
py -3.12 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
python -m wezcrypt_ufk            :: الواجهة الرسومية
python -m wezcrypt_ufk --help     :: واجهة الأوامر
python -m pytest                  :: الاختبارات
```

المكتبات الخارجية: `psutil` (العمليات والشبكة)، `reportlab` (PDF)، `arabic-reshaper` و`python-bidi` (العربية في PDF). كل ما عداها من مكتبة Python القياسية (tkinter, sqlite3, ctypes, winreg, xml).

---

<a id="gui"></a>
## 8. الواجهة الرسومية

| الصفحة | الوظيفة |
|---|---|
| **Dashboard** | حالة الصلاحيات، نوع قرص الأداة، المساحة الحرة، عدد الجلسات، إحصائيات خطورة الجلسة المحمّلة، التحذيرات، وقائمة الجلسات مع تحميل/فتح المجلد/فتح التقرير. |
| **Evidence Collection** | رقم القضية، الفاحص، ملاحظات/مرجع التصريح، اختيار الوحدات حسب الفئة مع علامة `[A]` (تتطلب مسؤولًا) و`[a]` (المسؤول يعطي بيانات أكمل)، اختيار صيغ التقارير، وتأكيد التصريح الإلزامي. |
| **Live Progress** | شريط تقدم إجمالي، حالة ونسبة كل وحدة، عدد الملفات والأخطاء، سجل حي، وزر إلغاء آمن. |
| **Evidence Explorer** | شجرة الوحدات والأدلة مع عدد السجلات، جدول قابل للتصفية والفرز، وعرض JSON كامل للسجل المحدد. |
| **Timeline Analysis** | الخط الزمني الموحد مع بحث نصي، تصفية حسب المصدر، ونطاق زمني (UTC)، وتصدير النتائج المصفاة إلى CSV. |
| **Hash Verification** | إعادة حساب هاشات الجلسة ومقارنتها بالـ Manifest، كشف الملفات المعدّلة/المفقودة/الدخيلة، التحقق من سلسلة الحيازة، وحساب SHA-256 لأي ملف (يُنسخ للحافظة). كل تحقق يُسجَّل في سجل الحيازة. |
| **Report Generator** | إعادة التحليل (اختياريًا مع ملف IOC)، توليد الصيغ المختارة، عرض هاش كل تقرير وفتحه. |
| **Settings** | كل الإعدادات (الإخراج، الحدود، مسارات الفحص، التحقق من التواقيع، VSS...) تُحفظ بجانب الأداة. |
| **About** | معلومات البرنامج والمطوّر. |

---

<a id="cli"></a>
## 9. واجهة الأوامر CLI

```bat
WezCryptUFK-cli.exe about
WezCryptUFK-cli.exe info                         :: الصلاحيات، مسار الأداة ونوع القرص، مجلد الإخراج
WezCryptUFK-cli.exe list-modules [--json]

:: جمع كامل مع كل التقارير
WezCryptUFK-cli.exe collect --case-id IR-2026-014 --examiner "Analyst" --notes "Auth #A-77" --yes

:: وحدات محددة، إخراج مخصص، ملف IOC، استخدام VSS للملفات المقفلة
WezCryptUFK-cli.exe collect -m event_logs,prefetch,amcache,browser_chrome -o F:\Cases --ioc-file F:\iocs.txt --vss --yes

:: كل الوحدات عدا بعضها، دون تقارير PDF
WezCryptUFK-cli.exe collect --exclude filesystem,recycle_bin -f html,json,csv --yes

WezCryptUFK-cli.exe verify  "E:\WezCryptUFK\WezCrypt_Cases\<session>"    :: التحقق من السلامة
WezCryptUFK-cli.exe analyze "<session>" --ioc-file iocs.txt               :: إعادة التحليل
WezCryptUFK-cli.exe report  "<session>" -f html,pdf                       :: إعادة توليد التقارير
WezCryptUFK-cli.exe sessions                                              :: قائمة الجلسات
```

خيارات عامة: `--config <file>` و`-v/--verbose` و`--debug`. الضغط على `Ctrl+C` أثناء الجمع يلغي بأمان.

**رموز الخروج:** `0` نجاح، `1` خطأ، `2` فشل التحقق من السلامة، `130` أُلغي.

---

<a id="modules"></a>
## 10. وحدات الجمع والصلاحيات

`no` = لا يحتاج مسؤولًا · `partial` = يعمل كمستخدم عادي ببيانات أقل · `yes` = يتطلب Administrator

| الوحدة | الاسم | الصلاحية | ما يُجمع |
|---|---|---|---|
| Windows Event Logs | `event_logs` | partial | تصدير `wevtutil epl` لـ 15 قناة (Security, System, Application, PowerShell, TaskScheduler, RDP, Defender, DriverFrameworks, Kernel-PnP, Partition, WLAN, BITS, Sysmon) ثم تحليل معرّفات الأحداث الجنائية من النسخة المُصدَّرة. Security وSysmon تتطلبان مسؤولًا. |
| Prefetch | `prefetch` | yes | نسخ `*.pf` وتحليل الإصدارات 17/23/26/30 (Win10/11 المضغوطة MAM عبر `ntdll`): عدد مرات التشغيل، آخر 8 أوقات تشغيل، الملفات المحمّلة، المجلدات. |
| Amcache | `amcache` | yes | نسخ `Amcache.hve` المقفل عبر `esentutl /y /vss` وتحليل InventoryApplicationFile (المسار، SHA-1، الناشر) وInventoryApplication. |
| Shimcache | `shimcache` | partial | AppCompatCache من خلية SYSTEM (المسار، وقت تعديل الملف، الترتيب). |
| UserAssist | `userassist` | partial | تشغيل البرامج عبر الواجهة لكل مستخدم (فك ROT13، العدد، زمن التركيز، آخر تشغيل). |
| ShellBags | `shellbags` | partial | المجلدات التي تُصفّحت (NTUSER وUsrClass) بما فيها مجلدات USB والشبكة والمحذوفة. |
| Jump Lists | `jump_lists` | partial | AutomaticDestinations (قارئ OLE + DestList) وCustomDestinations. |
| LNK Files | `lnk_files` | partial | اختصارات Recent وOffice Recent وسطح المكتب: الهدف، أوقات MAC، رقم المجلد التسلسلي، نوع القرص، معرّف الجهاز وMAC. |
| Recent Files & MRU | `recent_files` | partial | RecentDocs، RunMRU، TypedPaths. |
| USB Device History | `usb_history` | partial | USBSTOR وUSB (أول تثبيت/آخر توصيل/آخر فصل)، أسماء المجلدات، MountedDevices، MountPoints2، وsetupapi.dev.log. |
| Windows Registry Hives | `registry` | partial | تصدير SYSTEM وSOFTWARE وNTUSER/UsrClass لكل مستخدم (`reg save`) كأدلة مُهَشّة. بدون صلاحيات: قراءة الريجستري الحي للمستخدم الحالي. |
| Scheduled Tasks | `scheduled_tasks` | partial | ملفات `System32\Tasks` (مسؤول) أو `schtasks /query /xml` (مستخدم عادي). |
| Windows Services | `services` | no | إعدادات الخدمات من SYSTEM مع الحالة الحية. |
| Startup Programs | `startup_programs` | partial | Run/RunOnce (HKLM/HKCU/WOW64)، حالة StartupApproved، Winlogon، AppInit_DLLs، IFEO Debugger، مجلدات Startup. |
| Installed Applications | `installed_apps` | no | مفاتيح Uninstall (64/32-bit ولكل مستخدم). |
| Running Processes | `processes` | partial | العمليات مع الأب، سطر الأوامر، المالك، SHA-256 للملف التنفيذي، وحالة التوقيع الرقمي. |
| Network Analysis | `network` | partial | اتصالات TCP/UDP والمنافذ المفتوحة مع العملية المالكة، DNS Cache، ARP، Routing، المحولات، عناوين IP، ملفات وقواعد Windows Firewall. |
| File System Analysis | `filesystem` | partial | مسح مجلدات عالية القيمة (قابلة للتعديل): أوقات MACB، سمات NTFS ورقم سجل MFT، SHA-256، ADS (مع Zone.Identifier ومصدر التنزيل)، معلومات PE، التوقيع الرقمي، مؤشرات الملفات المشبوهة. |
| Recycle Bin | `recycle_bin` | partial | ملفات `$I` (المسار الأصلي، الحجم، وقت الحذف) لكل الأقراص الثابتة. |
| Google Chrome / Microsoft Edge / Brave / Opera / Mozilla Firefox | `browser_*` | partial | السجل، التنزيلات، المفضلة، الإضافات، البيانات الوصفية للكوكيز (دون القيم)، فهرس ذاكرة التخزين المؤقت، لكل مستخدم ولكل ملف تعريف. |
| System Information | `system_info` | no | هوية الجهاز، إصدار Windows، المنطقة الزمنية، وقت الإقلاع، المستخدمون المتصلون، الأقراص، مرجع الساعة. |

**الملفات المقفلة:** تُفتح أولًا للقراءة، ثم بمشاركة كاملة (`FILE_SHARE_READ|WRITE|DELETE`). سجلات الأحداث تُصدَّر عبر خدمة السجل، والخلايا عبر `reg save`، وAmcache عبر `esentutl /vss`. لقواعد المتصفحات المقفلة يمكن تفعيل `use_vss_for_locked` (مسؤول). ما يتعذر نسخه يُسجَّل كـ `locked` مع توصية.

---

<a id="layout"></a>
## 11. هيكل مجلد الجلسة

```
WezCrypt_Cases\IR-2026-014_WS-FIN01_20261009T101500Z_1a2b3c4d\
├── session.json                معلومات الجلسة، نتائج الوحدات، لقطة الإعدادات، هاش الـ Manifest
├── chain_of_custody.jsonl      سجل الحيازة المُسلسَل بالهاش
├── manifest.json               SHA-256 لكل ملف في evidence\ وparsed\
├── manifest.sha256             هاش ملف الـ Manifest
├── evidence\<module>\...       النسخ الأصلية للأدلة (لا تُعدَّل)
├── parsed\<module>\*.jsonl     السجلات المحللة + _timeline.jsonl
├── analysis\                   timeline.jsonl, findings.json, observables.json, summary.json
├── reports\                    report.html, report.pdf, report.json, report_hashes.json
│   ├── browsers\browser_chrome.html ...   تقرير مستقل لكل متصفح
│   └── csv\                    findings, timeline, evidence_hashes, errors, modules, observables, live_actions, artifacts\*.csv
└── logs\                       collection.log, errors.json, live_actions.json, acquired_files.json
```

---

<a id="analysis"></a>
## 12. محرك التحليل

القاعدة الأساسية: **كل نتيجة مرفقة بالأدلة التي بُنيت عليها**، والخطورة تعكس قوة المؤشر لا حكمًا نهائيًا، ولا يُوصف نشاط بأنه خبيث دون مؤشرات كافية.

| القاعدة | الوصف | الخطورة |
|---|---|---|
| LOG-001 | مسح سجلات الأحداث (1102/104) | high |
| AUTH-001 | محاولات دخول فاشلة متكررة ضمن نافذة زمنية (قابلة للضبط) — ترتفع إذا تبعها دخول ناجح من المصدر نفسه | medium/high |
| AUTH-002 | دخول RDP — ترتفع عند مصدر IP عام | info/medium |
| ACCT-001/002 | إنشاء حسابات / إضافة عضو لمجموعة Administrators | medium/high |
| PERS-001..005 | تثبيت خدمات من مسارات قابلة للكتابة، Winlogon/AppInit/IFEO غير افتراضية، Run keys ومهام مجدولة مشبوهة أو مخفية | info–high |
| AV-001/002 | اكتشافات Defender وتعطيل الحماية | high/medium |
| CMD-* | 15 نمطًا لسطور أوامر مشبوهة (PowerShell المشفّر، التنزيل والتنفيذ، certutil، mshta، rundll32، regsvr32، حذف Shadow Copies، أدوات سرقة بيانات الاعتماد، العبث بـ Defender، مسح السجلات...) من العمليات و4688 وSysmon و4104 والمهام والخدمات | medium–critical |
| PROC-001..003 | انتحال أسماء عمليات النظام أو آباء غير متوقعين، عمليات غير موقعة من مسارات قابلة للكتابة لديها اتصالات شبكة | low–high |
| NET-001/002 | منافذ أدوات التحكم عن بعد، منافذ استماع لبرامج من مسارات قابلة للكتابة | medium |
| EXEC-001 | تشغيل برامج من Downloads/Temp/AppData (Prefetch/UserAssist/Amcache) | low |
| USB-001/002 | أجهزة تخزين USB، وملفات فُتحت من وسائط قابلة للإزالة | info/low |
| WEB-000..002 | تنزيلات تنفيذية، تنزيلات وصفها المتصفح بالخطرة، **ربط**: ملف نُزّل ثم شُغّل لاحقًا | info/medium |
| FILE-001..003 | امتداد مزدوج، حرف RTLO، توقيع رقمي تالف، PE بامتداد مضلل، ADS غير معياري... | low–high |
| IOC-001 | تطابق مع قائمة IOC يقدمها الفاحص (هاشات/IP/نطاقات) | critical |

إضافة لذلك يُنتج المحرك: خطًا زمنيًا موحدًا (دمج k-way بذاكرة محدودة)، قائمة **Observables** (روابط، عناوين IP عامة، هاشات) للإثراء، **ملخصًا تنفيذيًا**، و**توصيات فنية** مبنية على النتائج الفعلية وعلى أخطاء الجمع (مثلًا: إعادة التشغيل كمسؤول).

**ملف IOC:** سطر لكل مؤشر (SHA-256/SHA-1/MD5، IPv4/IPv6، نطاق)، و`#` للتعليقات. انظر `examples\iocs_example.txt`.

---

<a id="reports"></a>
## 13. التقارير

كل تقرير يحتوي: معلومات الجلسة، تاريخ ووقت الجمع، إصدار الأداة، الوحدات المستخدمة، عدد الأدلة، النتائج المهمة، الأحداث المشبوهة، الخط الزمني، قيم SHA-256، الأخطاء والتحذيرات، الملخص التنفيذي، والتوصيات الفنية.

| الصيغة | الملاحظات |
|---|---|
| **HTML** | ملف واحد مستقل يعمل دون إنترنت (CSS/JS مضمنان، لا موارد خارجية). جداول قابلة للبحث والتصفية والفرز مع ترقيم صفحات، وتبويبات: Overview, Findings, Timeline, Modules, Evidence & SHA-256, Observables, Errors, Live actions, Chain of custody. يعرض أحدث N حدث (افتراضيًا 25,000) والخط الزمني الكامل في CSV/JSONL. |
| **HTML لكل متصفح** | `reports\browsers\browser_<name>.html`: السجل، التنزيلات، المفضلة، الإضافات، الكوكيز (بيانات وصفية)، فهرس الكاش. |
| **PDF** | تنسيق أفقي A4، خط Unicode من Windows (Tahoma/Arial/Segoe) مع تشكيل النص العربي. |
| **JSON** | كل بيانات التقرير بصيغة قابلة للمعالجة الآلية. |
| **CSV** | النتائج، الخط الزمني الكامل، الهاشات، الأخطاء، الوحدات، المؤشرات، العمليات الحية، وكل أداة محللة في `csv\artifacts\`. |

تُحسب هاشات ملفات التقارير في `reports\report_hashes.json` وتُسجَّل في سجل الحيازة.

---

<a id="settings"></a>
## 14. الإعدادات (`wezcrypt_config.json`)

| المفتاح | الافتراضي | الوصف |
|---|---|---|
| `output_dir` | "" | فارغ = `<مجلد الأداة>\WezCrypt_Cases` |
| `examiner` / `organization` / `case_prefix` | "" / "" / CASE | بيانات افتراضية للجلسات |
| `max_workers` | 4 | عدد الوحدات المتوازية (1–16) |
| `eventlog_max_events` | 20000 | الحد لكل قناة (الأحدث أولًا؛ السجل الكامل محفوظ كدليل) |
| `script_block_max_chars` | 4000 | حد طول حقول الأحداث (مثل ScriptBlockText) |
| `browser_max_rows` | 100000 | حد السجلات لكل جدول لكل ملف تعريف |
| `collect_browser_cache_index` | true | فهرسة ذاكرة الكاش |
| `fs_scan_paths` | Downloads, Desktop, %TEMP%, Startup, %PUBLIC% | مسارات فحص نظام الملفات (تدعم متغيرات البيئة) |
| `fs_max_depth` / `fs_max_files` / `fs_hash_max_mb` | 4 / 20000 / 512 | حدود المسح والهاش |
| `fs_copy_suspicious` / `fs_copy_max_mb` | false / 50 | نسخ الملفات المشبوهة كأدلة |
| `hash_process_executables` | true | هاش ملفات العمليات الجارية |
| `verify_signatures` | true | التحقق من Authenticode عبر PowerShell |
| `acquire_registry_hives` | true | تصدير الخلايا عبر `reg save` |
| `use_vss_for_locked` | false | استخدام `esentutl /vss` لقواعد المتصفحات المقفلة (مسؤول) |
| `html_timeline_limit` | 25000 | عدد الأحداث في HTML/PDF |
| `ioc_file` | "" | ملف مؤشرات الاختراق |
| `failed_logon_threshold` / `failed_logon_window_minutes` | 10 / 10 | عتبة كشف تخمين كلمات المرور |

---

<a id="live"></a>
## 15. العمليات التي تُجرى على النظام الحي

الجمع الحي يترك أثرًا حتميًا؛ لذلك تُوثَّق كل عملية مع أثرها المحتمل:

| العملية | الأثر |
|---|---|
| `wevtutil epl/qe` | إنشاء عملية (تسجلها Windows)؛ التصدير عبر خدمة السجل. |
| `reg save` | تصدير خلية عبر واجهة النسخ الاحتياطي الرسمية؛ إنشاء عملية. |
| `esentutl /y /vss` | إنشاء وحذف Volume Shadow Copy مؤقتة (تُسجَّل أحداث VSS وتُكتب في مساحة الظل على قرص النظام). |
| `powershell.exe` (التواقيع، DNS، ARP، Routes، Firewall) | إنشاء عملية؛ قد تُسجَّل في سجلات PowerShell/Script Block. |
| `ipconfig` / `netstat` / `arp` / `route` / `netsh` / `schtasks` | إنشاء عمليات قصيرة. |
| قراءة الملفات | قد تُحدَّث أوقات الوصول (Last Access) إذا كان التحديث مفعّلًا في NTFS. |

كل أدوات النظام تُستدعى بمسار مطلق من `System32` لمنع تنفيذ ملف مزروع بالاسم نفسه على الفلاشة أو المجلد الحالي.

---

<a id="tests"></a>
## 16. الاختبارات

```bat
python -m pytest -q
```

58 اختبارًا آليًا تعتمد **فقط على بيانات صناعية** تُنشأ داخل الاختبارات (`tests/builders.py`: مولّد خلايا REGF، LNK، Prefetch، ملفات OLE/Jump Lists، `$I`، قواعد Chrome/Firefox، XML أحداث Windows)، وتغطي:

| المجال | الملف |
|---|---|
| جمع الأدلة (Orchestrator كامل، وحدات المتصفح/LNK/Jump Lists/Prefetch/Recycle Bin/نظام الملفات) | `test_collection.py`, `test_browsers.py` |
| تحليل سجلات Windows (XML متدفق، الأوصاف، القواعد) | `test_parsers.py`, `test_analysis_reports.py` |
| قواعد بيانات المتصفحات التجريبية + التأكد من عدم تسرب قيم الكوكيز لأي ملف | `test_browsers.py` |
| SHA-256 والتحقق من السلامة وكشف التلاعب (تعديل/حذف/ملف دخيل/تزوير Manifest/تعديل سجل الحيازة) | `test_integrity.py`, `test_collection.py` |
| إنشاء التقارير بكل الصيغ (HTML دون موارد خارجية، PDF، JSON، CSV مع BOM) | `test_analysis_reports.py` |
| الملفات المقفلة (تسجيل الخطأ واستمرار الوحدة) | `test_integrity.py`, `test_collection.py` |
| نقص الصلاحيات (`requires_admin`) | `test_collection.py` |
| المسارات العربية والطويلة (>300 حرف) | `test_usb_paths.py`, `test_registry.py`, `test_parsers.py` |
| التشغيل من USB (كشف القرص القابل للإزالة، مسار EXE المجمّد، هيكل الجلسات) | `test_usb_paths.py` |
| عزل فشل الوحدات والإلغاء الآمن | `test_collection.py` |

---

<a id="limits"></a>
## 17. القيود المعروفة (بشفافية)

- **تحليل EVTX** يتم عبر أداة Windows المدمجة `wevtutil` على النسخة المُصدَّرة، وليس عبر محلل EVTX ثنائي مستقل؛ لذا يتطلب تحليل السجلات Windows.
- **خلايا الريجستري المتّسخة (dirty):** لا يُعاد تطبيق سجلات المعاملات `.LOG1/.LOG2`؛ تُعلَّم الحالة كتحذير في الأخطاء.
- **NTFS:** البيانات الوصفية عبر واجهات Win32 (السمات، رقم سجل MFT، عدد الروابط، الرقم التسلسلي للمجلد، ADS) — لا يوجد تحليل خام لـ `$MFT` أو `$UsnJrnl` أو `$LogFile`.
- **Shimcache:** صيغة Windows 10/11 فقط (الهدف المعلن للأداة). وقت Shimcache هو وقت تعديل الملف وليس دليل تنفيذ.
- **ذاكرة الكاش للمتصفحات:** يُستخرج فهرس العناوين والأوقات فقط، لا محتوى الملفات المخزنة.
- **أسماء AppID في Jump Lists:** قائمة صغيرة مؤكدة فقط؛ بقية المعرفات تُعرض كما هي.
- **التحقق من التواقيع** يعتمد على PowerShell `Get-AuthenticodeSignature` (يدعم توقيعات الكتالوج)؛ يمكن تعطيله من الإعدادات.
- **لا يتضمن الإصدار** التقاط الذاكرة الحية (RAM).
- **أوقات setupapi.dev.log** محلية لا UTC، وتُعلَّم بذلك صراحة.
- **البناء:** PyInstaller لا يبني ملفات EXE لنظام Windows من نظام آخر؛ يجب تشغيل `build.bat` على Windows.

---

<a id="troubleshooting"></a>
## 18. حل المشكلات

| المشكلة | الحل |
|---|---|
| وحدات كثيرة بحالة `partial` و`requires_admin` | شغّل `Run_as_Administrator.bat`. |
| `could not acquire History ... locked` | أغلق المتصفح، أو فعّل `use_vss_for_locked` وشغّل كمسؤول. |
| تحذير "not a removable USB drive" | بعض أقراص USB الخارجية تُعرّف كـ Fixed؛ تأكد من أن مجلد الإخراج ليس على قرص النظام. |
| `Prefetch folder not found` | Prefetch معطّل على بعض الأنظمة (VM/SSD)؛ موثّق في الأخطاء. |
| فشل التحقق من السلامة | راجع تبويب Hash Verification: أي ملف `MODIFIED`/`MISSING` يعني تغييرًا بعد الجمع. |
| PDF لا يظهر العربية | تأكد من وجود خط Tahoma/Arial في `C:\Windows\Fonts`. |
| الواجهة لا تفتح | استخدم `WezCryptUFK-cli.exe`؛ وراجع `WezCrypt_Logs\wezcrypt_app.log`. |

---

<a id="license"></a>
## 19. الترخيص والأمان

- الترخيص: **MIT** — انظر `LICENSE`.
- سياسة الإبلاغ عن الثغرات: انظر `SECURITY.md`.
- سجل التحديثات: `CHANGELOG.md`.

```
Application: WezCrypt USB Forensics Kit
Developer:   wezcrypt
Website:     https://wezcrypt.com
Category:    Digital Forensics & Incident Response
Platform:    Windows 10/11
License:     MIT
```

</div>
