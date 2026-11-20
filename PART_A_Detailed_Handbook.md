# PART A — Bug Bounty & Web Application Pentesting: Detailed Handbook

**Хэл:** Монгол; техникийн нэр, HTTP, payload, command — English.  
**Хувилбар:** 1.0 · **Шинэчилсэн:** 2026-11-20 · **Зорилго:** анхан шат → дунд түвшин.  
**Зөвшөөрөгдсөн хэрэглээ:** өөрийн `127.0.0.1` / `localhost` лаборатори, PortSwigger lab, эзэмшигчийн бичгээр зөвшөөрсөн in-scope web application.

> **Аюулгүй ажиллагааны заалт.** `example.com` бол баримт бичгийн жишээ domain болохоос тест хийх зөвшөөрөл биш. Domain-ийг өөрийн зөвшөөрөгдсөн hostname-оор солино. Доорх `/lab/...` endpoint болон response-ууд нь **зааварчилгааны synthetic fixture**, Juice Shop/WebGoat дээр заавал байдаг URL биш. Lab-оос өөр рүү payload ажиллуулахгүй. Non-destructive PoC, **хоёр өөрийн тест account**, synthetic data, бага давтамжтай manual replay ашигла. Бодит хэрэглэгчийн өгөгдөл, credential, session token, production transaction авах/өөрчлөхгүй. Хэрэв гэнэтийн sensitive data гарвал даруй зогсоож нууцалж мэдэгд.

## Гарчиг (Table of Contents)

1. [Bug Bounty Fundamentals](#chapter-1)
2. [Environment Setup](#chapter-2)
3. [Reconnaissance](#chapter-3)
4. [HTTP Fundamentals](#chapter-4)
5. [Authentication Testing](#chapter-5)
6. [Authorization Testing](#chapter-6)
7. [Injection Vulnerabilities](#chapter-7)
8. [Cross-Site Scripting](#chapter-8)
9. [Server-Side Vulnerabilities](#chapter-9)
10. [API Security](#chapter-10)
11. [Business Logic Vulnerabilities](#chapter-11)
12. [Security Misconfiguration](#chapter-12)
13. [Burp Suite Practical Guide](#chapter-13)
14. [Bug Bounty Methodology](#chapter-14)
15. [Reporting](#chapter-15)
16. [Quick Command Reference](#chapter-16)
17. [Testing Checklist](#chapter-17)
18. [Practice Labs](#chapter-18)

**Хэрэглэх дараалал:** 1–4 суурь → 5–12 vulnerability → 13 Burp → 14 workflow → 15 reporting → 16–17 талбайн лавлах → 18 дадлага. Товч хуудас [PART B](./PART_B_Quick_Cheat_Sheet.md), гүйцэтгэлийн checklist [PART C](./PART_C_Practical_Workflow.md)-д тусдаа бий.

### Нэр томьёоны товч тайлбар

- **OWASP** — Open Worldwide Application Security Project; web/API security-ийн нээлттэй мэдлэгийн сан.
- **WSTG** — Web Security Testing Guide; security testing-ийн аргачлал.
- **BPP/VDP** — Bug Bounty Program / Vulnerability Disclosure Program.
- **PoC** — Proof of Concept; алдааг аюулгүй аргаар батлах нотолгоо.
- **CIA** — Confidentiality, Integrity, Availability буюу нууцлал, бүрэн бүтэн байдал, хүртээмж.
- **CVSS** — Common Vulnerability Scoring System; severity тооцоолох арга.
- **HTTP** — Hypertext Transfer Protocol; **TLS** — Transport Layer Security; **URL** — Uniform Resource Locator.
- **API** — Application Programming Interface; **REST** — Representational State Transfer; **JWT** — JSON Web Token.
- **MFA** — Multi-Factor Authentication; **OIDC** — OpenID Connect; **OAuth** — эрх олгох framework.
- **IDOR** — Insecure Direct Object Reference; **BOLA** — Broken Object Level Authorization; **BFLA** — Broken Function Level Authorization.
- **XSS** — Cross-Site Scripting; **SQLi** — SQL Injection; **SSRF** — Server-Side Request Forgery; **XXE** — XML External Entity.
- **CORS** — Cross-Origin Resource Sharing; **CSP** — Content Security Policy; **CSRF** — Cross-Site Request Forgery.
- **CT** — Certificate Transparency; **DNS** — Domain Name System; **SSTI** — Server-Side Template Injection.

### Framework-ийн хувилбар

Энэ лавлах нь **OWASP Top 10:2025** (2021 биш), **OWASP API Security Top 10:2023**, **OWASP WSTG v4.2 stable** болон PortSwigger Web Security Academy-д тулгуурласан. OWASP Top 10 awareness жагсаалт нь penetration test-ийн бүрэн checklist биш; WSTG-ээр илүү нарийн шалгана. Албан эх сурвалжийг төгсгөлийн References хэсгээс хар.

<a id="chapter-1"></a>
## Chapter 1 — Bug Bounty Fundamentals

### 1.1 Bug bounty гэж юу вэ?

**Bug Bounty Program (BBP)**-д байгууллага тодорхой системээ тодорхой дүрмийн дагуу шалгаж, нотлогдсон security finding-д урамшуулал олгож болно. **VDP**-ийн гол зорилго нь эмзэг байдлын мэдээллийг аюулгүй хүлээн авах, засах; төлбөр заавал дагалдахгүй. Урамшуулалтай эсэхээс үл хамааран program policy хамгийн түрүүнд мөрдөгдөнө.

### 1.2 Scope / Out of scope / Rules of Engagement (RoE)

| Шалгах зүйл | Зөв хувилбар | Эрсдэлтэй буруу ойлголт |
|---|---|---|
| In-scope | `https://app.lab.test` яг нэрээрээ бичигдсэн | `*.lab.test` гэж үзээд бүх subdomain-ийг шалгах |
| API | `https://api.lab.test/v1/` заагдсан | Third-party payment API-г автоматаар хамруулах |
| Accounts | Өөрийн A/B test user | Бодит хэрэглэгчийн object ID-г онцгой зөвшөөрөлгүй солих |
| Automation | Зөвшөөрсөн, бага rate, тодорхой хугацаанд | Recursive scan, brute force, service stress |
| Exploitation | Minimum PoC; marker, test object | Full database dump, RCE persistence, exfiltration |
| Disclosure | Нууц, зөв суваг, policy дагуу | Social media-д өмнө нь нийтлэх |

**RoE sheet**-дээ `program URL`, scope hostname, excluded paths, allowed methods, test accounts, rate ceiling, hours, contact, stop conditions, evidence retention, safe harbor бич. Scope зөвхөн hostname биш: app, environment, API, IP, wildcard, third-party integration, testing types бүгд тусдаа шалгагдана.

### 1.3 Аюулгүй тестийн 10 зарчим

1. Бичгээр authorization байхгүй бол active test хийхгүй.
2. Production хэрэглэгчийн ID, token, profile руу зориуд нэвтрэхгүй; өөрийн A/B account хэрэглэ.
3. Үнэ, төлбөр, захиалга, имэйл, webhook зэрэг side-effect-тай үйлдэл зөвхөн тусгаарласан тест өгөгдлөөр хийнэ.
4. Availability test, brute-force, credential stuffing, SSRF→internal metadata, mass fuzzing-ээс татгалз.
5. `curl`-д `--max-time`, scanner-т rate/concurrency limit тавь.
6. Scope-оос гарсан redirect, CDN, SSO provider, payment gateway руу follow хийхгүй.
7. Production-д upload хийх бол зөвхөн harmless `.txt` test file, policy зөвшөөрсөн үед.
8. Request/response evidence-ээс password, token, PII (Personally Identifiable Information)-г redact хийнэ.
9. Нэг тестээс хангалттай баталгаа авмагц зогсоно; шаардлагагүй дахин туршихгүй.
10. Incident шинж (500 өсөх, 429, latency, бусдын data) илэрвэл тасалдуулж owner-т мэдэгд.

### 1.4 Finding, false positive, duplicate, triage

- **Hypothesis:** 'ID солиход өөр record ирж магадгүй' — батлагдаагүй.
- **Observation:** status 200, response өөр боловч cache/shared data эсэх тодорхойгүй.
- **Confirmed:** өөрийн Account A-аас өөрийн Account B-ийн **private synthetic object**-ийг B-ийн зөвшөөрөлгүй уншиж чадсан; expected/actual болон баримт хадгалсан.
- **Duplicate:** өмнө мэдээлэгдсэн ижил root cause; report policy-оос шалтгаалан урамшуулалгүй байж болно.
- **Informational / Low / Medium / High / Critical:** нөлөө, exploitability, precondition, program triage-оос хамаарна. CVSS тоо нь bounty severity-тэй заавал адил биш.

**Шинжээчийн дүрэм:** `HTTP 200 ≠ vulnerability`, `HTTP 403 ≠ бүх authorization хамгаалалт зөв`, `CSP missing ≠ XSS`, `error string ≠ SQLi confirmed`.

### 1.5 Responsible disclosure

1. Нөлөөг safety boundary дотор батална. 2. Нотолгоог sanitize хийнэ. 3. Program-ийн official report channel руу илгээнэ. 4. Triage-ийн асуултад хариулна. 5. Засвар баталгаажуулах бол зөвшөөрөгдсөн retest хийнэ. 6. Нийтэд мэдээлэх хугацааг program policy-оор тохиролцоно.

**Severity-ийн богино матриц:** Confidentiality = бусдын хувийн object харагдах; Integrity = зөвшөөрөлгүй өөрчлөх; Availability = үйлчилгээ тасрах. Тестийн хүрээнд availability-д нөлөөлөхийг **туршиж батлах шаардлагагүй**: design/code evidence болон owner-ийн review ашигла.

<a id="chapter-2"></a>
## Chapter 2 — Environment Setup

### 2.1 Үндсэн хэрэгсэл

| Хэрэгсэл | Зорилго | Суурилуулалт / шалгах |
|---|---|---|
| Kali Linux | Security tool-уудтай Linux distro | Official installer/VM image; `cat /etc/os-release` |
| Burp Suite Community | Manual HTTP proxy / Repeater | PortSwigger official download; launch GUI |
| Burp Suite Professional | Community + Scanner, нэмэлт automation | Лиценз, program scanning permission шаардлагатай |
| Firefox/Chrome DevTools | Network, Storage, Console, Sources | `F12` / `Ctrl+Shift+I` |
| curl | HTTP request шалгах | `curl --version` |
| jq | JSON форматлах/шүүх | `jq --version` |
| Python 3 | Scripting/inspection | `python3 --version` |
| Docker | Local vulnerable apps | `docker --version`, `docker compose version` |

Kali/Debian-д боломжтой package-ууд:

```bash
sudo apt update
sudo apt install -y curl jq python3 python3-venv git dnsutils docker.io
curl --version
jq --version
python3 --version
```

**Тайлбар:** `apt update` package metadata шинэчилнэ; `install -y` суулгахыг зөвшөөрнө; `-venv` тусгаарласан Python environment; `dnsutils` нь `dig`-г өгнө. Дээж output: `curl 8.x`, `jq-1.x`, `Python 3.x`. `command not found` бол PATH/package, permission denied бол package эрхийг шалга. Эдгээр command өөрөө target scan хийхгүй.

### 2.2 Docker — intentionally vulnerable local lab

```bash
docker pull bkimminich/juice-shop
docker run --rm --name juice-lab -p 127.0.0.1:3000:3000 bkimminich/juice-shop
# Browser: http://127.0.0.1:3000/
```

- `pull`: image татна; `--rm`: container зогсоход устгана; `--name`: танигдах нэр; `-p 127.0.0.1:3000:3000`: **зөвхөн host localhost** руу bind хийж container-ийн 3000 port-ыг гаргана.
- Амжилттай ажиллавал `docker ps`-д `juice-lab` ба port mapping харагдана. `port is already allocated` бол 3000-ыг өөр port-оор солино (`127.0.0.1:3001:3000`).
- `http://localhost:3000` зөвхөн өөрийн хост дээр нээгдэнэ; өөр төхөөрөмжид expose хийхгүй. `docker stop juice-lab`-аар зогсооно.

WebGoat:

```bash
docker run --rm --name webgoat-lab -p 127.0.0.1:8080:8080 -p 127.0.0.1:9090:9090 webgoat/webgoat
# http://127.0.0.1:8080/WebGoat
# http://127.0.0.1:9090/WebWolf
```

Энд 9090 нь WebWolf helper. `8080` порт Burp listener-тэй давхцах магадлалтай — Burp listener-ийг `127.0.0.1:8081` болгох эсвэл WebGoat host port-ыг өөрчил. **Анхаар:** vulnerable lab-ийг `0.0.0.0` эсвэл public interface рүү нээлттэй гаргахгүй.

### 2.3 Burp Proxy — эхний 10 минут

1. Burp нээж **Temporary project → Start Burp** сонго; Community-д project хадгалалт хязгаартай байж болно.
2. **Proxy → Intercept → Open Browser**. Burp-ийн browser proxy ба CA нь урьдчилан тохируулгатай.
3. `http://127.0.0.1:3000` руу орж тест үйлдэл хийнэ.
4. **Proxy → HTTP history**-д хүсэлт ирж байгааг нягтал.
5. **Target → Scope** хэсэгт зөвхөн `http://127.0.0.1:3000` нэм. In-scope filter ашигла.
6. **Proxy → Intercept**-ийг `Off` болгож өдөр тутмын browsing-ийг саадгүй болго.
7. HTTP history дахь нэг `GET` request → right click → **Send to Repeater** → **Repeater → Send**. Response code, content, duration тэмдэглэ.
8. Browser DevTools **Network → Preserve log**, **Disable cache** (шаардлагатай үед), response headers шалга.

**External Firefox/Chrome:** browser HTTP(S) proxy = `127.0.0.1:8080` (listener-ээ өөрчилсөн бол бодит port); Burp-ийн `http://burpsuite`-ээс CA certificate авч browser trust store-д зөвхөн өөрийн lab profile-д импортол. Burp browser ашиглавал тусгай CA суулгах шаардлагагүй. HTTPS warning гарвал certificate trust болон listener шалга; `curl -k`-г TLS алдаа нуух тогтмол шийдэл болгож болохгүй.

### 2.4 Proxy шалгах жишээ

```bash
curl -i --max-time 10 --proxy http://127.0.0.1:8080 http://127.0.0.1:3000/
```

`-i`: headers хамт; `--max-time 10`: нийт timeout 10s; `--proxy`: Burp-д дамжуулна. **Expected:** `HTTP/1.1 200` эсвэл app-ийн зохих redirect, Burp history-д нэг request. `Connection refused`: Burp listener эсвэл Juice Shop ажиллаагүй. `localhost` proxy bypass configuration tool бүрт өөр байж болно.

### 2.5 Файл/нотолгооны зохион байгуулалт

```text
engagement-2026-11/
  00_scope/authorization.md
  01_recon/inventory.csv
  02_requests/redacted-requests.http
  03_evidence/screenshot-01.png
  04_findings/FIND-001.md
  05_retest/retest-notes.md
```

Evidence-г account ID, request time (timezone), method, URL, precondition, response status, control test, artifact hash зэрэгтэй хадгал. Password, session cookie, private data-г plain text repository-д commit хийхгүй.

<a id="chapter-3"></a>
## Chapter 3 — Reconnaissance

**Passive recon** гэдэг нь target host руу заавал хүсэлт илгээхгүйгээр CT, DNS, public archives-аас metadata цуглуулахыг хэлнэ. **Active recon** гэдэг нь зөвшөөрөгдсөн target руу DNS/HTTP query, crawl, fuzz илгээхийг хэлнэ. Public index-д олдсон asset нь **автоматаар in-scope болохгүй**.

### 3.1 Scope-first asset inventory

```csv
asset,source,in_scope,proof,owner,method,notes
app.lab.test,program_scope,yes,scope-v1,team,manual,main app
api.lab.test,program_scope,yes,scope-v1,team,manual,API v1
payments.vendor.test,app_link,no,none,third_party,none,exclude
```

**Аюулгүй pipeline:** `discovered.csv` → program scope-тай string/hostname comparison → approved-hosts.txt → only then `httpx`, `katana`, `ffuf`. `example.com` public domain-ийг жишээ болгон харуулсан command-уудыг ажиллуулахын өмнө **заавал** approved domain-оор солино.

### 3.2 Tool бүрийн үүрэг, command, тайлбар

| Tool | Хэзээ хэрэглэх | Passive/active | Үндсэн анхааруулга |
|---|---|---|---|
| `subfinder` | Subdomain candidate | Passive sources | Гарсан host бүрийг scope-р шүүнэ |
| `amass` | DNS/asset discovery | `enum -passive` passive | Active mode тусдаа зөвшөөрөл |
| `dnsx` | Approved host resolve, DNS record | DNS query = active | Wildcard/3rd-party шийдвэргүйгээр scan хийхгүй |
| `httpx` (ProjectDiscovery) | Live HTTP / status / tech | Active | Python `httpx`-оос ялгаатай; rate limit |
| `gau` | Public URL archive | Passive-ish external providers | Historical URL live/authorized гэсэн үг биш |
| `waybackurls` | Wayback Machine URLs | Passive archive query | PII-н хуучин URL-г нийтлэхгүй |
| `katana` | Crawl allowed application | Active | `-fs fqdn`, rate limit, logout/payment exclude |
| `ffuf` | Small wordlist lab endpoint discovery | Active | `-rate`, `-t`, `-maxtime`; unknown production-д default fast тохиргоо зохимжгүй |

```bash
# Зөвхөн scope зөвшөөрсөн домэйн дээр passive candidate авна
subfinder -d lab.test -silent > discovered-subdomains.txt
amass enum -passive -d lab.test -o amass-passive.txt

# approved-hosts.txt файлыг scope-тэй MANUAL тулгаж гаргасны дараа:
dnsx -l approved-hosts.txt -a -resp -silent
httpx -l approved-hosts.txt -sc -title -td -rl 2 -silent

# Archive: олох ≠ тест хийх эрх
gau lab.test --o archive-urls.txt
printf '%s\n' lab.test | waybackurls > wayback-urls.txt

# Lab domain/host scope, бага давтамж
katana -u http://127.0.0.1:3000 -d 2 -rl 2 -c 1 -silent
printf '%s\n' api health robots.txt > tiny-lab-words.txt
ffuf -w tiny-lab-words.txt -u http://127.0.0.1:3000/FUZZ -rate 1 -t 1 -maxtime 15 -mc 200,301,302,401,403
```

**Flag тайлбар:** `-d` (subfinder/amass) domain; `-silent` зөвхөн үр дүн; `-o` output file; `-l` input list; `-a` A record; `-resp` DNS хариу; `-sc` status code; `-title` HTML title; `-td` tech detect; `-rl` requests/second; `-c` concurrency; `-w` wordlist; `-u` URL; `FUZZ` replacement marker; `-rate` requests/second; `-t` concurrent workers; `-maxtime` бүх гүйлтийн секунд; `-mc` show matching HTTP codes. Тухайн CLI-ийн `-h`-ээр installed version-ийг шалга.

**Жишээ output (synthetic):**

```text
api.lab.test [A] [192.0.2.10]
https://app.lab.test [200] [App Portal] [nginx]
http://127.0.0.1:3000/health [Status: 200, Size: 13]
```

`192.0.2.0/24` бол documentation-only IP range. `Status: 200` нь тухайн URL байж болохыг харуулах боловч эмзэг байдал **батлахгүй**. `404/403` гээд security bypass оролдож болохгүй; scope/permission шалга.

### 3.3 DNS, CT, robots, sitemap, headers

```bash
# Officially owned/authorized test host-ыг орлуул
dig A app.lab.test +short
dig CNAME app.lab.test +short
curl -sS -I --max-time 10 http://127.0.0.1:3000/
curl -sS --max-time 10 http://127.0.0.1:3000/robots.txt
curl -sS --max-time 10 http://127.0.0.1:3000/sitemap.xml
```

- `dig` DNS утга харах; `+short` богино output. `curl -I` нь HEAD request бөгөөд серверийн GET-ээс өөр ажиллаж болно. `-sS` progress нууж error харуулна. `--max-time` хязгаарлана.
- CT log: `https://crt.sh/` зэрэг public CT explorer-т **зөвхөн зөвшөөрөгдсөн байгууллагын domain**-ийн certificate SAN (Subject Alternative Name) мэдээллийг шинжилж болно; DNS resolved эсэх, ownership, scope-ийг давхар шалга.
- `robots.txt` бол crawl guidance, access-control биш. `Disallow: /admin` нь vulnerability биш.
- `sitemap.xml` нь URL discovery; discovered endpoints production-д automatic fuzz хийх зөвшөөрөл биш.

### 3.4 JavaScript, parameter, API endpoints

DevTools → **Network**, JS filter → өөрийн app-ийн `.js` bundle → **Sources** search (`fetch(`, `/api/`, `Authorization`, `graphql`, `sourceMappingURL`) хийнэ. JS дотор хардкодлогдсон string нь **secret баталгаа биш** — test/dummy key, public client ID ялгана. 

```bash
# Татаж болох өөрийн mock JS бэлдэх
printf 'const apiBase="/api/v1"; const q="?page=1";\n' > demo.js
grep -En '(/api/|fetch\(|sourceMappingURL|\?)' demo.js
# 1:const apiBase="/api/v1"; const q="?page=1";
```

`grep -E` regex; `-n` line number. Source map хандалттай байвал зөвхөн app owner зөвшөөрсөн хэмжээнд metadata шалга; repo secret, credentials цуглуулахгүй.

### 3.5 Recon common mistakes

Wildcard DNS-ийг real subdomain гэж эндүүрэх; CDN/SSO-ийг scope-д оруулах; `httpx` active probe-г passive гэж үзэх; `gau`/Wayback-д олдсон хуучин URL-г баталгаатай live гэж үзэх; user logout, delete, purchase endpoint-г crawler-д барьж явуулах; 401/403 response-г vulnerability гэж тайлагнах — нийтлэг алдаа.

<a id="chapter-4"></a>
## Chapter 4 — HTTP Fundamentals

### 4.1 HTTP request ба response

```http
GET /api/v1/profile?view=summary HTTP/1.1
Host: app.lab.test
Accept: application/json
Authorization: Bearer <OWN_LAB_TOKEN>
Cookie: session=<OWN_LAB_SESSION>

```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store
Set-Cookie: session=<NEW_LAB_SESSION>; HttpOnly; Secure; SameSite=Lax

{"id":"test-a","name":"Lab User A"}
```

**Request line**: method + path/query + protocol. **Headers**: metadata (Host, Accept, Authorization, Cookie). **Body**: POST/PATCH үед JSON/form гэх мэт. **Status**: server-ийн хариу; **response headers**: content, cache, cookie policy; **response body**: data. Raw HTTP-д `Content-Length` зөв тооцогдох ёстой; Burp ихэнхдээ update хийдэг.

| Method | Ерөнхий үүрэг | Аюулгүй тестийн тэмдэглэл |
|---|---|---|
| GET | Fetch/read | State өөрчилдөг бол design flaw байж болно |
| HEAD | Headers | Бүрэн GET-тэй адил гэсэн баталгаа биш |
| POST | Create/action | Side effect-тай; зөвхөн test object |
| PUT | Replace | Зөвхөн өөрийн record |
| PATCH | Partial update | Hidden field/role болгоомжлоорой |
| DELETE | Delete | Production-д бүү турш; isolated lab |
| OPTIONS | Supported methods/CORS preflight | `Allow`-г хараад auth bypass гэж дүгнэхгүй |

| Status | Утга | Анхаарах зүйл |
|---|---|---|
| 200/201/204 | Success / Created / No Content | Status 200 дангаараа data authorization нотлохгүй |
| 301/302/307/308 | Redirect | External redirect in-scope эсэхийг шалга |
| 400/422 | Bad request/validation | Validation error байж болно |
| 401 | Unauthenticated | Token байхгүй/хүчингүй |
| 403 | Forbidden | Access denied; object-level check мөн эсэхийг тусад нь шалга |
| 404 | Not found | Object байхгүй эсвэл authorization hiding |
| 429 | Rate limited | Тестийг бууруул/зогсоо |
| 500 | Server error | Алдаа ганцаараа injection нотлохгүй |

### 4.2 Cookie, session, SameSite

`Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax; Path=/`:
- `Secure`: cookie зөвхөн HTTPS-аар (localhost-ийн browser exception байж болно).
- `HttpOnly`: JavaScript `document.cookie`-оос харагдахгүй; XSS-ийн бүх үр дагаврыг зогсоохгүй.
- `SameSite=Strict|Lax|None`: cross-site request үед cookie явуулах бодлого; `None` нь `Secure` шаарддаг.
- `Path`/`Domain`: cookie хаана хүрэх. Эдгээр нь token encryption биш.

### 4.3 CORS, CSP, Cache-Control, Content-Type

- **CORS** browser origin-аас cross-origin resource унших эрхийг хянадаг. `Access-Control-Allow-Origin: *` нь public resource-д зөв байж болно; credentials-тэй private response дээр risk үүсдэг. CORS бол authentication биш.
- **CSP** скрипт хаанаас ажиллахыг хязгаарлах defense-in-depth. CSP байхгүй = **XSS confirmed биш**.
- `Cache-Control: no-store` sensitive response-г хадгалах эрсдэлийг бууруулна, гэхдээ үүнийг дангаар нь finding болгох severity нь бага байж болно.
- `Content-Type` болон `X-Content-Type-Options: nosniff` нь browser content handling-д нөлөөлнө.
- `Authorization: Bearer`-т raw JWT/token оруулах бол зөвхөн өөрийн test token; evidence дээр **redact**.

### 4.4 curl ба jq-г алхамчлах

```bash
curl -sS -i --max-time 10 -H 'Accept: application/json' http://127.0.0.1:3000/
printf '%s\n' '{"role":"viewer","id":7}' | jq -r '.role'
# viewer
```

`-H` request header нэмнэ; `jq -r` JSON string-ийг quote-гүй гаргана, `.role` JSON field. `parse error` бол response JSON биш эсвэл HTML error page. Нэвтрэх authentication cookie-г shell history-д шууд бичихээс зайлсхий; test token env/secret file-ийг хамгаал.

### 4.5 Baseline → Controlled change → Comparison

1. Өөрийн account A-аар valid request илгээ → status, response body, request ID тэмдэглэ.
2. **Зөвхөн нэг field** өөрчил (жишээ `objectId` өөрийн account B-ийн synthetic object).
3. Same method/path/auth context ашигла.
4. Response body **болон** бодит state-ийг шалга. Status адил байх нь failure гэсэн үг биш.
5. Test account B-аар object ownership-ийг хөндлөн баталгаажуул.
6. Evidence sanitize хийж hypothesis/confirmed гэж ялга.

<a id="chapter-5"></a>
## Chapter 5 — Authentication Testing

Authentication гэдэг нь “хэн бэ?” гэдгийг баталгаажуулах; authorization бол “юу хийж болох вэ?” гэдгийг шийдэх. Login → MFA → session → logout бүх шатыг тусад нь шалгана.

> **Сургалтын маршрут:** Эхлээд raw HTTP-г ойлго → baseline → own controlled change → negative control → state validation → report. Доорх бүх `/lab` URL ба response нь **synthetic**. Бодит дасгалыг дурдсан lab-ийн сэдвийн exercise-д хий.

### 5.1 Login Response Handling — Нэвтрэлтийн хариу боловсруулах алдаа

**A. Vulnerability Name.** **Login Response Handling** — Нэвтрэлтийн хариу боловсруулах алдаа.

**B. What Is It? (Энгийнээр).** Үүдний хамгаалалт амжилттай нэвтэрсэн эсэхийг зөвхөн дэлгэц дээрх мессежээр шийдэж буй мэт.

**C. Why Does It Happen? (Root cause).** Server-side credential/session validation дутуу, client-side login flag-д итгэдэг.

**D. Where to Look? (Тестийн байрлал).** `POST /login`, response JSON `authenticated`, login redirect, session cookie. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **OWASP Juice Shop / Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Lab account A-гаар зөв нэвтэр; дараа нь өөрийн буруу password бүхий ганц request илгээ; response болон protected route-г тусад нь шалга.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
curl -sS -i --max-time 10 -X POST 'http://127.0.0.1:3000/rest/user/login' -H 'Content-Type: application/json' --data '{"email":"test-user@example.invalid","password":"incorrect-lab-only"}'
```

`curl` = HTTP client; `-sS` = progress нуух боловч error хэвлэх; `-i` = response header харуулах; `-I` = HEAD request; `--max-time 10` = 10 секунд timeout; `-X` = HTTP method; `-H` = header; `--data` = body. Зөвхөн ашигласан flag-ууд энэ command-д хамаарна.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
POST /lab/login HTTP/1.1
Host: app.lab.test
Content-Type: application/json

{"username":"lab-a","password":"wrong"}
```

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{"error":"invalid credentials"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Сэжигтэй нь: invalid login-ийн дараа **шинэ authenticated session** үүсч protected `/lab/me` өөрийн test user-ийн контент өгвөл; зөвхөн текст `ok` байхад хангалтгүй.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Сэжигтэй нь: invalid login-ийн дараа **шинэ authenticated session** үүсч protected `/lab/me` өөрийн test user-ийн контент өгвөл; зөвхөн текст `ok` байхад хангалтгүй. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** SPA-д login banner хадгалагдсан, cache, өмнөх cookie байна уу; incognito/clear session-тай давт. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** Authentication gate эвдэрвэл C/I өндөр, A шууд бага; зөвхөн own account-аар demonstrate. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Backend бүрт credential шалгаж, authenticated session-ийг server үүсгэх; frontend status-д итгэхгүй. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Login Response Handling on synthetic lab endpoint`
- **Summary:** Нэвтрэлтийн хариу боловсруулах алдаа; ажиглагдсан ялгаа нь `Сэжигтэй нь: invalid login-ийн дараа **шинэ authenticated session** үүсч protected `/lab/me` өөрийн test user-ийн контент өгвөл; зөвхөн текст `ok` байхад хангалтгүй.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `POST /lab/login HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** Authentication gate эвдэрвэл C/I өндөр, A шууд бага; зөвхөн own account-аар demonstrate.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Backend бүрт credential шалгаж, authenticated session-ийг server үүсгэх; frontend status-д итгэхгүй.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `POST /lab/login HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `POST /lab/login HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 5.2 Password Reset Token Validation — Нууц үг сэргээх token шалгалтын алдаа

**A. Vulnerability Name.** **Password Reset Token Validation** — Нууц үг сэргээх token шалгалтын алдаа.

**B. What Is It? (Энгийнээр).** Нэг удаагийн түлхүүр хугацаагүй эсвэл дахин ашиглагдвал өмнөх түлхүүр хэвээр ажиллах мэт.

**C. Why Does It Happen? (Root cause).** Reset token expire, single-use, account-binding шалгалт байхгүй.

**D. Where to Look? (Тестийн байрлал).** `/forgot-password`, `/reset?token=`, reset form, email-link, cookie. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **Web Security Academy Authentication**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Өөрийн account A-ийн reset link үүсгээд тусгаарласан лабд password reset хий; хуучин token-оор дахин **validation-only** шалга (хэрэв state change шаардагдвал isolated lab only).
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'Lab reset token must be single-use and expire promptly'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/reset/validate?token=OWN_LAB_TOKEN HTTP/1.1
Host: app.lab.test
```

```http
HTTP/1.1 400 Bad Request

{"valid":false,"reason":"used"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Token хэрэглэсний дараа тухайн token серверээс хүчинтэй хэвээр байвал vulnerable; validator 200 ганцаараа final reset боломжийг нотлохгүй.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Token хэрэглэсний дараа тухайн token серверээс хүчинтэй хэвээр байвал vulnerable; validator 200 ганцаараа final reset боломжийг нотлохгүй. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Link preview, frontend caching, test token хараахан хэрэглээгүй; confirm server-side state. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** Own reset token дахин ажиллавал account takeover болзошгүй; C/I өндөр. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** CSPRNG token, short TTL, one-time use, token hash in storage, account/session binding, invalidate on use. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Password Reset Token Validation on synthetic lab endpoint`
- **Summary:** Нууц үг сэргээх token шалгалтын алдаа; ажиглагдсан ялгаа нь `Token хэрэглэсний дараа тухайн token серверээс хүчинтэй хэвээр байвал vulnerable; validator 200 ганцаараа final reset боломжийг нотлохгүй.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/reset/validate?token=OWN_LAB_TOKEN HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** Own reset token дахин ажиллавал account takeover болзошгүй; C/I өндөр.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** CSPRNG token, short TTL, one-time use, token hash in storage, account/session binding, invalidate on use.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/reset/validate?token=OWN_LAB_TOKEN HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/reset/validate?token=OWN_LAB_TOKEN HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 5.3 Account Registration Verification — Бүртгэлийн баталгаажуулалтын алдаа

**A. Vulnerability Name.** **Account Registration Verification** — Бүртгэлийн баталгаажуулалтын алдаа.

**B. What Is It? (Энгийнээр).** Шинээр бүртгүүлсэн хүн email ownership нотлоогүй ч баталгаажсан эрхтэй болж буй мэт.

**C. Why Does It Happen? (Root cause).** Verification status-ийг frontend-ээс авдаг, backend workflow gate байхгүй.

**D. Where to Look? (Тестийн байрлал).** `POST /register`, `/verify`, `emailVerified` attribute, protected feature. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Өөрийн `test-a@example.invalid` synthetic account үүсгэ; verification хийгээгүй байхад protected email-verified-only action-д хараахан хандахгүй эсэхийг шалга.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'Manual: create own unverified test account; inspect emailVerified flag and protected action'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/verified-feature HTTP/1.1
Host: app.lab.test
Cookie: session=OWN_UNVERIFIED_SESSION
```

```http
HTTP/1.1 403 Forbidden

{"error":"email verification required"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Unverified test account protected action гүйцэтгэвэл proof; UI товч харагдахгүй нь backend protection биш.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Unverified test account protected action гүйцэтгэвэл proof; UI товч харагдахгүй нь backend protection биш. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Feature үнэндээ email verification шаардахгүй байж болно; requirement/role specification шаардана. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** И-мэйл identity assurance алдагдаж entitlement буруу олгогдох; C/I нөхцөлт. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): Medium.** Нөлөө, шаардлагатай эрх, attacker interaction-аас хамаарч Low–High хооронд хэлбэлзэнэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Server-side verified state, short-lived link, idempotent validation, state machine checks. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Account Registration Verification on synthetic lab endpoint`
- **Summary:** Бүртгэлийн баталгаажуулалтын алдаа; ажиглагдсан ялгаа нь `Unverified test account protected action гүйцэтгэвэл proof; UI товч харагдахгүй нь backend protection биш.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/verified-feature HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** И-мэйл identity assurance алдагдаж entitlement буруу олгогдох; C/I нөхцөлт.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Server-side verified state, short-lived link, idempotent validation, state machine checks.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/verified-feature HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/verified-feature HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 5.4 MFA Enforcement Bypass — Олон хүчин зүйлийн баталгаажуулалт алгасах

**A. Vulnerability Name.** **MFA Enforcement Bypass** — Олон хүчин зүйлийн баталгаажуулалт алгасах.

**B. What Is It? (Энгийнээр).** Хоёр дахь түлхүүр шаардсан хаалганы араар нэмэлт хаалга түгжээгүй мэт.

**C. Why Does It Happen? (Root cause).** MFA pending session-ийг full-auth session-тэй андуурах.

**D. Where to Look? (Тестийн байрлал).** `/login`, `/mfa/verify`, session state, protected API. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Own account A дээр MFA асааж, primary login-ийн дараа MFA verification хийгээгүйгээр **зөвхөн өөрийн profile read** request илгээ.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'Inspect own pre-MFA session in Burp Repeater; request only /lab/me'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/me HTTP/1.1
Host: app.lab.test
Cookie: session=OWN_PRE_MFA_SESSION
```

```http
HTTP/1.1 401 Unauthorized

{"error":"mfa_required"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** MFA-г дуусгаагүй session-ээр protected account data авч чадвал finding.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** MFA-г дуусгаагүй session-ээр protected account data авч чадвал finding. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Remembered device/session, recovery flow, MFA already satisfied cache. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** C/I өндөр, account compromise defense bypass; precondition valid primary credential. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Backend authentication state machine (`password_ok`→`mfa_ok`), MFA gate every sensitive endpoint. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `MFA Enforcement Bypass on synthetic lab endpoint`
- **Summary:** Олон хүчин зүйлийн баталгаажуулалт алгасах; ажиглагдсан ялгаа нь `MFA-г дуусгаагүй session-ээр protected account data авч чадвал finding.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/me HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** C/I өндөр, account compromise defense bypass; precondition valid primary credential.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Backend authentication state machine (`password_ok`→`mfa_ok`), MFA gate every sensitive endpoint.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/me HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/me HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 5.5 Session Fixation — Session ID тогтоон үлдээх

**A. Vulnerability Name.** **Session Fixation** — Session ID тогтоон үлдээх.

**B. What Is It? (Энгийнээр).** Login хийхийн өмнөх session ID login-ийн дараа хэвээр үлдэж authentication-д холбогдох.

**C. Why Does It Happen? (Root cause).** Login / privilege change үед session ID regenerate хийхгүй.

**D. Where to Look? (Тестийн байрлал).** `Set-Cookie`, login response, authentication state transition. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Өөрийн lab browser-ийн pre-login cookie ID-г тэмдэглэ; test account-аар login хий; post-login ID солигдсон эсэхийг хар.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'Compare only OWN pre-login and post-login Set-Cookie values'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
POST /lab/login HTTP/1.1
Host: app.lab.test
Cookie: sid=LAB_PRELOGIN

username=lab-a&password=OWN_TEST_PASSWORD
```

```http
HTTP/1.1 302 Found
Set-Cookie: sid=LAB_ROTATED; HttpOnly; SameSite=Lax
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Session ID ижил хэвээр байх нь indicator; exploitable fixation гэдгийг тогтоохын тулд attacker-controlled pre-session binding зэрэг нэмэлт нөхцөл шалга.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Session ID ижил хэвээр байх нь indicator; exploitable fixation гэдгийг тогтоохын тулд attacker-controlled pre-session binding зэрэг нэмэлт нөхцөл шалга. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Stateless signed session, login шинэ authentication cookie-оос гадна anonymous cookie хэвээр үлдэж болно. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** Нөхцөл бүрдвэл account impersonation; C/I өндөр. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): Medium.** Нөлөө, шаардлагатай эрх, attacker interaction-аас хамаарч Low–High хооронд хэлбэлзэнэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Regenerate session ID on login/elevation; invalidate pre-auth ID; secure cookie flags. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Session Fixation on synthetic lab endpoint`
- **Summary:** Session ID тогтоон үлдээх; ажиглагдсан ялгаа нь `Session ID ижил хэвээр байх нь indicator; exploitable fixation гэдгийг тогтоохын тулд attacker-controlled pre-session binding зэрэг нэмэлт нөхцөл шалга.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `POST /lab/login HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** Нөхцөл бүрдвэл account impersonation; C/I өндөр.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Regenerate session ID on login/elevation; invalidate pre-auth ID; secure cookie flags.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `POST /lab/login HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `POST /lab/login HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 5.6 Logout Session Invalidation — Гарсны дараах session хүчинтэй үлдэх

**A. Vulnerability Name.** **Logout Session Invalidation** — Гарсны дараах session хүчинтэй үлдэх.

**B. What Is It? (Энгийнээр).** Гарлаа гэсэн ч хуучин нэвтрэх тасалбар ашиглагдаж байгаа мэт.

**C. Why Does It Happen? (Root cause).** Logout нь зөвхөн client cookie устгадаг, backend token/session revoke хийхгүй.

**D. Where to Look? (Тестийн байрлал).** `POST /logout`, `Cookie`, `Authorization: Bearer` token, `/me`. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Өөрийн lab session-ийн token-ийг зөвхөн local evidence-д аваад logout хий; token-оор ганц `/lab/me` read request replay хий.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'Use Burp Repeater: replay own saved /lab/me request AFTER own logout'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/me HTTP/1.1
Host: app.lab.test
Cookie: sid=OWN_LOGGED_OUT_SESSION
```

```http
HTTP/1.1 401 Unauthorized

{"error":"session revoked"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Logout-ийн дараа token нь эхний 200-тэй ижил private data буцаавал; server-side expiration strategy-тэй харьцуул.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Logout-ийн дараа token нь эхний 200-тэй ижил private data буцаавал; server-side expiration strategy-тэй харьцуул. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** JWT stateless logout-ийн design, access-token TTL, refresh revoke; policy мөн эсэх. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** Хулгайлагдсан хуучин session ашиглалтын хугацаа өснө; C/I нөхцөлт. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): Medium.** Нөлөө, шаардлагатай эрх, attacker interaction-аас хамаарч Low–High хооронд хэлбэлзэнэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Session revocation list, short access TTL, revoke refresh token, rotate credentials. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Logout Session Invalidation on synthetic lab endpoint`
- **Summary:** Гарсны дараах session хүчинтэй үлдэх; ажиглагдсан ялгаа нь `Logout-ийн дараа token нь эхний 200-тэй ижил private data буцаавал; server-side expiration strategy-тэй харьцуул.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/me HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** Хулгайлагдсан хуучин session ашиглалтын хугацаа өснө; C/I нөхцөлт.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Session revocation list, short access TTL, revoke refresh token, rotate credentials.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/me HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/me HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 5.7 Remember-me Token Weakness — Намайг сана токены сул хамгаалалт

**A. Vulnerability Name.** **Remember-me Token Weakness** — Намайг сана токены сул хамгаалалт.

**B. What Is It? (Энгийнээр).** Урт хугацааны session тасалбар нь predict/rotate хийгдэхгүй байж болно.

**C. Why Does It Happen? (Root cause).** Predictable, unbound, unhashed remember-me cookie болон revoke механизм дутуу.

**D. Where to Look? (Тестийн байрлал).** `remember_me`, persistent cookie, logout and password change. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Өөрийн account дээр remember-me on/off хийж cookie expiration, rotation, password change logout policy-г зөвхөн өөрийн session-д шалга.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'DevTools Application/Storage > Cookies: inspect own remember-me expiry and rotation'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/me HTTP/1.1
Host: app.lab.test
Cookie: remember=OWN_LAB_TOKEN
```

```http
HTTP/1.1 200 OK
Set-Cookie: remember=ROTATED_OWN_TOKEN; HttpOnly; Secure
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Long-lived token client-д plain predictable мэдээлэлтэй бол өөр finding; cookie duration ганцаараа defect биш.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Long-lived token client-д plain predictable мэдээлэлтэй бол өөр finding; cookie duration ганцаараа defect биш. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Session cookie болон device-specific remember cookie ялга; browser extension эсэх. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** Хулгайлагдсан token дахин хэрэглэгдэх эрсдэл; C/I. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): Medium.** Нөлөө, шаардлагатай эрх, attacker interaction-аас хамаарч Low–High хооронд хэлбэлзэнэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Random opaque token, hash server-side, rotation/revocation, device management, Secure/HttpOnly/SameSite. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Remember-me Token Weakness on synthetic lab endpoint`
- **Summary:** Намайг сана токены сул хамгаалалт; ажиглагдсан ялгаа нь `Long-lived token client-д plain predictable мэдээлэлтэй бол өөр finding; cookie duration ганцаараа defect биш.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/me HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** Хулгайлагдсан token дахин хэрэглэгдэх эрсдэл; C/I.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Random opaque token, hash server-side, rotation/revocation, device management, Secure/HttpOnly/SameSite.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/me HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/me HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 5.8 JWT Signature / Claim Validation — JWT гарын үсэг болон claim шалгалт

**A. Vulnerability Name.** **JWT Signature / Claim Validation** — JWT гарын үсэг болон claim шалгалт.

**B. What Is It? (Энгийнээр).** Сервер токеныг уншдаг ч үнэн зөвийг нь шалгаагүй шиг.

**C. Why Does It Happen? (Root cause).** Signature verify, issuer/audience, expiry, accepted algorithm whitelist дутуу.

**D. Where to Look? (Тестийн байрлал).** `Authorization: Bearer`, signed JWT, `iss`, `aud`, `exp`, `alg`, `kid`. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Өөрийн test token-ийг local decode хий; **зөвхөн lab-д** payload-ийн harmless `displayName` claim-г өөрчилж signature unchanged replay хийгээд reject эсэхийг шалга.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
python3 -c 'import base64,json; x="eyJhbGciOiJIUzI1NiJ9"; print(json.loads(base64.urlsafe_b64decode(x+"="*(-len(x)%4))))'
```

`python3 -c` = нэг мөр local Python ажиллуулах; `base64.urlsafe_b64decode` нь JWT header decode хийнэ, **signature verify хийхгүй**.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/me HTTP/1.1
Host: app.lab.test
Authorization: Bearer OWN_MODIFIED_INVALID_SIGNATURE_JWT
```

```http
HTTP/1.1 401 Unauthorized

{"error":"invalid token signature"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Tampered JWT-ээр өмнөх authenticated state-г хадгалсан бол verify incomplete; bearer token-г cookie-оос ялга.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Tampered JWT-ээр өмнөх authenticated state-г хадгалсан бол verify incomplete; bearer token-г cookie-оос ялга. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** App browser cookie-г auth болгон ашигласан хэвээр, endpoint anonymous, decode болох нь verify гэсэн үг биш. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** Signature bypass нь identity/role forgery хүргэж болно; C/I өндөр. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Pinned algorithms/keys, verify `iss`/`aud`/`exp`/`nbf`, safe key rotation, least privilege. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `JWT Signature / Claim Validation on synthetic lab endpoint`
- **Summary:** JWT гарын үсэг болон claim шалгалт; ажиглагдсан ялгаа нь `Tampered JWT-ээр өмнөх authenticated state-г хадгалсан бол verify incomplete; bearer token-г cookie-оос ялга.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/me HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** Signature bypass нь identity/role forgery хүргэж болно; C/I өндөр.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Pinned algorithms/keys, verify `iss`/`aud`/`exp`/`nbf`, safe key rotation, least privilege.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/me HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/me HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 5.9 OAuth 2.0 Redirect / State Validation — OAuth 2.0 redirect ба state шалгалт

**A. Vulnerability Name.** **OAuth 2.0 Redirect / State Validation** — OAuth 2.0 redirect ба state шалгалт.

**B. What Is It? (Энгийнээр).** Гуравдагч identity provider руу явсан буцах хаяг зөв эсэхийг шалгаагүй.

**C. Why Does It Happen? (Root cause).** `redirect_uri` allowlist, `state` CSRF binding, PKCE check, token audience handling буруу.

**D. Where to Look? (Тестийн байрлал).** `/authorize`, `/callback`, `redirect_uri`, `state`, `code`, `code_challenge`. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **Web Security Academy OAuth Authentication**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Өөрийн local mock OAuth client/server эсвэл Academy OAuth lab-д authorization request-ийг ажигла; зөвшөөрөгдсөн callback-аас өөр localhost URI-г reject эсэхийг шалга.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'Manual lab: compare authorized redirect_uri vs unregistered localhost callback'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/oauth/authorize?client_id=lab&redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fwrong&state=lab123 HTTP/1.1
Host: auth.lab.test
```

```http
HTTP/1.1 400 Bad Request

{"error":"invalid_redirect_uri"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Unregistered callback-д auth code очвол genuine redirect validation issue; third-party provider руу request илгээхгүй.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Unregistered callback-д auth code очвол genuine redirect validation issue; third-party provider руу request илгээхгүй. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Wildcard зөвшөөрөгдсөн dev callback, provider error redirect-ийн харилцан ялгаа. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** Auth code leak/account linking risk; C/I өндөр, prerequisite OAuth login flow. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Exact redirect_uri allowlist, PKCE, opaque per-session state, secure code exchange. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `OAuth 2.0 Redirect / State Validation on synthetic lab endpoint`
- **Summary:** OAuth 2.0 redirect ба state шалгалт; ажиглагдсан ялгаа нь `Unregistered callback-д auth code очвол genuine redirect validation issue; third-party provider руу request илгээхгүй.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/oauth/authorize?client_id=lab&redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fwrong&state=lab123 HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** Auth code leak/account linking risk; C/I өндөр, prerequisite OAuth login flow.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Exact redirect_uri allowlist, PKCE, opaque per-session state, secure code exchange.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/oauth/authorize?client_id=lab&redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fwrong&state=lab123 HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/oauth/authorize?client_id=lab&redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fwrong&state=lab123 HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 5.10 OpenID Connect (OIDC) Validation — OpenID Connect identity claim баталгаажуулалт

**A. Vulnerability Name.** **OpenID Connect (OIDC) Validation** — OpenID Connect identity claim баталгаажуулалт.

**B. What Is It? (Энгийнээр).** ID token-ийг зөв provider/audience/nonce-тэй гэдгийг батлаагүй.

**C. Why Does It Happen? (Root cause).** `iss`, `aud`, `nonce`, `exp`, signature, `azp` claim болон JWKS key validation буруу.

**D. Where to Look? (Тестийн байрлал).** `/.well-known/openid-configuration`, `/callback`, ID token. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Өөрийн lab OIDC login-ийн ID token claims-ийг decode (verify-тэй андуурахгүй); wrong audience/expired test token reject эсэхийг isolated fixture-д шалга.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'Use own mock OIDC issuer and client; no real-provider token editing'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
POST /lab/oidc/callback HTTP/1.1
Host: app.lab.test
Content-Type: application/json

{"id_token":"OWN_LAB_WRONG_AUDIENCE_TOKEN"}
```

```http
HTTP/1.1 401 Unauthorized

{"error":"invalid_audience"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Wrong-audience token authentication grant авбал OIDC validation defect.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Wrong-audience token authentication grant авбал OIDC validation defect. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** ID token vs access token буруу сонгосон; client-specific accepted audiences. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** Identity spoofing/account takeover risk; C/I өндөр. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Use certified OIDC library, signature/issuer/audience/nonce validation, safe JWKS caching. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `OpenID Connect (OIDC) Validation on synthetic lab endpoint`
- **Summary:** OpenID Connect identity claim баталгаажуулалт; ажиглагдсан ялгаа нь `Wrong-audience token authentication grant авбал OIDC validation defect.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `POST /lab/oidc/callback HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** Identity spoofing/account takeover risk; C/I өндөр.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Use certified OIDC library, signature/issuer/audience/nonce validation, safe JWKS caching.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `POST /lab/oidc/callback HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `POST /lab/oidc/callback HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 5.11 Account Enumeration — Бүртгэлтэй эсэх мэдээлэл илчлэгдэх

**A. Vulnerability Name.** **Account Enumeration** — Бүртгэлтэй эсэх мэдээлэл илчлэгдэх.

**B. What Is It? (Энгийнээр).** Хэрэглэгчийн нэр оруулахад бүртгэлтэй эсэхийг өөр өөр хариултаар хэлдэг.

**C. Why Does It Happen? (Root cause).** Login/reset error message, timing, status differential.

**D. Where to Look? (Тестийн байрлал).** `/forgot-password`, `/register`, login error body, response time. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Өөрийн **нэг бүртгэлтэй lab account** ба **нэг бүртгэлгүй synthetic** email-ээр ганц password reset request тус бүр илгээ; email delivery зөвхөн mock mailbox.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'Compare two OWN synthetic usernames, one registered and one unregistered'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
POST /lab/forgot-password HTTP/1.1
Host: app.lab.test
Content-Type: application/json

{"email":"unknown-test@example.invalid"}
```

```http
HTTP/1.1 200 OK

{"message":"If an account exists, instructions were sent"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Нэг нь `User does not exist`, нөгөө нь `Email sent` гэвэл enumeration; impact хязгаарлагдмал байж болно.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Нэг нь `User does not exist`, нөгөө нь `Email sent` гэвэл enumeration; impact хязгаарлагдмал байж болно. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Rate limit/captcha/network jitter, response generic боловч duration variation non-significant. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** Account metadata reveal; C бага–дунд, identity exposure/privacy context-аас шалтгаална. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): Low.** Нөлөө ихэнхдээ context-dependent; CVSS ихэвчлэн Low/Informational байж болно. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Generic messages, constant-work approach, monitoring and rate limit without account lockout abuse. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Account Enumeration on synthetic lab endpoint`
- **Summary:** Бүртгэлтэй эсэх мэдээлэл илчлэгдэх; ажиглагдсан ялгаа нь `Нэг нь `User does not exist`, нөгөө нь `Email sent` гэвэл enumeration; impact хязгаарлагдмал байж болно.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `POST /lab/forgot-password HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** Account metadata reveal; C бага–дунд, identity exposure/privacy context-аас шалтгаална.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Generic messages, constant-work approach, monitoring and rate limit without account lockout abuse.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `POST /lab/forgot-password HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `POST /lab/forgot-password HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### Chapter 5 — Consolidated review

**Хамгийн чухал:** Confirmed finding бол зөвхөн response string биш, precondition + policy boundary + actual effect + negative control-оор дэмжигдсэн дүгнэлт. `Finding ID`, `confidence (hypothesis/likely/confirmed)`, severity rationale-г нэгтгэ.

<a id="chapter-6"></a>
## Chapter 6 — Authorization Testing

Object ID-г таах чадвар нь permission биш. Хэрэглэгч A/B, role viewer/admin, tenant T1/T2 хосоор **зөвхөн өөрийн fixture** тест хийнэ.

> **Сургалтын маршрут:** Эхлээд raw HTTP-г ойлго → baseline → own controlled change → negative control → state validation → report. Доорх бүх `/lab` URL ба response нь **synthetic**. Бодит дасгалыг дурдсан lab-ийн сэдвийн exercise-д хий.

### 6.1 IDOR / BOLA — Объект түвшний эрхийн хяналт алдаа

**A. Vulnerability Name.** **IDOR / BOLA** — Объект түвшний эрхийн хяналт алдаа.

**B. What Is It? (Энгийнээр).** Өөрийн шүүгээнээс хөрш шүүгээний дугаар оруулаад түгжээ тайлагдах шиг.

**C. Why Does It Happen? (Root cause).** Backend нь object ownership/tenant membership-ийг query + authenticated subject-тай тулгахгүй.

**D. Where to Look? (Тестийн байрлал).** `GET /api/orders/{id}`, `userId`, `documentId`, GraphQL object(id), UUID/sequence ID. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **Web Security Academy Access control / OWASP crAPI**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Өөрийн Account A ба B үүсгээд B-д synthetic private object хийнэ; A-аар A object-г read; дараа B object ID-ийг A session-д ганц удаа шалга.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'Burp Repeater: A cookie + B-owned synthetic object ID; GET only'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/api/documents/B-OWNED-002 HTTP/1.1
Host: app.lab.test
Cookie: sid=OWN_ACCOUNT_A_SESSION
```

```http
HTTP/1.1 403 Forbidden

{"error":"not authorized"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** A-ийн session B-ийн private test document-ийн marker `B_PRIVATE_TEST`-ийг өгвөл confirmed.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** A-ийн session B-ийн private test document-ийн marker `B_PRIVATE_TEST`-ийг өгвөл confirmed. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Object public/shared эсэх, B account A-тай organization membership shared эсэх, cache. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** Unauthorized read = C High, unauthorized update = I High (production-д бүү test); A usually none. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Every object request: `WHERE id=? AND owner_id=current_user` буюу server-side policy; deny-by-default. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `IDOR / BOLA on synthetic lab endpoint`
- **Summary:** Объект түвшний эрхийн хяналт алдаа; ажиглагдсан ялгаа нь `A-ийн session B-ийн private test document-ийн marker `B_PRIVATE_TEST`-ийг өгвөл confirmed.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/api/documents/B-OWNED-002 HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** Unauthorized read = C High, unauthorized update = I High (production-д бүү test); A usually none.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Every object request: `WHERE id=? AND owner_id=current_user` буюу server-side policy; deny-by-default.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/api/documents/B-OWNED-002 HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/api/documents/B-OWNED-002 HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 6.2 Horizontal Privilege Escalation — Ижил түвшний хэрэглэгч хооронд эрх хэтрүүлэх

**A. Vulnerability Name.** **Horizontal Privilege Escalation** — Ижил түвшний хэрэглэгч хооронд эрх хэтрүүлэх.

**B. What Is It? (Энгийнээр).** Ижил role-той хоёр хэрэглэгч нэгний private workflow-д нөгөө нь хандах.

**C. Why Does It Happen? (Root cause).** Current user vs target account relationship шалгадаггүй.

**D. Where to Look? (Тестийн байрлал).** `/users/{id}/settings`, message, tickets, profile API, tenant-specific account. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Role=viewer хоёр account A/B-тай own fixtures; A-аас B-ийн private settings-ийг **GET**-ээр шалга.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'Use one controlled GET with A session and B-owned test URL'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/users/B-02/settings HTTP/1.1
Host: app.lab.test
Cookie: sid=A
```

```http
HTTP/1.1 403 Forbidden

{"error":"not owner"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** B-ийн private setting A-аар ирвэл suspicious; role-level shared settings бол normal.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** B-ийн private setting A-аар ирвэл suspicious; role-level shared settings бол normal. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Public profile vs private settings, own organization collaboration. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** C/I High байж болно, object sensitivity-аас хамаарна. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Subject-object ownership policy, scoped query and regression tests. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Horizontal Privilege Escalation on synthetic lab endpoint`
- **Summary:** Ижил түвшний хэрэглэгч хооронд эрх хэтрүүлэх; ажиглагдсан ялгаа нь `B-ийн private setting A-аар ирвэл suspicious; role-level shared settings бол normal.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/users/B-02/settings HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** C/I High байж болно, object sensitivity-аас хамаарна.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Subject-object ownership policy, scoped query and regression tests.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/users/B-02/settings HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/users/B-02/settings HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 6.3 Vertical Privilege Escalation — Role түвшин дээшлэх

**A. Vulnerability Name.** **Vertical Privilege Escalation** — Role түвшин дээшлэх.

**B. What Is It? (Энгийнээр).** Энгийн ажилтан admin хийх үйлдэлд backend шалгалтгүй хандах.

**C. Why Does It Happen? (Root cause).** UI hidden button-оор хязгаарлаад server-side role permission шалгадаггүй.

**D. Where to Look? (Тестийн байрлал).** `/admin/*`, `/api/users/roles`, admin feature, authenticated role claims. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Өөрийн lab viewer ба admin account; viewer-аас **safe read-only admin test endpoint**-д хандах; side-effect method ажиллуулахгүй.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'Burp Repeater: viewer token -> admin read-only lab endpoint'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/admin/audit-summary HTTP/1.1
Host: app.lab.test
Cookie: sid=OWN_VIEWER_SESSION
```

```http
HTTP/1.1 403 Forbidden

{"error":"insufficient role"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Viewer admin-only synthetic summary уншвал finding; admin UI харагдах нь finding биш.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Viewer admin-only synthetic summary уншвал finding; admin UI харагдах нь finding биш. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Endpoint admin-only эсэх requirement, debug public status гэж зориуд гаргасан эсэх. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** C/I high/critical depending on admin function. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Per-route RBAC/ABAC enforced backend, tested negative permissions. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Vertical Privilege Escalation on synthetic lab endpoint`
- **Summary:** Role түвшин дээшлэх; ажиглагдсан ялгаа нь `Viewer admin-only synthetic summary уншвал finding; admin UI харагдах нь finding биш.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/admin/audit-summary HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** C/I high/critical depending on admin function.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Per-route RBAC/ABAC enforced backend, tested negative permissions.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/admin/audit-summary HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/admin/audit-summary HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 6.4 Broken Access Control (Default-Deny) — Нэгдсэн access control-ийн алдаа

**A. Vulnerability Name.** **Broken Access Control (Default-Deny)** — Нэгдсэн access control-ийн алдаа.

**B. What Is It? (Энгийнээр).** Хаалганы зарим зам хамгаалалттай, нэг зам нээлттэй.

**C. Why Does It Happen? (Root cause).** Authorization middleware route бүрт ижил биш, default allow.

**D. Where to Look? (Тестийн байрлал).** `/v1/report` vs `/v2/report`, alias paths, POST vs GET, public/private boundary. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Өөрийн test account-аар нэг read-only feature-ийн хоёр canonical route/version-ийг шалга.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'Compare only two in-scope aliases for one protected lab resource'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/v2/private-summary HTTP/1.1
Host: app.lab.test
```

```http
HTTP/1.1 401 Unauthorized

{"error":"authentication required"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Unauthenticated alias дээр private data ирвэл confirmed; 404 болон 200 public page ялга.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Unauthenticated alias дээр private data ирвэл confirmed; 404 болон 200 public page ялга. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Versioned route intentionally public, upstream auth vs app auth differences. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** C/I өргөн хүрээтэй бол High. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Central authorization middleware, deny-by-default, route audit and tests. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Broken Access Control (Default-Deny) on synthetic lab endpoint`
- **Summary:** Нэгдсэн access control-ийн алдаа; ажиглагдсан ялгаа нь `Unauthenticated alias дээр private data ирвэл confirmed; 404 болон 200 public page ялга.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/v2/private-summary HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** C/I өргөн хүрээтэй бол High.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Central authorization middleware, deny-by-default, route audit and tests.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/v2/private-summary HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/v2/private-summary HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 6.5 BFLA / Missing Function-Level Authorization — Функц/үйлдлийн түвшний эрхгүй хандалт

**A. Vulnerability Name.** **BFLA / Missing Function-Level Authorization** — Функц/үйлдлийн түвшний эрхгүй хандалт.

**B. What Is It? (Энгийнээр).** Read эрхтэй хэрэглэгч export/admin function-г дуудах боломжтой.

**C. Why Does It Happen? (Root cause).** Function role/permission check missing, endpoint permission mapping дутуу.

**D. Where to Look? (Тестийн байрлал).** `/api/admin/export`, `/api/approve`, GraphQL mutation, action names. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Viewer-role own account-аар synthetic, side-effect үгүй `/lab/admin/export-preview` зэрэг read-only lab function шалга.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'No real export/download; use non-sensitive preview endpoint in isolated lab'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/admin/export-preview HTTP/1.1
Host: app.lab.test
Authorization: Bearer OWN_VIEWER_TOKEN
```

```http
HTTP/1.1 403 Forbidden

{"error":"permission denied"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Viewer-д admin-only lab preview буцаавал BFLA; route labeling proof-тэй байх.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Viewer-д admin-only lab preview буцаавал BFLA; route labeling proof-тэй байх. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Public export metadata болон actual export endpoint ялга. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** C high, I high if state change possible (do not execute production mutation). **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Action-level permission check + object-level check, least privilege. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `BFLA / Missing Function-Level Authorization on synthetic lab endpoint`
- **Summary:** Функц/үйлдлийн түвшний эрхгүй хандалт; ажиглагдсан ялгаа нь `Viewer-д admin-only lab preview буцаавал BFLA; route labeling proof-тэй байх.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/admin/export-preview HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** C high, I high if state change possible (do not execute production mutation).
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Action-level permission check + object-level check, least privilege.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/admin/export-preview HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/admin/export-preview HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 6.6 Mass Assignment — JSON field-д хэт их итгэх

**A. Vulnerability Name.** **Mass Assignment** — JSON field-д хэт их итгэх.

**B. What Is It? (Энгийнээр).** Хэрэглэгч өөрийн нэрийг солих form-аар `role`-оо солих боломжтой мэт.

**C. Why Does It Happen? (Root cause).** User-controlled JSON-г ORM/model-д unrestricted merge хийдэг.

**D. Where to Look? (Тестийн байрлал).** `PUT /users/me`, `PATCH /profile`, `role`, `isAdmin`, `verified`, `tenantId`. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **Web Security Academy API testing / OWASP crAPI**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Own lab user-ийн profile request-д harmless unknown `labNote` field нэмж, field accepted/ignored шалга; **role/isAdmin өөрчлөх тест зөвхөн isolated lab**.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'Lab-only: compare normal profile JSON and JSON with extra labNote'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
PATCH /lab/me HTTP/1.1
Host: app.lab.test
Content-Type: application/json

{"displayName":"Lab A","labNote":"EXTRA_FIELD"}
```

```http
HTTP/1.1 200 OK

{"displayName":"Lab A"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Unexpected field server-side persist хийх нь indicator; privileged property truly modified эсэх isolated lab-д шалга.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Unexpected field server-side persist хийх нь indicator; privileged property truly modified эсэх isolated lab-д шалга. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Server echo нь persistence биш, schema allows extension fields байж болно. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** Role/tenant modification possible бол I High; property sensitivity хамаарна. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Explicit field allowlist DTO; separate admin-only update path; server-owned attributes. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Mass Assignment on synthetic lab endpoint`
- **Summary:** JSON field-д хэт их итгэх; ажиглагдсан ялгаа нь `Unexpected field server-side persist хийх нь indicator; privileged property truly modified эсэх isolated lab-д шалга.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `PATCH /lab/me HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** Role/tenant modification possible бол I High; property sensitivity хамаарна.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Explicit field allowlist DTO; separate admin-only update path; server-owned attributes.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `PATCH /lab/me HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `PATCH /lab/me HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 6.7 Tenant Isolation Failure — Байгууллага хооронд тусгаарлалт алдагдах

**A. Vulnerability Name.** **Tenant Isolation Failure** — Байгууллага хооронд тусгаарлалт алдагдах.

**B. What Is It? (Энгийнээр).** Нэг байгууллагын хэрэглэгч нөгөө байгууллагын private object-г харах.

**C. Why Does It Happen? (Root cause).** DB query tenant scope-гүй, tenant header/user input-д итгэдэг.

**D. Where to Look? (Тестийн байрлал).** `X-Tenant-ID`, `/org/{id}/`, JWT `tenant`, workspace id, API lists. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Өөрийн эрхээр үүсгэсэн tenant T1/T2 хоёр test environment-д ажилла; T1 token + T2 synthetic object ID-г safe GET request-д ашигла.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'Two owned test tenants only; observe T1 token vs T2 synthetic object'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/tenants/T2/documents/D2 HTTP/1.1
Host: app.lab.test
Cookie: sid=T1_USER
```

```http
HTTP/1.1 403 Forbidden

{"error":"tenant mismatch"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** T1 session T2 private marker буцаавал confirmed cross-tenant leakage.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** T1 session T2 private marker буцаавал confirmed cross-tenant leakage. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Shared group, cross-tenant collaboration feature, admin scope ялга. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** C High/Critical нөхцөлт, compliance/data privacy нөлөөтэй. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Enforce tenant context server-side every query/cache key, integration tests for all roles. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Tenant Isolation Failure on synthetic lab endpoint`
- **Summary:** Байгууллага хооронд тусгаарлалт алдагдах; ажиглагдсан ялгаа нь `T1 session T2 private marker буцаавал confirmed cross-tenant leakage.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/tenants/T2/documents/D2 HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** C High/Critical нөхцөлт, compliance/data privacy нөлөөтэй.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Enforce tenant context server-side every query/cache key, integration tests for all roles.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/tenants/T2/documents/D2 HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/tenants/T2/documents/D2 HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 6.8 Insecure Direct Function Invocation — API path өөрчилж protected function дуудах

**A. Vulnerability Name.** **Insecure Direct Function Invocation** — API path өөрчилж protected function дуудах.

**B. What Is It? (Энгийнээр).** UI дээр дарагддаггүй товчийг API endpoint руу шууд очиж ашиглах боломжтой.

**C. Why Does It Happen? (Root cause).** Presentation-layer controls-ийг server-side auth орлуулсан.

**D. Where to Look? (Тестийн байрлал).** Hidden UI route, `GET /lab/internal/status`, feature flag, API methods. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Own test user interface-аас hidden admin endpoint нэр илэрвэл зөвхөн harmless status read lab endpoint-ийг шалга.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'Observe request only; never call production approve/delete/update endpoint'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/internal/admin-summary HTTP/1.1
Host: app.lab.test
Cookie: sid=OWN_USER
```

```http
HTTP/1.1 403 Forbidden

{"error":"forbidden"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Unauthorized admin-specific private test data response бодитоор ирвэл finding.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Unauthorized admin-specific private test data response бодитоор ирвэл finding. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Endpoint public health telemetry байх боломжтой, sensitive proof шаардлагатай. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** C/I scenario-dependent. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): Medium.** Нөлөө, шаардлагатай эрх, attacker interaction-аас хамаарч Low–High хооронд хэлбэлзэнэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Backend authorization decorators on all functions, prohibit client-only checks. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Insecure Direct Function Invocation on synthetic lab endpoint`
- **Summary:** API path өөрчилж protected function дуудах; ажиглагдсан ялгаа нь `Unauthorized admin-specific private test data response бодитоор ирвэл finding.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/internal/admin-summary HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** C/I scenario-dependent.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Backend authorization decorators on all functions, prohibit client-only checks.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/internal/admin-summary HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/internal/admin-summary HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### Chapter 6 — Consolidated review

**Хамгийн чухал:** Confirmed finding бол зөвхөн response string биш, precondition + policy boundary + actual effect + negative control-оор дэмжигдсэн дүгнэлт. `Finding ID`, `confidence (hypothesis/likely/confirmed)`, severity rationale-г нэгтгэ.

<a id="chapter-7"></a>
## Chapter 7 — Injection Vulnerabilities

Input код/асуулгын **өгөгдөл** биш **синтакс** болон тайлбарлагдах үед injection үүснэ. Production-д blind extraction, file read, OS command, credential bypass, data mutation хийхгүй.

> **Сургалтын маршрут:** Эхлээд raw HTTP-г ойлго → baseline → own controlled change → negative control → state validation → report. Доорх бүх `/lab` URL ба response нь **synthetic**. Бодит дасгалыг дурдсан lab-ийн сэдвийн exercise-д хий.

### 7.1 SQL Injection (SQLi) — SQL query-д user input код болж орох

**A. Vulnerability Name.** **SQL Injection (SQLi)** — SQL query-д user input код болж орох.

**B. What Is It? (Энгийнээр).** Ажилтны нэрийг бичих талбарт SQL синтакс нэмэхэд database query-ийн утга өөрчлөгдөх.

**C. Why Does It Happen? (Root cause).** String concatenation/unsafe dynamic SQL; parameterized query хэрэглэдэггүй.

**D. Where to Look? (Тестийн байрлал).** `?id=`, `?sort=`, search, filter, login, JSON `userId`. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **Web Security Academy SQL injection**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Web Security Academy **SQL injection** lab-д baseline search request; `'` ба boolean TRUE/FALSE-ийн хос **read-only** test хийж response diff-ийг шалга; production data enumerate хийхгүй.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' "1 AND 1=1" "1 AND 1=2"
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/products?id=1%20AND%201%3D1 HTTP/1.1
Host: app.lab.test
```

```http
HTTP/1.1 200 OK

{"items":[{"id":1,"label":"LAB_PRODUCT"}]}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** `1 AND 1=1` ба `1 AND 1=2`-д data semantics ялгаатай бөгөөд controls дээр тогтвортой давтагдвал strong indicator. Error/500 ганцаараа proof биш.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** `1 AND 1=1` ба `1 AND 1=2`-д data semantics ялгаатай бөгөөд controls дээр тогтвортой давтагдвал strong indicator. Error/500 ганцаараа proof биш. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Application-level filter, caching, input parse fallback, query logic legitimate variation. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** C/I High; availability claims-ийг actual stress хийхгүй, precondition injectable SQL path. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Prepared statements/bound parameters; allowlist sort columns; least-privileged DB account. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `SQL Injection (SQLi) on synthetic lab endpoint`
- **Summary:** SQL query-д user input код болж орох; ажиглагдсан ялгаа нь ``1 AND 1=1` ба `1 AND 1=2`-д data semantics ялгаатай бөгөөд controls дээр тогтвортой давтагдвал strong indicator. Error/500 ганцаараа proof биш.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/products?id=1%20AND%201%3D1 HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** C/I High; availability claims-ийг actual stress хийхгүй, precondition injectable SQL path.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Prepared statements/bound parameters; allowlist sort columns; least-privileged DB account.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/products?id=1%20AND%201%3D1 HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/products?id=1%20AND%201%3D1 HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 7.2 NoSQL Injection — NoSQL query бүтэцөд хэрэглэгчийн object нөлөөлөх

**A. Vulnerability Name.** **NoSQL Injection** — NoSQL query бүтэцөд хэрэглэгчийн object нөлөөлөх.

**B. What Is It? (Энгийнээр).** String гэж хүлээх талбарт JSON operator object ороход filter-ийн утга өөрчлөгдөх.

**C. Why Does It Happen? (Root cause).** Untrusted JSON MongoDB-style operator-ийг query object-д шууд merge хийдэг.

**D. Where to Look? (Тестийн байрлал).** `POST /search`, JSON filter, `$eq`, `$regex`, object parameters. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **Web Security Academy NoSQL injection**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: OWASP lab-д synthetic product filter-д literal string болон `$eq` object хийж server-side schema rejection харьцуул; **login bypass operator pattern ашиглахгүй**.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' '{"sku":"LAB-001"}' '{"sku":{"$eq":"LAB-001"}}'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
POST /lab/search HTTP/1.1
Host: app.lab.test
Content-Type: application/json

{"sku":{"$eq":"LAB-001"}}
```

```http
HTTP/1.1 400 Bad Request

{"error":"sku must be a string"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Typed string field operator object-ийг DB filter гэж ажиллуулж semantics нь өөрчлөгдвөл suspect; exact request/result compare.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Typed string field operator object-ийг DB filter гэж ажиллуулж semantics нь өөрчлөгдвөл suspect; exact request/result compare. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** API spec нь structured query filter зориуд дэмждэг эсэх, ORM object coercion. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** C/I potentially High; proof data sensitivity, access control-аас хамаарна. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Strict schema/type validation, operator allowlist, separate query builder, least privilege. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `NoSQL Injection on synthetic lab endpoint`
- **Summary:** NoSQL query бүтэцөд хэрэглэгчийн object нөлөөлөх; ажиглагдсан ялгаа нь `Typed string field operator object-ийг DB filter гэж ажиллуулж semantics нь өөрчлөгдвөл suspect; exact request/result compare.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `POST /lab/search HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** C/I potentially High; proof data sensitivity, access control-аас хамаарна.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Strict schema/type validation, operator allowlist, separate query builder, least privilege.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `POST /lab/search HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `POST /lab/search HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 7.3 OS Command Injection — OS shell command-д input орох

**A. Vulnerability Name.** **OS Command Injection** — OS shell command-д input орох.

**B. What Is It? (Энгийнээр).** Хайлт хийх талбарт бичсэн текстээ shell командад залгаж ажиллуулсан мэт.

**C. Why Does It Happen? (Root cause).** Shell invocation string concatenation (`sh -c`) with user input.

**D. Where to Look? (Тестийн байрлал).** `/ping`, diagnostics, image processing, filename, exporter. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **Web Security Academy OS command injection**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Тусгаарласан lab-д app-ийн ping/diagnostic parameter дээр **only `printf LAB_CMD_OK`** маркер ажиллуулах боломжийг шалга; production host дээр commands огт ажиллуулахгүй.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' '127.0.0.1; printf LAB_CMD_OK'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Command delimiter payload-ийг зөвхөн local isolated lab-д ашигла; production-д command ажиллуулахгүй.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/diagnostic?host=127.0.0.1%3B%20printf%20LAB_CMD_OK HTTP/1.1
Host: app.lab.test
```

```http
HTTP/1.1 400 Bad Request

{"error":"invalid host"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Isolated lab-ийн stdout-д `LAB_CMD_OK` гарвал shell parsing indicator; echoed payload stdout мөн үү шалга.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Isolated lab-ийн stdout-д `LAB_CMD_OK` гарвал shell parsing indicator; echoed payload stdout мөн үү шалга. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** App input echo, application өөрөө `LAB_CMD_OK` текст хэвлэсэн, network diagnostic команд байхгүй. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** RCE боломжит учраас C/I/A Critical байж болно; бодит системд exploit хийхгүй. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): Critical.** Capability батлагдвал өндөр нөлөөтэй; production-д аюултай exploit хийх шаардлагагүй. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** No shell; use argument arrays with strict allowed values, sandbox/service account privileges. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `OS Command Injection on synthetic lab endpoint`
- **Summary:** OS shell command-д input орох; ажиглагдсан ялгаа нь `Isolated lab-ийн stdout-д `LAB_CMD_OK` гарвал shell parsing indicator; echoed payload stdout мөн үү шалга.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/diagnostic?host=127.0.0.1%3B%20printf%20LAB_CMD_OK HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** RCE боломжит учраас C/I/A Critical байж болно; бодит системд exploit хийхгүй.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** No shell; use argument arrays with strict allowed values, sandbox/service account privileges.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/diagnostic?host=127.0.0.1%3B%20printf%20LAB_CMD_OK HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/diagnostic?host=127.0.0.1%3B%20printf%20LAB_CMD_OK HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 7.4 Server-Side Template Injection (SSTI) — Сервер талын template expression биелэх

**A. Vulnerability Name.** **Server-Side Template Injection (SSTI)** — Сервер талын template expression биелэх.

**B. What Is It? (Энгийнээр).** Загварт оруулах текстийг `{{...}}` илэрхийлэл болгон тайлбарласан.

**C. Why Does It Happen? (Root cause).** Template source content untrusted string-ээр үүсгэгдэж evaluation хийдэг.

**D. Where to Look? (Тестийн байрлал).** `/preview`, email template, PDF render, greeting personalization. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **Web Security Academy SSTI**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: SSTI lab-д эхлээд simple mathematical literal `{{7*7}}` эсвэл тухайн engine-ийн зөв syntax-тай harmless expression оруул; template engine тодорхойгүй бол шууд exploit дүгнэхгүй.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' '{{7*7}}'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
POST /lab/template-preview HTTP/1.1
Host: app.lab.test
Content-Type: text/plain

Hello {{7*7}}
```

```http
HTTP/1.1 200 OK

Hello {{7*7}}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Response `Hello 49` гарвал template evaluation сэжигтэй; app deliberately math parser эсэхийг шалга.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Response `Hello 49` гарвал template evaluation сэжигтэй; app deliberately math parser эсэхийг шалга. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Client-side template render, math formatting, different syntax engine, cached preview. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** Engine capability-аас хамаарах C/I/A High/Critical боломжтой. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Never render untrusted template source; allowlist data values, sandbox engine, escape template syntax. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Server-Side Template Injection (SSTI) on synthetic lab endpoint`
- **Summary:** Сервер талын template expression биелэх; ажиглагдсан ялгаа нь `Response `Hello 49` гарвал template evaluation сэжигтэй; app deliberately math parser эсэхийг шалга.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `POST /lab/template-preview HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** Engine capability-аас хамаарах C/I/A High/Critical боломжтой.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Never render untrusted template source; allowlist data values, sandbox engine, escape template syntax.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `POST /lab/template-preview HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `POST /lab/template-preview HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 7.5 LDAP Injection — LDAP filter string-д input шингэх

**A. Vulnerability Name.** **LDAP Injection** — LDAP filter string-д input шингэх.

**B. What Is It? (Энгийнээр).** Хайлтын нэрийг LDAP filter-ийн хаалт/operator гэж тайлбарлах.

**C. Why Does It Happen? (Root cause).** LDAP search filter-д user input-г escaping хийлгүй concatenate хийх.

**D. Where to Look? (Тестийн байрлал).** `/directory?name=`, SSO directory search, group lookup. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **OWASP WebGoat / private LDAP fixture**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Local LDAP test fixture-д `lab-user` болон `lab-user*` гэсэн harmless search-ийг харьцуул; real directory users-г enumerate хийхгүй.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'lab-user' 'lab-user*'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/directory?name=lab-user%2A HTTP/1.1
Host: app.lab.test
```

```http
HTTP/1.1 200 OK

{"users":[]}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Unescaped wildcard unintended broad synthetic result өгвөл suspect; backend query/filter logs-аар баталгаажуул.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Unescaped wildcard unintended broad synthetic result өгвөл suspect; backend query/filter logs-аар баталгаажуул. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Application өөрөө wildcard search зөвшөөрдөг legitimate feature байж болно. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** Directory data leak/auth flaw нөхцөлт; C Medium/High. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): Medium.** Нөлөө, шаардлагатай эрх, attacker interaction-аас хамаарч Low–High хооронд хэлбэлзэнэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** LDAP filter escaping RFC4515, query API and allowed search patterns. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `LDAP Injection on synthetic lab endpoint`
- **Summary:** LDAP filter string-д input шингэх; ажиглагдсан ялгаа нь `Unescaped wildcard unintended broad synthetic result өгвөл suspect; backend query/filter logs-аар баталгаажуул.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/directory?name=lab-user%2A HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** Directory data leak/auth flaw нөхцөлт; C Medium/High.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** LDAP filter escaping RFC4515, query API and allowed search patterns.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/directory?name=lab-user%2A HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/directory?name=lab-user%2A HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 7.6 XPath Injection — XPath expression-д user input код болох

**A. Vulnerability Name.** **XPath Injection** — XPath expression-д user input код болох.

**B. What Is It? (Энгийнээр).** XML хайлтын filter-ийн хаалтад утга шиг оруулсан string expression болох.

**C. Why Does It Happen? (Root cause).** Unescaped values in XPath expression string; dynamic XPath concatenation.

**D. Where to Look? (Тестийн байрлал).** `/catalog?category=`, XML-backed search, legacy SOAP/XML. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **Local XML/XPath lab**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Local XML-backed lab-д single quote нэмсэн query-г valid control-тэй харьцуул; broad match/data extraction хийхгүй.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' "LAB_ITEM" "LAB_ITEM'"
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/xml/search?item=LAB_ITEM%27 HTTP/1.1
Host: app.lab.test
```

```http
HTTP/1.1 400 Bad Request

{"error":"invalid item"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Parser error + predictable changed predicate semantics combined with backend evidence needed.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Parser error + predictable changed predicate semantics combined with backend evidence needed. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Plain validation error, app not XPath based, response differences due to URL decoding. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** C/I Medium/High depending on XML content. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): Medium.** Нөлөө, шаардлагатай эрх, attacker interaction-аас хамаарч Low–High хооронд хэлбэлзэнэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Parameterized XPath APIs or safe expression construction, escaping and strict schema. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `XPath Injection on synthetic lab endpoint`
- **Summary:** XPath expression-д user input код болох; ажиглагдсан ялгаа нь `Parser error + predictable changed predicate semantics combined with backend evidence needed.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/xml/search?item=LAB_ITEM%27 HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** C/I Medium/High depending on XML content.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Parameterized XPath APIs or safe expression construction, escaping and strict schema.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/xml/search?item=LAB_ITEM%27 HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/xml/search?item=LAB_ITEM%27 HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 7.7 CRLF Injection — Carriage Return Line Feed-ээр header салгах

**A. Vulnerability Name.** **CRLF Injection** — Carriage Return Line Feed-ээр header салгах.

**B. What Is It? (Энгийнээр).** Header-ийн нэг мөрөнд оруулах утга шинэ HTTP header шиг харагдах.

**C. Why Does It Happen? (Root cause).** CRLF (`
`) sanitize хийхгүйгээр response header-д interpolation.

**D. Where to Look? (Тестийн байрлал).** `?next=`, `?filename=`, `Location`, `Content-Disposition`, custom headers. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Lab-д benign `X-Lab-Marker: 1` header нэмэгдэх эсэхийг шалгах ганц encoded CRLF request илгээ.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' '%0D%0AX-Lab-Marker%3A%201'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/redirect?next=%0D%0AX-Lab-Marker%3A%201 HTTP/1.1
Host: app.lab.test
```

```http
HTTP/1.1 400 Bad Request

{"error":"invalid redirect"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Response header хэсэгт **тусдаа** `X-Lab-Marker: 1` бий болвол splitting indicator; body echo биш.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Response header хэсэгт **тусдаа** `X-Lab-Marker: 1` бий болвол splitting indicator; body echo биш. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Proxy normalize, browser display auto-wrap, original encoded string response body-д харагдах. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** Header manipulation / response splitting; C/I context-dependent. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): Medium.** Нөлөө, шаардлагатай эрх, attacker interaction-аас хамаарч Low–High хооронд хэлбэлзэнэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Reject CR/LF in header values; framework safe header APIs; fixed redirect allowlist. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `CRLF Injection on synthetic lab endpoint`
- **Summary:** Carriage Return Line Feed-ээр header салгах; ажиглагдсан ялгаа нь `Response header хэсэгт **тусдаа** `X-Lab-Marker: 1` бий болвол splitting indicator; body echo биш.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/redirect?next=%0D%0AX-Lab-Marker%3A%201 HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** Header manipulation / response splitting; C/I context-dependent.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Reject CR/LF in header values; framework safe header APIs; fixed redirect allowlist.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/redirect?next=%0D%0AX-Lab-Marker%3A%201 HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/redirect?next=%0D%0AX-Lab-Marker%3A%201 HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 7.8 HTTP Header Injection — HTTP header value-д хянагдаагүй утга оруулах

**A. Vulnerability Name.** **HTTP Header Injection** — HTTP header value-д хянагдаагүй утга оруулах.

**B. What Is It? (Энгийнээр).** Хэрэглэгчийн `lang` утгыг server header-д шууд оруулж policy/redirect өөрчлөх.

**C. Why Does It Happen? (Root cause).** Header value validation дутуу эсвэл trusted upstream header-г client-аас авдаг.

**D. Where to Look? (Тестийн байрлал).** `X-Forwarded-*`, `Host`, `Referer`, response header reflected parameters. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Өөрийн lab request-д harmless `X-Lab-Trace: SAFE-123` нэмээд backend response header-ийн trusted routing-д санаандгүй нөлөөлж байгаа эсэхийг хар.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'X-Lab-Trace: SAFE-123'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/headers HTTP/1.1
Host: app.lab.test
X-Lab-Trace: SAFE-123
```

```http
HTTP/1.1 200 OK
X-Request-ID: server-generated-id

{"ok":true}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** User header `Host`/forwarded policy-г өөрчилж generated absolute URL хяналтгүй болсон нь context-dependent finding.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** User header `Host`/forwarded policy-г өөрчилж generated absolute URL хяналтгүй болсон нь context-dependent finding. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Trusted reverse proxy intentional header forwarding, reflection/debug behavior. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** C/I potentially Medium/High; isolated redirect/link proof ашигла. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): Medium.** Нөлөө, шаардлагатай эрх, attacker interaction-аас хамаарч Low–High хооронд хэлбэлзэнэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Trusted proxy configuration, header allowlist, sanitize/validate host, fixed application origin. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `HTTP Header Injection on synthetic lab endpoint`
- **Summary:** HTTP header value-д хянагдаагүй утга оруулах; ажиглагдсан ялгаа нь `User header `Host`/forwarded policy-г өөрчилж generated absolute URL хяналтгүй болсон нь context-dependent finding.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/headers HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** C/I potentially Medium/High; isolated redirect/link proof ашигла.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Trusted proxy configuration, header allowlist, sanitize/validate host, fixed application origin.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/headers HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/headers HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### Chapter 7 — Consolidated review

**Хамгийн чухал:** Confirmed finding бол зөвхөн response string биш, precondition + policy boundary + actual effect + negative control-оор дэмжигдсэн дүгнэлт. `Finding ID`, `confidence (hypothesis/likely/confirmed)`, severity rationale-г нэгтгэ.

<a id="chapter-8"></a>
## Chapter 8 — Cross-Site Scripting

XSS-ийн түлхүүр нь untrusted data браузер дээр **JavaScript context-д execution** болох. HTML injection, reflected string, CSP policy-г ялгаж нотол.

> **Сургалтын маршрут:** Эхлээд raw HTTP-г ойлго → baseline → own controlled change → negative control → state validation → report. Доорх бүх `/lab` URL ба response нь **synthetic**. Бодит дасгалыг дурдсан lab-ийн сэдвийн exercise-д хий.

### 8.1 Reflected XSS — Хүсэлтээс буцаж туссан JavaScript

**A. Vulnerability Name.** **Reflected XSS** — Хүсэлтээс буцаж туссан JavaScript.

**B. What Is It? (Энгийнээр).** Хайлтад оруулсан HTML/JS код response-д хамгаалалтгүй орж браузерт биелэх.

**C. Why Does It Happen? (Root cause).** Output encoding context буруу, HTML insertion unsafe.

**D. Where to Look? (Тестийн байрлал).** `?q=`, `?message=`, error, search result, URL fragment client JS. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **Web Security Academy XSS**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: XSS lab-д эхлээд `LAB_XSS_01`, дараа `<b>LAB_MARKER</b>` reflection context шалга; зөвхөн өөрийн isolated browser lab-д `<script>alert(1)</script>`-ээр execution confirm хий.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' '<b>LAB_MARKER</b>' '<script>alert(1)</script>'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1
Host: app.lab.test
```

```http
HTTP/1.1 200 OK
Content-Type: text/html

<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Safe: HTML-escaped literal text. Vulnerable: isolated lab page дээр JavaScript-ийн `alert(1)` execution батлагдана.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Safe: HTML-escaped literal text. Vulnerable: isolated lab page дээр JavaScript-ийн `alert(1)` execution батлагдана. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** HTML injection нь script execution биш; DevTools console-оос гараар alert дуудах нь PoC биш; CSP blocking. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** Stored/session/token actions боломжтой C/I дунд–өндөр; own browser only. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): Medium.** Нөлөө, шаардлагатай эрх, attacker interaction-аас хамаарч Low–High хооронд хэлбэлзэнэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Contextual encoding, templating autoescape, safe DOM APIs, CSP defense-in-depth. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Reflected XSS on synthetic lab endpoint`
- **Summary:** Хүсэлтээс буцаж туссан JavaScript; ажиглагдсан ялгаа нь `Safe: HTML-escaped literal text. Vulnerable: isolated lab page дээр JavaScript-ийн `alert(1)` execution батлагдана.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** Stored/session/token actions боломжтой C/I дунд–өндөр; own browser only.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Contextual encoding, templating autoescape, safe DOM APIs, CSP defense-in-depth.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 8.2 Stored XSS — Өгөгдөлд хадгалагдсан JavaScript

**A. Vulnerability Name.** **Stored XSS** — Өгөгдөлд хадгалагдсан JavaScript.

**B. What Is It? (Энгийнээр).** Сэтгэгдэлд бичсэн код дараа нь page уншихад дахин биелнэ.

**C. Why Does It Happen? (Root cause).** Persisted untrusted content unsafe render, sanitizer missing/unsafe.

**D. Where to Look? (Тестийн байрлал).** Own comment, profile bio, note, ticket, Markdown renderer. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **OWASP Juice Shop / Web Security Academy XSS**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Local lab-д өөрийн test-only comment үүсгэж `LAB_STORED` marker хадгал; own second lab browser session-д render шалга; XSS execution зөвхөн isolated browser-д.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' '<b>LAB_STORED</b>'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
POST /lab/comments HTTP/1.1
Host: app.lab.test
Content-Type: application/json

{"postId":"OWN_POST","text":"<b>LAB_STORED</b>"}
```

```http
HTTP/1.1 201 Created

{"id":"OWN_COMMENT"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** POST 201 ганцаараа PoC биш; second read-д script executes эсэх, sanitize хийгдэж байгаа эсэхийг шалга.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** POST 201 ганцаараа PoC биш; second read-д script executes эсэх, sanitize хийгдэж байгаа эсэхийг шалга. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Rendering markdown bold intentionally allowed; HTML text-only; CSP blocks execution. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** Other users viewing potentially affected = C/I High; production-д бусдад харагдах payload байрлуулахгүй. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Sanitize HTML allowlist, context encoding, safe markdown parser, CSP. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Stored XSS on synthetic lab endpoint`
- **Summary:** Өгөгдөлд хадгалагдсан JavaScript; ажиглагдсан ялгаа нь `POST 201 ганцаараа PoC биш; second read-д script executes эсэх, sanitize хийгдэж байгаа эсэхийг шалга.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `POST /lab/comments HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** Other users viewing potentially affected = C/I High; production-д бусдад харагдах payload байрлуулахгүй.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Sanitize HTML allowlist, context encoding, safe markdown parser, CSP.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `POST /lab/comments HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `POST /lab/comments HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 8.3 DOM-based XSS — Browser DOM дээр input code болж орох

**A. Vulnerability Name.** **DOM-based XSS** — Browser DOM дээр input code болж орох.

**B. What Is It? (Энгийнээр).** URL `#fragment`-ийн текстийг JS `innerHTML`-д шууд бичсэн.

**C. Why Does It Happen? (Root cause).** Client-side source (location/search/hash/postMessage) → unsafe sink (innerHTML/eval).

**D. Where to Look? (Тестийн байрлал).** `location.hash`, `location.search`, `postMessage`, `document.write`, `innerHTML`. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **Web Security Academy DOM XSS**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: DevTools Sources-д `location.hash` → `innerHTML` урсгалыг trace хий; local lab URL fragment-д marker хийж DOM tree өөрчлөгдөхийг хар.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' '#<b>DOM_TEST</b>'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/dom HTTP/1.1
Host: app.lab.test

#fragment=encoded-in-browser-only
```

```http
HTTP/1.1 200 OK
Content-Type: text/html

<div id="output"></div>
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Hash fragment HTTP request-д **явдаггүй**; browser DOM-д unsafe HTML/script effect байвал DOM-based risk.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Hash fragment HTTP request-д **явдаггүй**; browser DOM-д unsafe HTML/script effect байвал DOM-based risk. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** TextContent safe, sanitizer, framework DOM binding safe, browser extensions. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** C/I Medium/High dependent on sink and origin. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): Medium.** Нөлөө, шаардлагатай эрх, attacker interaction-аас хамаарч Low–High хооронд хэлбэлзэнэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Replace innerHTML with textContent for text, sanitization, Trusted Types, CSP. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `DOM-based XSS on synthetic lab endpoint`
- **Summary:** Browser DOM дээр input code болж орох; ажиглагдсан ялгаа нь `Hash fragment HTTP request-д **явдаггүй**; browser DOM-д unsafe HTML/script effect байвал DOM-based risk.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/dom HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** C/I Medium/High dependent on sink and origin.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Replace innerHTML with textContent for text, sanitization, Trusted Types, CSP.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/dom HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/dom HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 8.4 HTML Injection — HTML markup-шиг input render болох

**A. Vulnerability Name.** **HTML Injection** — HTML markup-шиг input render болох.

**B. What Is It? (Энгийнээр).** Хэрэглэгчийн бичсэн текст page layout-г HTML болгон өөрчилж байна.

**C. Why Does It Happen? (Root cause).** HTML escaping дутуу, text node биш markup insert.

**D. Where to Look? (Тестийн байрлал).** Comment, search result, preview widget, UI label. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Зөвхөн own lab profile-д `<b>LAB_HTML_OK</b>` хийж tag render болон code execution ялга.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' '<b>LAB_HTML_OK</b>'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/preview?text=%3Cb%3ELAB_HTML_OK%3C%2Fb%3E HTTP/1.1
Host: app.lab.test
```

```http
HTTP/1.1 200 OK

<div>&lt;b&gt;LAB_HTML_OK&lt;/b&gt;</div>
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** DOM-д `<b>` element үүссэн бол HTML injection; JavaScript execution батлагдаагүй тул XSS гэж бичихгүй.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** DOM-д `<b>` element үүссэн бол HTML injection; JavaScript execution батлагдаагүй тул XSS гэж бичихгүй. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** HTML explicitly supported content field (WYSIWYG), safe allowlist. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** UI deception/content spoofing; context-dependent Low/Medium. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): Low.** Нөлөө ихэнхдээ context-dependent; CVSS ихэвчлэн Low/Informational байж болно. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Escape untrusted text, strict HTML sanitizer where formatting needed. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `HTML Injection on synthetic lab endpoint`
- **Summary:** HTML markup-шиг input render болох; ажиглагдсан ялгаа нь `DOM-д `<b>` element үүссэн бол HTML injection; JavaScript execution батлагдаагүй тул XSS гэж бичихгүй.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/preview?text=%3Cb%3ELAB_HTML_OK%3C%2Fb%3E HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** UI deception/content spoofing; context-dependent Low/Medium.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Escape untrusted text, strict HTML sanitizer where formatting needed.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/preview?text=%3Cb%3ELAB_HTML_OK%3C%2Fb%3E HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/preview?text=%3Cb%3ELAB_HTML_OK%3C%2Fb%3E HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 8.5 Unsafe JavaScript Sink / CSP Limitations — Аюултай DOM sink болон CSP-ийн хязгаар

**A. Vulnerability Name.** **Unsafe JavaScript Sink / CSP Limitations** — Аюултай DOM sink болон CSP-ийн хязгаар.

**B. What Is It? (Энгийнээр).** CSP байлаа ч unsafe sink эсвэл misconfigured policy зарим script risk-г зогсоохгүй.

**C. Why Does It Happen? (Root cause).** Unsafe `eval`, `innerHTML`, `setTimeout(string)`, overly permissive `script-src`.

**D. Where to Look? (Тестийн байрлал).** JS source/sink, CSP response header, dynamic HTML rendering. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: DevTools Sources-д source→sink-ийг trace хийгээд HTML marker ашиглаж observe; CSP bypass payload/cross-origin attack хийхгүй.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'Check CSP script-src; note unsafe-inline versus nonce-based policy'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/page HTTP/1.1
Host: app.lab.test
```

```http
HTTP/1.1 200 OK
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-LAB_NONCE'
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** CSP header сул байж болох ч exploitability ганцаараа нотлохгүй; reachable unsafe sink + script execution lab-д батал.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** CSP header сул байж болох ч exploitability ганцаараа нотлохгүй; reachable unsafe sink + script execution lab-д батал. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** CSP Report-Only, third-party scripts, `unsafe-inline` policy intentionally testing. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** XSS impact context-д хамаарна; header missing informational alone. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): Medium.** Нөлөө, шаардлагатай эрх, attacker interaction-аас хамаарч Low–High хооронд хэлбэлзэнэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Context-safe output, Trusted Types, nonce/hash-based CSP, no unsafe-eval. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Unsafe JavaScript Sink / CSP Limitations on synthetic lab endpoint`
- **Summary:** Аюултай DOM sink болон CSP-ийн хязгаар; ажиглагдсан ялгаа нь `CSP header сул байж болох ч exploitability ганцаараа нотлохгүй; reachable unsafe sink + script execution lab-д батал.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/page HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** XSS impact context-д хамаарна; header missing informational alone.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Context-safe output, Trusted Types, nonce/hash-based CSP, no unsafe-eval.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/page HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/page HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### Chapter 8 — Consolidated review

**Хамгийн чухал:** Confirmed finding бол зөвхөн response string биш, precondition + policy boundary + actual effect + negative control-оор дэмжигдсэн дүгнэлт. `Finding ID`, `confidence (hypothesis/likely/confirmed)`, severity rationale-г нэгтгэ.

<a id="chapter-9"></a>
## Chapter 9 — Server-Side Vulnerabilities

Server-side flaw-ийн тест бүрийг isolated lab эсвэл owner-controlled test fixture ашиглан хий. Internal services, cloud metadata, OS files, queue, transactions руу хандсан үр дагавартай PoC хориотой.

> **Сургалтын маршрут:** Эхлээд raw HTTP-г ойлго → baseline → own controlled change → negative control → state validation → report. Доорх бүх `/lab` URL ба response нь **synthetic**. Бодит дасгалыг дурдсан lab-ийн сэдвийн exercise-д хий.

### 9.1 Server-Side Request Forgery (SSRF) — Серверийг хүсээгүй URL руу request явуулахад хүргэх

**A. Vulnerability Name.** **Server-Side Request Forgery (SSRF)** — Серверийг хүсээгүй URL руу request явуулахад хүргэх.

**B. What Is It? (Энгийнээр).** Серверээс URL татдаг функц өөрийн зөвшөөрөлтэй хаягаас өөр тийш явж магадгүй.

**C. Why Does It Happen? (Root cause).** User-controlled URL, weak scheme/host validation, unsafe redirect handling.

**D. Where to Look? (Тестийн байрлал).** `/fetch?url=`, image import, webhook validation, PDF-from-URL, preview. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **Web Security Academy SSRF / owned localhost callback**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: PortSwigger SSRF **isolated lab** эсвэл өөрийн owned callback `127.0.0.1` (same network namespace нөхцөлөөс хамаарна)-т `/ping` endpoint тавь; зөвхөн benign request ажигла.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'http://127.0.0.1:9001/ping'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
POST /lab/fetch-preview HTTP/1.1
Host: app.lab.test
Content-Type: application/json

{"url":"http://127.0.0.1:9001/ping"}
```

```http
HTTP/1.1 400 Bad Request

{"error":"private targets forbidden"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Тусгаарласан lab-ийн owned listener-д server-origin request бүртгэгдсэн бол SSRF indicator; web UI echo ганцаараа биш.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Тусгаарласан lab-ийн owned listener-д server-origin request бүртгэгдсэн бол SSRF indicator; web UI echo ганцаараа биш. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** DNS caching, browser-side fetch, container localhost ≠ host localhost, loopback resolution. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** Internal reachability risk; C/I/A нөхцөлт High. Cloud metadata, third-party URL руу бүү ханда. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Allowlist destinations, DNS/IP revalidation, block loopback/private/link-local, disable redirects, egress firewall. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Server-Side Request Forgery (SSRF) on synthetic lab endpoint`
- **Summary:** Серверийг хүсээгүй URL руу request явуулахад хүргэх; ажиглагдсан ялгаа нь `Тусгаарласан lab-ийн owned listener-д server-origin request бүртгэгдсэн бол SSRF indicator; web UI echo ганцаараа биш.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `POST /lab/fetch-preview HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** Internal reachability risk; C/I/A нөхцөлт High. Cloud metadata, third-party URL руу бүү ханда.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Allowlist destinations, DNS/IP revalidation, block loopback/private/link-local, disable redirects, egress firewall.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `POST /lab/fetch-preview HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `POST /lab/fetch-preview HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 9.2 Path Traversal — Folder-ийн хязгаараас гарах

**A. Vulnerability Name.** **Path Traversal** — Folder-ийн хязгаараас гарах.

**B. What Is It? (Энгийнээр).** Хавтасны нэрээр `../` буцааж файл татах замыг өөрчилж буй.

**C. Why Does It Happen? (Root cause).** Untrusted path canonicalize/allowlist шалгадаггүй.

**D. Where to Look? (Тестийн байрлал).** `GET /download?file=`, image/attachment reader, static file route. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **Web Security Academy Path traversal**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Local fixture-д зөвшөөрөгдсөн `/safe/` folder ба түүний гадна **өөрийн** `outside-marker.txt` үүсгэ; controlled traversal-аар зөвхөн marker руу хандахыг турш.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' '../outside-marker.txt'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/download?file=..%2Foutside-marker.txt HTTP/1.1
Host: app.lab.test
```

```http
HTTP/1.1 403 Forbidden

{"error":"invalid path"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Own marker file-ийн `LAB_OUTSIDE_ONLY` content ирвэл confirmed; `/etc/passwd` зэрэг real file-г уншихгүй.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Own marker file-ийн `LAB_OUTSIDE_ONLY` content ирвэл confirmed; `/etc/passwd` зэрэг real file-г уншихгүй. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Server route normalize хийж өөр harmless file өгөх, intended shared directory, CDN cache. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** C High when sensitive files reachable; I if write path vulnerable. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Resolve canonical path and verify inside base, prefer opaque file IDs, least privilege. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Path Traversal on synthetic lab endpoint`
- **Summary:** Folder-ийн хязгаараас гарах; ажиглагдсан ялгаа нь `Own marker file-ийн `LAB_OUTSIDE_ONLY` content ирвэл confirmed; `/etc/passwd` зэрэг real file-г уншихгүй.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/download?file=..%2Foutside-marker.txt HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** C High when sensitive files reachable; I if write path vulnerable.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Resolve canonical path and verify inside base, prefer opaque file IDs, least privilege.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/download?file=..%2Foutside-marker.txt HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/download?file=..%2Foutside-marker.txt HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 9.3 Local File Inclusion (LFI) — Серверийн local файл template-д include болох

**A. Vulnerability Name.** **Local File Inclusion (LFI)** — Серверийн local файл template-д include болох.

**B. What Is It? (Энгийнээр).** Хуудасны нэрийг хэрэглэгч өгснөөр server өөр local template/file load хийх.

**C. Why Does It Happen? (Root cause).** User input include/require path-д шууд дамждаг.

**D. Where to Look? (Тестийн байрлал).** `?page=`, `?template=`, PHP include, legacy views. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **DVWA / isolated PHP file include lab**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Local lab-д allowlisted `help` page ба өөрийн `lab-marker.txt` файл бэлдэж гаднах файл include оролдлогыг шалга; real OS files ашиглахгүй.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' '../lab-marker.txt'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/view?page=..%2Flab-marker.txt HTTP/1.1
Host: app.lab.test
```

```http
HTTP/1.1 404 Not Found

{"error":"template not found"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Server-generated view-д allowed folder-оос гаднах own marker file content орвол LFI indicator.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Server-generated view-д allowed folder-оос гаднах own marker file content орвол LFI indicator. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Plain path traversal download vs template include, client-side routing. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** C High, code execution chain боломжтой ч үйлдвэрлэл дээр батлахгүй. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Fixed template names allowlist, never include raw user path, disable risky dynamic includes. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Local File Inclusion (LFI) on synthetic lab endpoint`
- **Summary:** Серверийн local файл template-д include болох; ажиглагдсан ялгаа нь `Server-generated view-д allowed folder-оос гаднах own marker file content орвол LFI indicator.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/view?page=..%2Flab-marker.txt HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** C High, code execution chain боломжтой ч үйлдвэрлэл дээр батлахгүй.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Fixed template names allowlist, never include raw user path, disable risky dynamic includes.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/view?page=..%2Flab-marker.txt HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/view?page=..%2Flab-marker.txt HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 9.4 Remote File Inclusion (RFI) — Алсын файл include болох

**A. Vulnerability Name.** **Remote File Inclusion (RFI)** — Алсын файл include болох.

**B. What Is It? (Энгийнээр).** Template замд өгсөн URL-аас код/агуулга server-side load хийгдэх.

**C. Why Does It Happen? (Root cause).** Dynamic include accepts remote schemes, PHP allow_url_include-like unsafe behavior.

**D. Where to Look? (Тестийн байрлал).** `?template=`, remote include setting, PHP app. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **DVWA isolated File Inclusion module**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Зөвхөн тусгаарласан PHP lab-д өөрийн loopback `http://127.0.0.1:9001/marker.txt`-ийг plain text болгон include хүсээд content appearance шалга; executable remote script бүү ашигла.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'http://127.0.0.1:9001/marker.txt'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/view?template=http%3A%2F%2F127.0.0.1%3A9001%2Fmarker.txt HTTP/1.1
Host: app.lab.test
```

```http
HTTP/1.1 400 Bad Request

{"error":"remote templates disabled"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Own harmless marker remote content серверээс include болвол RFI indicator; browser iframe биш.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Own harmless marker remote content серверээс include болвол RFI indicator; browser iframe биш. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** SSRF file fetch vs executed include, remote URL blocked by runtime. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** Potential C/I/A Critical, actual code execution шаардлагагүй. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Disable remote include, fixed view allowlist, egress restrictions. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Remote File Inclusion (RFI) on synthetic lab endpoint`
- **Summary:** Алсын файл include болох; ажиглагдсан ялгаа нь `Own harmless marker remote content серверээс include болвол RFI indicator; browser iframe биш.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/view?template=http%3A%2F%2F127.0.0.1%3A9001%2Fmarker.txt HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** Potential C/I/A Critical, actual code execution шаардлагагүй.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Disable remote include, fixed view allowlist, egress restrictions.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/view?template=http%3A%2F%2F127.0.0.1%3A9001%2Fmarker.txt HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/view?template=http%3A%2F%2F127.0.0.1%3A9001%2Fmarker.txt HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 9.5 XML External Entity (XXE) — XML parser-ийн гаднын entity

**A. Vulnerability Name.** **XML External Entity (XXE)** — XML parser-ийн гаднын entity.

**B. What Is It? (Энгийнээр).** XML баримт дотор гаднаас resource авах заавар өгөөд parser дагах.

**C. Why Does It Happen? (Root cause).** DTD/external entity enabled, safe parser mode хэрэглэхгүй.

**D. Where to Look? (Тестийн байрлал).** `Content-Type: application/xml`, SOAP, XML upload, import, SVG parser. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **Web Security Academy XXE**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Isolated XML lab-д эхлээд **internal entity** `LAB_OK` processing шалга (энэ нь XXE-г батлахгүй); дараа зөвхөн өөрийн local harmless fixture entity-ээр external resolution эсэхийг шалга.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' '<!DOCTYPE r [<!ENTITY lab "LAB_OK">]><r>&lab;</r>'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
POST /lab/xml/parse HTTP/1.1
Host: app.lab.test
Content-Type: application/xml

<!DOCTYPE r [<!ENTITY lab "LAB_OK">]><r>&lab;</r>
```

```http
HTTP/1.1 400 Bad Request

{"error":"DTD not allowed"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Internal entity `LAB_OK` expansion бол дангаараа **XXE биш**. External entity зөвхөн owned isolated test file/resource руу resolve болсныг батлах шаардлагатай.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Internal entity `LAB_OK` expansion бол дангаараа **XXE биш**. External entity зөвхөн owned isolated test file/resource руу resolve болсныг батлах шаардлагатай. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Parser silently strips DTD; body echo; internal entity-only support. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** C High if external file/network reachable; lab-д system files рүү чиглүүлэхгүй. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Disable DTD/external entities, hardened XML parsers, schema validation, egress controls. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `XML External Entity (XXE) on synthetic lab endpoint`
- **Summary:** XML parser-ийн гаднын entity; ажиглагдсан ялгаа нь `Internal entity `LAB_OK` expansion бол дангаараа **XXE биш**. External entity зөвхөн owned isolated test file/resource руу resolve болсныг батлах шаардлагатай.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `POST /lab/xml/parse HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** C High if external file/network reachable; lab-д system files рүү чиглүүлэхгүй.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Disable DTD/external entities, hardened XML parsers, schema validation, egress controls.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `POST /lab/xml/parse HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `POST /lab/xml/parse HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 9.6 Insecure Deserialization — Өөрчлөгдөх боломжтой serialized object-д итгэх

**A. Vulnerability Name.** **Insecure Deserialization** — Өөрчлөгдөх боломжтой serialized object-д итгэх.

**B. What Is It? (Энгийнээр).** Хэрэглэгчийн хадгалсан object-г сервер шалгалтгүй сэргээж dangerous class/process ажиллуулах.

**C. Why Does It Happen? (Root cause).** Untrusted native object deserialization, unsafe gadget types and missing integrity.

**D. Where to Look? (Тестийн байрлал).** `session` cookie, serialized blob, file import, queue payload. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **Web Security Academy Insecure deserialization**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Isolated lab-д **harmless serialized settings**-ийг valid vs tampered version-оор шалга; gadget chain, code execution, payload hunting хийхгүй.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' '{"theme":"light"}' '{"theme":"dark"}'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
POST /lab/settings/import HTTP/1.1
Host: app.lab.test
Content-Type: application/json

{"settings":{"theme":"dark"}}
```

```http
HTTP/1.1 200 OK

{"theme":"dark"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Plain JSON parsing vulnerability биш; unsafe native object type instantiate болох code review/lab behavior нотол.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Plain JSON parsing vulnerability биш; unsafe native object type instantiate болох code review/lab behavior нотол. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** JSON-to-DTO safe validation; mere base64 blob does not prove deserialization. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** Integrity/availability or RCE risk depending on gadget classes; High/Critical potential. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Avoid native deserialization of untrusted input; schema DTO, signatures, type allowlist. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Insecure Deserialization on synthetic lab endpoint`
- **Summary:** Өөрчлөгдөх боломжтой serialized object-д итгэх; ажиглагдсан ялгаа нь `Plain JSON parsing vulnerability биш; unsafe native object type instantiate болох code review/lab behavior нотол.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `POST /lab/settings/import HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** Integrity/availability or RCE risk depending on gadget classes; High/Critical potential.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Avoid native deserialization of untrusted input; schema DTO, signatures, type allowlist.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `POST /lab/settings/import HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `POST /lab/settings/import HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 9.7 File Upload Validation — File upload хязгаарлалт алдаа

**A. Vulnerability Name.** **File Upload Validation** — File upload хязгаарлалт алдаа.

**B. What Is It? (Энгийнээр).** Зураг upload гэх боловч server дурын өргөтгөл эсвэл web-executable content зөвшөөрөх.

**C. Why Does It Happen? (Root cause).** Content-type/extension trust, storage web root, executable permission.

**D. Where to Look? (Тестийн байрлал).** `POST /upload`, multipart `file`, image processing, file download route. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **Web Security Academy File upload vulnerabilities**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Зөвхөн local lab-д `LAB_UPLOAD_TEST` агуулгатай `.txt` файл үүсгээд approved upload function-д илгээн safe download path/auth шалга; web shell ашиглахгүй.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf 'LAB_UPLOAD_TEST\n' > lab-upload.txt
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
POST /lab/upload HTTP/1.1
Host: app.lab.test
Content-Type: multipart/form-data; boundary=...

[own harmless lab-upload.txt form data]
```

```http
HTTP/1.1 201 Created

{"fileId":"OWN_TEST_FILE","contentType":"text/plain"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Risk зөвхөн file accepted гэдгээр батлагдахгүй: dangerous type permitted, execution or unauthorized exposure trust boundary needed.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Risk зөвхөн file accepted гэдгээр батлагдахгүй: dangerous type permitted, execution or unauthorized exposure trust boundary needed. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** App allows `.txt` by design, MIME handling correct, attachment served from separate domain. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** I/Availability possible; RCE if executed; demonstrated scope-dependent. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): Medium.** Нөлөө, шаардлагатай эрх, attacker interaction-аас хамаарч Low–High хооронд хэлбэлзэнэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Extension+magic type validation, rename, store outside web root, noexecute, antivirus, permissions. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `File Upload Validation on synthetic lab endpoint`
- **Summary:** File upload хязгаарлалт алдаа; ажиглагдсан ялгаа нь `Risk зөвхөн file accepted гэдгээр батлагдахгүй: dangerous type permitted, execution or unauthorized exposure trust boundary needed.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `POST /lab/upload HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** I/Availability possible; RCE if executed; demonstrated scope-dependent.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Extension+magic type validation, rename, store outside web root, noexecute, antivirus, permissions.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `POST /lab/upload HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `POST /lab/upload HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 9.8 Open Redirect — Хүсээгүй сайт руу redirect хийх

**A. Vulnerability Name.** **Open Redirect** — Хүсээгүй сайт руу redirect хийх.

**B. What Is It? (Энгийнээр).** Хэрэглэгчийн өгсөн хаягийг website танихгүй домэйн руу дамжуулж байна.

**C. Why Does It Happen? (Root cause).** Untrusted `next`, `returnUrl`-г `Location` header-т allowlist-гүй ашиглах.

**D. Where to Look? (Тестийн байрлал).** `/login?next=`, `/go?url=`, OAuth callback pre-redirect. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Local mock domain-д `next=http://127.0.0.1:9001/landing` өгч redirect дарааллыг **follow хийхгүй** `Location` header-оос шалга.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
curl -sS -I --max-time 10 'http://127.0.0.1:3000/?next=http%3A%2F%2F127.0.0.1%3A9001%2Flanding'
```

`curl` = HTTP client; `-sS` = progress нуух боловч error хэвлэх; `-i` = response header харуулах; `-I` = HEAD request; `--max-time 10` = 10 секунд timeout; `-X` = HTTP method; `-H` = header; `--data` = body. Зөвхөн ашигласан flag-ууд энэ command-д хамаарна.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/redirect?next=http%3A%2F%2F127.0.0.1%3A9001%2Flanding HTTP/1.1
Host: app.lab.test
```

```http
HTTP/1.1 400 Bad Request

{"error":"invalid return URL"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** `Location: http://127.0.0.1:9001/landing` нь unvalidated off-site redirect; `-L`-гүй тул request follow хийхгүй.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** `Location: http://127.0.0.1:9001/landing` нь unvalidated off-site redirect; `-L`-гүй тул request follow хийхгүй. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Trusted allowlisted redirect, relative paths, client-side link is not server redirect. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** Phishing/OAuth chain risk; standalone Low/Medium. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): Low.** Нөлөө ихэнхдээ context-dependent; CVSS ихэвчлэн Low/Informational байж болно. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Allow only relative paths, exact allowlist, bind redirects to intended origins. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Open Redirect on synthetic lab endpoint`
- **Summary:** Хүсээгүй сайт руу redirect хийх; ажиглагдсан ялгаа нь ``Location: http://127.0.0.1:9001/landing` нь unvalidated off-site redirect; `-L`-гүй тул request follow хийхгүй.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/redirect?next=http%3A%2F%2F127.0.0.1%3A9001%2Flanding HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** Phishing/OAuth chain risk; standalone Low/Medium.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Allow only relative paths, exact allowlist, bind redirects to intended origins.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/redirect?next=http%3A%2F%2F127.0.0.1%3A9001%2Flanding HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/redirect?next=http%3A%2F%2F127.0.0.1%3A9001%2Flanding HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 9.9 HTTP Request Smuggling — Proxy ба backend request хил зөрөх

**A. Vulnerability Name.** **HTTP Request Smuggling** — Proxy ба backend request хил зөрөх.

**B. What Is It? (Энгийнээр).** Front-end ба backend proxy нэг byte stream-ийг хоёр өөр request гэж ойлгох.

**C. Why Does It Happen? (Root cause).** CL/TE parsing disagreement, HTTP/1.1 framing inconsistency.

**D. Where to Look? (Тестийн байрлал).** Reverse proxy chain, HTTP/1.1 forwarding, request parsing differences. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **Web Security Academy HTTP Request Smuggling**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: **Зөвхөн тусгаарласан Academy lab**-ийн dedicated smuggling exercise ашигла; production-д raw malformed request/CL-TE ambiguity бүү илгээ. Lab logs-д request boundary difference ажигла.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'Concept: front-end and back-end must agree on Content-Length/Transfer-Encoding framing'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Concept + isolated lab only. No raw request-smuggling exploit payloads in production.

**G. HTTP Request & Response — synthetic example.**

```http
POST /lab/echo HTTP/1.1
Host: isolated.lab.test
Content-Type: text/plain
Content-Length: 4

TEST
```

```http
HTTP/1.1 200 OK

TEST
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Энэ **well-formed** request нь smuggling PoC биш; isolated lab-д proxy/backend boundary desync баталсан лог шаардлагатай.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Энэ **well-formed** request нь smuggling PoC биш; isolated lab-д proxy/backend boundary desync баталсан лог шаардлагатай. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Network timeout, ordinary 400 response, HTTP/2 conversion, keepalive closure. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** C/I High/Critical potential; deliberate desynchronization only local sandbox. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Normalize/reject ambiguous framing, consistent proxy/backend parsers, HTTP/2 end-to-end where feasible. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `HTTP Request Smuggling on synthetic lab endpoint`
- **Summary:** Proxy ба backend request хил зөрөх; ажиглагдсан ялгаа нь `Энэ **well-formed** request нь smuggling PoC биш; isolated lab-д proxy/backend boundary desync баталсан лог шаардлагатай.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `POST /lab/echo HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** C/I High/Critical potential; deliberate desynchronization only local sandbox.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Normalize/reject ambiguous framing, consistent proxy/backend parsers, HTTP/2 end-to-end where feasible.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `POST /lab/echo HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `POST /lab/echo HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 9.10 Race Conditions — Зэрэгцээ хүсэлтийн логикийн алдаа

**A. Vulnerability Name.** **Race Conditions** — Зэрэгцээ хүсэлтийн логикийн алдаа.

**B. What Is It? (Энгийнээр).** Нэг купоныг зэрэг хоёр удаа ашиглахад сервер бүртгэлээ шалгаж амжаагүй.

**C. Why Does It Happen? (Root cause).** Check-then-act non-atomic database transaction, duplicate processing.

**D. Where to Look? (Тестийн байрлал).** `/redeem`, `/checkout`, `/approve`, token single-use, inventory reservation. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **Web Security Academy Race Conditions**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Тусгаарласан lab-д хоёр synthetic request-г хамгийн ихдээ **2** parallel илгээ; production transaction, payment, inventory-д concurrency test хийхгүй.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'Run two OWN lab-only coupon redemption requests; cap concurrency at 2'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
POST /lab/redeem HTTP/1.1
Host: isolated.lab.test
Content-Type: application/json

{"coupon":"OWN_LAB_SINGLE_USE"}
```

```http
HTTP/1.1 200 OK

{"redeemed":true}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Хоёр request хоёулаа success байсан нь state нөлөө давхардсан эсэхээр баталгаажна; нэг 200/нэг 409 бол secure.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Хоёр request хоёулаа success байсан нь state нөлөө давхардсан эсэхээр баталгаажна; нэг 200/нэг 409 бол secure. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Idempotent success message боловч ledger нэг л бичлэг, eventual consistency. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** I high/financial impact possible, use zero-value test data. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Atomic transactions, unique constraints, idempotency keys, lock/compare-and-swap. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Race Conditions on synthetic lab endpoint`
- **Summary:** Зэрэгцээ хүсэлтийн логикийн алдаа; ажиглагдсан ялгаа нь `Хоёр request хоёулаа success байсан нь state нөлөө давхардсан эсэхээр баталгаажна; нэг 200/нэг 409 бол secure.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `POST /lab/redeem HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** I high/financial impact possible, use zero-value test data.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Atomic transactions, unique constraints, idempotency keys, lock/compare-and-swap.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `POST /lab/redeem HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `POST /lab/redeem HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### Chapter 9 — Consolidated review

**Хамгийн чухал:** Confirmed finding бол зөвхөн response string биш, precondition + policy boundary + actual effect + negative control-оор дэмжигдсэн дүгнэлт. `Finding ID`, `confidence (hypothesis/likely/confirmed)`, severity rationale-г нэгтгэ.

<a id="chapter-10"></a>
## Chapter 10 — API Security

REST/GraphQL гэх interface өөрөө vulnerability биш. OWASP API Top 10:2023-оор object, property, function, authentication, quota, inventory, provider trust boundary-ийг тусад нь шалга.

> **Сургалтын маршрут:** Эхлээд raw HTTP-г ойлго → baseline → own controlled change → negative control → state validation → report. Доорх бүх `/lab` URL ба response нь **synthetic**. Бодит дасгалыг дурдсан lab-ийн сэдвийн exercise-д хий.

### OWASP API Security Top 10:2023 — official categories

| ID | Category | Энэ гарын авлагын байрлал |
|---|---|---|
| API1 | Broken Object Level Authorization | API BOLA / Chapter 6 IDOR |
| API2 | Broken Authentication | API Authentication / Chapter 5 |
| API3 | Broken Object Property Level Authorization | BOPLA / Mass Assignment |
| API4 | Unrestricted Resource Consumption | Rate limiting/complexity |
| API5 | Broken Function Level Authorization | API BFLA |
| API6 | Unrestricted Access to Sensitive Business Flows | Chapter 11 |
| API7 | Server Side Request Forgery | Chapter 9 SSRF |
| API8 | Security Misconfiguration | Chapter 12 |
| API9 | Improper Inventory Management | API Versioning / Inventory |
| API10 | Unsafe Consumption of APIs | External API trust |

**REST**: URL + HTTP methods + JSON response. **GraphQL**: нэг endpoint-д query/mutation ба field/resolver түвшний policy; introspection-enabled гэдэг нь дангаараа bug биш.

### 10.1 API BOLA (REST and GraphQL) — API object ownership шалгалт

**A. Vulnerability Name.** **API BOLA (REST and GraphQL)** — API object ownership шалгалт.

**B. What Is It? (Энгийнээр).** ID-д суурилсан API зөвшөөрөл шалгахгүйгээр object буцаах.

**C. Why Does It Happen? (Root cause).** Object ID-тай холбоотой per-request authorization missing.

**D. Where to Look? (Тестийн байрлал).** `GET /api/v1/items/{id}`, GraphQL `node(id)`/`order(id)`. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **OWASP crAPI / Academy API testing**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Own Account A/B synthetic object-оор REST ба GraphQL read-only compare; A token-аар B object marker харагдахгүй эсэхийг шалга.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'REST or GraphQL: use OWN A token + OWN B object ID only'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/api/v1/items/B-OWNED HTTP/1.1
Host: app.lab.test
Authorization: Bearer OWN_A_TOKEN
```

```http
HTTP/1.1 403 Forbidden

{"error":"object forbidden"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** A token → B private marker = BOLA; REST/GraphQL responses may return 200 with `errors`, body inspect.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** A token → B private marker = BOLA; REST/GraphQL responses may return 200 with `errors`, body inspect. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Shared/public object, GraphQL `data:null`+error, owner membership. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** C/I High, tenant boundaries may increase impact. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Resource-level ownership checks on every resolver/controller, scoped DB queries. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `API BOLA (REST and GraphQL) on synthetic lab endpoint`
- **Summary:** API object ownership шалгалт; ажиглагдсан ялгаа нь `A token → B private marker = BOLA; REST/GraphQL responses may return 200 with `errors`, body inspect.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/api/v1/items/B-OWNED HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** C/I High, tenant boundaries may increase impact.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Resource-level ownership checks on every resolver/controller, scoped DB queries.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/api/v1/items/B-OWNED HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/api/v1/items/B-OWNED HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 10.2 API BFLA — API function-level эрхийн алдаа

**A. Vulnerability Name.** **API BFLA** — API function-level эрхийн алдаа.

**B. What Is It? (Энгийнээр).** Viewer user нь admin mutation/operation-д хүрэх боломжтой.

**C. Why Does It Happen? (Root cause).** API route/mutation-level permission missing, role only frontend.

**D. Where to Look? (Тестийн байрлал).** `/api/admin/*`, `/api/export`, GraphQL mutation. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Only own read-only admin preview in isolated test tenant, viewer token-оор access control check.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'Viewer token + read-only admin preview route; no production mutations'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/api/v1/admin/settings-preview HTTP/1.1
Host: app.lab.test
Authorization: Bearer OWN_VIEWER
```

```http
HTTP/1.1 403 Forbidden

{"error":"role denied"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Admin-only synthetic metadata viewer token-д ирвэл confirmed.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Admin-only synthetic metadata viewer token-д ирвэл confirmed. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Endpoint deliberately public, feature entitlement not documented. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** C/I High. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Explicit action permissions, policy engine, GraphQL resolver checks. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `API BFLA on synthetic lab endpoint`
- **Summary:** API function-level эрхийн алдаа; ажиглагдсан ялгаа нь `Admin-only synthetic metadata viewer token-д ирвэл confirmed.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/api/v1/admin/settings-preview HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** C/I High.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Explicit action permissions, policy engine, GraphQL resolver checks.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/api/v1/admin/settings-preview HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/api/v1/admin/settings-preview HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 10.3 Broken Object Property Level Authorization (BOPLA) — Объектын field түвшний эрхийн алдаа

**A. Vulnerability Name.** **Broken Object Property Level Authorization (BOPLA)** — Объектын field түвшний эрхийн алдаа.

**B. What Is It? (Энгийнээр).** Profile-г харж болно, гэхдээ private `internalNotes` field ч хамт буцаж байна.

**C. Why Does It Happen? (Root cause).** Serializer field-level allowlist, mutation DTO permission дутуу.

**D. Where to Look? (Тестийн байрлал).** `GET /api/users/me`, JSON `internalNote`, `salary`, `roles`, GraphQL field. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Өөрийн test admin/regular account-ийн synthetic field-үүдээр role-specific response compare; real salaries/PII бүү шалга.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'Compare only seeded synthetic fields across own authorized roles'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/api/v1/users/B-PUBLIC-PROFILE HTTP/1.1
Host: app.lab.test
Authorization: Bearer OWN_VIEWER
```

```http
HTTP/1.1 200 OK

{"displayName":"Lab B"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Private `internalNotes: "B_SECRET_MARKER"` viewer response-д орсон бол excess field exposure confirmed.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Private `internalNotes: "B_SECRET_MARKER"` viewer response-д орсон бол excess field exposure confirmed. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** API public schema includes field by design; field value not sensitive. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** C Medium/High, I if sensitive fields mass editable. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): Medium.** Нөлөө, шаардлагатай эрх, attacker interaction-аас хамаарч Low–High хооронд хэлбэлзэнэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Per-field serialization policy, DTO allowlist, GraphQL field auth and negative tests. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Broken Object Property Level Authorization (BOPLA) on synthetic lab endpoint`
- **Summary:** Объектын field түвшний эрхийн алдаа; ажиглагдсан ялгаа нь `Private `internalNotes: "B_SECRET_MARKER"` viewer response-д орсон бол excess field exposure confirmed.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/api/v1/users/B-PUBLIC-PROFILE HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** C Medium/High, I if sensitive fields mass editable.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Per-field serialization policy, DTO allowlist, GraphQL field auth and negative tests.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/api/v1/users/B-PUBLIC-PROFILE HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/api/v1/users/B-PUBLIC-PROFILE HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 10.4 Excessive Data Exposure — Хэрэгцээгүй олон sensitive data буцаах

**A. Vulnerability Name.** **Excessive Data Exposure** — Хэрэгцээгүй олон sensitive data буцаах.

**B. What Is It? (Энгийнээр).** Дэлгэц зөвхөн нэрийг харуулдаг ч JSON нь нууц талбар агуулна.

**C. Why Does It Happen? (Root cause).** Backend raw DB model serialize, frontend filtering-д найддаг.

**D. Where to Look? (Тестийн байрлал).** `/api/profile`, network response vs displayed UI, mobile APIs. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Own test account-аар DevTools Network response-г UI field-тэй харьцуулж synthetic test-only private field leak эсэхийг шалга.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'DevTools > Network > Response: compare UI-required vs API-returned own fields'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/api/v1/profile HTTP/1.1
Host: app.lab.test
Authorization: Bearer OWN_A
```

```http
HTTP/1.1 200 OK

{"displayName":"Lab A"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Unneeded sensitive marker response-д байвал risk; **өөрийн** мэдээлэл илүү ирэх нь bounty eligible эсэх program-оос хамаарна.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Unneeded sensitive marker response-д байвал risk; **өөрийн** мэдээлэл илүү ирэх нь bounty eligible эсэх program-оос хамаарна. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Frontend hidden field intentional business integration, non-sensitive metadata. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** C depends on audience/object authorization. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): Medium.** Нөлөө, шаардлагатай эрх, attacker interaction-аас хамаарч Low–High хооронд хэлбэлзэнэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Return minimal DTO/fields, schema review, per-field policies, no credentials in JSON. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Excessive Data Exposure on synthetic lab endpoint`
- **Summary:** Хэрэгцээгүй олон sensitive data буцаах; ажиглагдсан ялгаа нь `Unneeded sensitive marker response-д байвал risk; **өөрийн** мэдээлэл илүү ирэх нь bounty eligible эсэх program-оос хамаарна.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/api/v1/profile HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** C depends on audience/object authorization.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Return minimal DTO/fields, schema review, per-field policies, no credentials in JSON.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/api/v1/profile HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/api/v1/profile HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 10.5 API Mass Assignment — API update-д илүүдэл JSON property орох

**A. Vulnerability Name.** **API Mass Assignment** — API update-д илүүдэл JSON property орох.

**B. What Is It? (Энгийнээр).** Profile update body-д server-managed `approved` field-ийг хэрэглэгч нэмдэг.

**C. Why Does It Happen? (Root cause).** Untrusted JSON to data model auto-binding without allowlist.

**D. Where to Look? (Тестийн байрлал).** `PATCH /api/me`, `POST /api/orders`, `isApproved`, `tenantId`. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Own isolated lab object-д harmless unknown `labExtra` нэм; persist эсэхийг GET-ээр шалга; protected role field зөвхөн lab fixture-д.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' '{"displayName":"Lab A","labExtra":"x"}'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
PATCH /lab/api/v1/me HTTP/1.1
Host: app.lab.test
Content-Type: application/json

{"displayName":"Lab A","labExtra":"x"}
```

```http
HTTP/1.1 200 OK

{"displayName":"Lab A"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Unexpected server-managed field persist + authority impact isolated proof шаардлагатай.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Unexpected server-managed field persist + authority impact isolated proof шаардлагатай. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Echoed input vs persisted, customizable extension fields. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** I High if privileged values mutable. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** DTO input models, field allowlist, validated server-owned fields. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `API Mass Assignment on synthetic lab endpoint`
- **Summary:** API update-д илүүдэл JSON property орох; ажиглагдсан ялгаа нь `Unexpected server-managed field persist + authority impact isolated proof шаардлагатай.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `PATCH /lab/api/v1/me HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** I High if privileged values mutable.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** DTO input models, field allowlist, validated server-owned fields.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `PATCH /lab/api/v1/me HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `PATCH /lab/api/v1/me HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 10.6 Unrestricted Resource Consumption / Rate Limiting — API resource лимитгүй хэрэглээ

**A. Vulnerability Name.** **Unrestricted Resource Consumption / Rate Limiting** — API resource лимитгүй хэрэглээ.

**B. What Is It? (Энгийнээр).** Давтамж, pagination хэмжээ буруу хязгаарлагдсан тул API resource ачаалж магадгүй.

**C. Why Does It Happen? (Root cause).** No quota, no max page size, expensive operation not bounded.

**D. Where to Look? (Тестийн байрлал).** `?limit=`, pagination, GraphQL depth, `/export`, `/send-code`. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Production-д throughput test хийхгүй; нэг own request-д `limit=9999` хүсээд max clamp/400 эсэхийг хар; load хэмжих бол isolated lab.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'GET /lab/api/items?limit=9999 once; verify server clamps to documented maximum'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/api/items?limit=9999 HTTP/1.1
Host: app.lab.test
Authorization: Bearer OWN_A
```

```http
HTTP/1.1 400 Bad Request

{"error":"limit exceeds 100"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Unlimited response/body/time эсвэл load risk actual proof хийхэд design/config evidence хэрэгтэй; нэг 200 finding биш.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Unlimited response/body/time эсвэл load risk actual proof хийхэд design/config evidence хэрэгтэй; нэг 200 finding биш. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Total item count < limit, proxy response truncation, intentionally allowed large pages. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** Availability risk theoretical unless demonstrated; do not stress. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): Medium.** Нөлөө, шаардлагатай эрх, attacker interaction-аас хамаарч Low–High хооронд хэлбэлзэнэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Max page size, complexity cost budget, per-user quota, timeouts, backpressure, monitoring. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Unrestricted Resource Consumption / Rate Limiting on synthetic lab endpoint`
- **Summary:** API resource лимитгүй хэрэглээ; ажиглагдсан ялгаа нь `Unlimited response/body/time эсвэл load risk actual proof хийхэд design/config evidence хэрэгтэй; нэг 200 finding биш.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/api/items?limit=9999 HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** Availability risk theoretical unless demonstrated; do not stress.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Max page size, complexity cost budget, per-user quota, timeouts, backpressure, monitoring.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/api/items?limit=9999 HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/api/items?limit=9999 HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 10.7 API Authentication Weakness — API token ба credential шалгалт

**A. Vulnerability Name.** **API Authentication Weakness** — API token ба credential шалгалт.

**B. What Is It? (Энгийнээр).** API endpoint заримдаа token-гүй ажиллаж нууц data өгдөг.

**C. Why Does It Happen? (Root cause).** Route auth middleware missing, token issuer/audience/scope not checked.

**D. Where to Look? (Тестийн байрлал).** `Authorization`, API keys, cookie session, public/private routes. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Өөрийн `/lab/api/me` GET request token-той ба token-гүйгээр нэг нэг удаа харьцуул.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'Compare one own profile GET with and without Authorization header'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/api/me HTTP/1.1
Host: app.lab.test
```

```http
HTTP/1.1 401 Unauthorized

{"error":"login required"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** No-token request private synthetic data өгвөл confirmed.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** No-token request private synthetic data өгвөл confirmed. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Session cookie аль хэдийн browser-д байна; endpoint deliberately public. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** C High if private identity data, I if mutable methods exposed. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Uniform auth middleware, token validation and scopes, regression tests. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `API Authentication Weakness on synthetic lab endpoint`
- **Summary:** API token ба credential шалгалт; ажиглагдсан ялгаа нь `No-token request private synthetic data өгвөл confirmed.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/api/me HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** C High if private identity data, I if mutable methods exposed.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Uniform auth middleware, token validation and scopes, regression tests.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/api/me HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/api/me HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 10.8 API Versioning / Inventory — Хуучин API version хамгаалалтгүй үлдэх

**A. Vulnerability Name.** **API Versioning / Inventory** — Хуучин API version хамгаалалтгүй үлдэх.

**B. What Is It? (Энгийнээр).** Шинэ API protected боловч v1 route үлдсэн.

**C. Why Does It Happen? (Root cause).** Deprecated endpoint inventory missing, inconsistent auth.

**D. Where to Look? (Тестийн байрлал).** `/api/v1/` vs `/api/v2/`, swagger, OpenAPI inventory. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Program-аар **хоёулаа scope-д байгаа** version дээр зөвхөн own synthetic profile read; auth differences observe.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'Document both in-scope API versions; avoid unknown legacy hosts'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/api/v1/private-summary HTTP/1.1
Host: app.lab.test
```

```http
HTTP/1.1 401 Unauthorized

{"error":"login required"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** v1 no-auth private data, v2 rejected → confirmed version mismatch.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** v1 no-auth private data, v2 rejected → confirmed version mismatch. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Different audience/permission by design, version paths map public route. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** C/I high if legacy endpoints expose protected actions. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** API inventory and retirement, consistent auth policies across versions, gateway routing. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `API Versioning / Inventory on synthetic lab endpoint`
- **Summary:** Хуучин API version хамгаалалтгүй үлдэх; ажиглагдсан ялгаа нь `v1 no-auth private data, v2 rejected → confirmed version mismatch.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/api/v1/private-summary HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** C/I high if legacy endpoints expose protected actions.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** API inventory and retirement, consistent auth policies across versions, gateway routing.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/api/v1/private-summary HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/api/v1/private-summary HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 10.9 GraphQL Field / Resolver Authorization — GraphQL field болон resolver-ийн эрхийн алдаа

**A. Vulnerability Name.** **GraphQL Field / Resolver Authorization** — GraphQL field болон resolver-ийн эрхийн алдаа.

**B. What Is It? (Энгийнээр).** Query зөвшөөрөгдөх ч nested private field check хийхгүй байж болно.

**C. Why Does It Happen? (Root cause).** Resolver auth relies on root query only, field-level authorization absent.

**D. Where to Look? (Тестийн байрлал).** `POST /graphql`, `user(id)`, nested `internalNotes`, mutations. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **Web Security Academy GraphQL API vulnerabilities**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Өөрийн account A/B synthetic records; **нэг** shallow query-д B object-ийн public ба private field хүсээд field-specific error эсэхийг хар.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' '{ user(id: "OWN_B") { displayName internalNotes } }'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
POST /lab/graphql HTTP/1.1
Host: app.lab.test
Content-Type: application/json

{"query":"{ user(id: \"OWN_B\") { displayName internalNotes } }"}
```

```http
HTTP/1.1 200 OK

{"data":{"user":{"displayName":"Lab B","internalNotes":null}},"errors":[{"message":"forbidden"}]}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** GraphQL HTTP 200 нь auth success батлахгүй; `data` ба `errors` хамт унш. Private field marker ирвэл issue.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** GraphQL HTTP 200 нь auth success батлахгүй; `data` ба `errors` хамт унш. Private field marker ирвэл issue. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Schema permission allows shared internalNotes, introspection enable бол finding биш. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** C/I dependent on field/action. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Field-level auth in resolvers, query complexity limits, schema policy tests. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `GraphQL Field / Resolver Authorization on synthetic lab endpoint`
- **Summary:** GraphQL field болон resolver-ийн эрхийн алдаа; ажиглагдсан ялгаа нь `GraphQL HTTP 200 нь auth success батлахгүй; `data` ба `errors` хамт унш. Private field marker ирвэл issue.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `POST /lab/graphql HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** C/I dependent on field/action.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Field-level auth in resolvers, query complexity limits, schema policy tests.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `POST /lab/graphql HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `POST /lab/graphql HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 10.10 Unsafe Consumption of External APIs — Гаднын API response-д хэт итгэх

**A. Vulnerability Name.** **Unsafe Consumption of External APIs** — Гаднын API response-д хэт итгэх.

**B. What Is It? (Энгийнээр).** Third-party API-аас ирсэн field-г шалгалтгүйгээр өөрийн системд зөвшөөрсөн утга гэж хэрэглэдэг.

**C. Why Does It Happen? (Root cause).** Unvalidated external response, weak TLS/identity trust, unsafe data transformation.

**D. Where to Look? (Тестийн байрлал).** Vendor webhook mock, payment status callback, shipping price, external JSON. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **OWASP crAPI private mock integration**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Зөвхөн owner-controlled local mock provider-т `status:"PENDING"` ба invalid enum өгч app reject/log эсэхийг шалга; real provider руу webhook бүү илгээ.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' '{"status":"UNKNOWN_LAB_STATE"}'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
POST /lab/mock-provider/callback HTTP/1.1
Host: isolated.lab.test
Content-Type: application/json

{"status":"UNKNOWN_LAB_STATE"}
```

```http
HTTP/1.1 400 Bad Request

{"error":"unexpected provider status"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Unknown provider response authoritative transaction state өөрчилбөл lab-д confirmed.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Unknown provider response authoritative transaction state өөрчилбөл lab-д confirmed. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Callback test stub intentional, signature verified upstream. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** I High business context-dependent. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Sign/verify webhooks, schema validate response, allowlisted transitions and provenance checks. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Unsafe Consumption of External APIs on synthetic lab endpoint`
- **Summary:** Гаднын API response-д хэт итгэх; ажиглагдсан ялгаа нь `Unknown provider response authoritative transaction state өөрчилбөл lab-д confirmed.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `POST /lab/mock-provider/callback HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** I High business context-dependent.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Sign/verify webhooks, schema validate response, allowlisted transitions and provenance checks.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `POST /lab/mock-provider/callback HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `POST /lab/mock-provider/callback HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### Chapter 10 — Consolidated review

**Хамгийн чухал:** Confirmed finding бол зөвхөн response string биш, precondition + policy boundary + actual effect + negative control-оор дэмжигдсэн дүгнэлт. `Finding ID`, `confidence (hypothesis/likely/confirmed)`, severity rationale-г нэгтгэ.

<a id="chapter-11"></a>
## Chapter 11 — Business Logic Vulnerabilities

Бизнес дүрэм зөвхөн UI биш backend transaction / state-machine дээр enforce хийгдэх ёстой. Цэнэглэх, худалдан авах, имэйл илгээх, approve хийх бодит үйлдэл production-д тестлэхгүй.

> **Сургалтын маршрут:** Эхлээд raw HTTP-г ойлго → baseline → own controlled change → negative control → state validation → report. Доорх бүх `/lab` URL ба response нь **synthetic**. Бодит дасгалыг дурдсан lab-ийн сэдвийн exercise-д хий.

### 11.1 Coupon Validation Bypass — Купон ашиглалтын бизнес дүрмийн алдаа

**A. Vulnerability Name.** **Coupon Validation Bypass** — Купон ашиглалтын бизнес дүрмийн алдаа.

**B. What Is It? (Энгийнээр).** Нэг удаа хэрэглэх купон олон удаа хөнгөлөлт тооцуулах.

**C. Why Does It Happen? (Root cause).** Coupon eligibility/use count server transaction-д atomic биш, frontend-only validation.

**D. Where to Look? (Тестийн байрлал).** `POST /coupon/apply`, `cart`, `redeem`, `checkout`. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **Web Security Academy Business logic / own mock checkout**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Тусгаарласан zero-value order fixture + own coupon; нэг хэрэглэсний дараа **нэг удаа** duplicate apply хийхэд reject эсэхийг шалга.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'LAB_COUPON_ONCE'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
POST /lab/cart/coupon HTTP/1.1
Host: isolated.lab.test
Content-Type: application/json

{"cartId":"OWN_ZERO_CART","coupon":"LAB_COUPON_ONCE"}
```

```http
HTTP/1.1 409 Conflict

{"error":"coupon already redeemed"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Second apply discount double-counted, total state diff → confirmed; 200 with `alreadyApplied:true` is not.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Second apply discount double-counted, total state diff → confirmed; 200 with `alreadyApplied:true` is not. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Coupon reusable by policy, identical total despite 200, UI stale. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** I/financial Medium/High depending on redeem scale. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Server-side rules, atomic redemption, unique constraints, idempotency. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Coupon Validation Bypass on synthetic lab endpoint`
- **Summary:** Купон ашиглалтын бизнес дүрмийн алдаа; ажиглагдсан ялгаа нь `Second apply discount double-counted, total state diff → confirmed; 200 with `alreadyApplied:true` is not.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `POST /lab/cart/coupon HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** I/financial Medium/High depending on redeem scale.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Server-side rules, atomic redemption, unique constraints, idempotency.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `POST /lab/cart/coupon HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `POST /lab/cart/coupon HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 11.2 Checkout Flow Bypass — Төлбөр/checkout урсгал алгасах

**A. Vulnerability Name.** **Checkout Flow Bypass** — Төлбөр/checkout урсгал алгасах.

**B. What Is It? (Энгийнээр).** Төлбөр батлагдахаас өмнө “paid” шатны нөөц олгох.

**C. Why Does It Happen? (Root cause).** Order state machine and payment verification backend missing.

**D. Where to Look? (Тестийн байрлал).** `/checkout/start`, `/payment/callback`, `/order/complete`, order status. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **Private checkout fixture / Academy business logic**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Зөвхөн local mock payment sandbox-д zero-cost test order; verified payment event-гүйгээр fulfilled state руу шилжихгүй эсэхийг observe; production order үүсгэхгүй.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'Test order state transitions with synthetic zero-value order only'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/orders/OWN_ZERO_ORDER HTTP/1.1
Host: isolated.lab.test
```

```http
HTTP/1.1 200 OK

{"status":"AWAITING_PAYMENT"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Payment success event огт байхгүй атал `FULFILLED` state болсон нь confirm; status string overwrite alone биш.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Payment success event огт байхгүй атал `FULFILLED` state болсон нь confirm; status string overwrite alone биш. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Free product/shipping promotion allowed; test-only provisioning. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** I/financial High, possible service abuse. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Server-side verified payment gateway signature, robust state machine, reconciliation. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Checkout Flow Bypass on synthetic lab endpoint`
- **Summary:** Төлбөр/checkout урсгал алгасах; ажиглагдсан ялгаа нь `Payment success event огт байхгүй атал `FULFILLED` state болсон нь confirm; status string overwrite alone биш.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/orders/OWN_ZERO_ORDER HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** I/financial High, possible service abuse.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Server-side verified payment gateway signature, robust state machine, reconciliation.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/orders/OWN_ZERO_ORDER HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/orders/OWN_ZERO_ORDER HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 11.3 Price / Quantity Trust — Үнэ эсвэл тоо хэмжээг client-ээс итгэх

**A. Vulnerability Name.** **Price / Quantity Trust** — Үнэ эсвэл тоо хэмжээг client-ээс итгэх.

**B. What Is It? (Энгийнээр).** Browser дээр үнэ өөрчлөөд server түүнийг жинхэнэ гэж хүлээж авдаг.

**C. Why Does It Happen? (Root cause).** Server recalculation missing, client total/discount trusted.

**D. Where to Look? (Тестийн байрлал).** `price`, `unitPrice`, `total`, `quantity`, `discount` JSON fields. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Local mock order-ийн `unitPrice` field-д synthetic value өөрчлөөд server-side quoted price өөрчлөгдөх эсэхийг хар; ямар ч real purchase хийхгүй.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' '{"sku":"LAB-ITEM","quantity":1,"clientTotal":0}'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
POST /lab/orders/quote HTTP/1.1
Host: isolated.lab.test
Content-Type: application/json

{"sku":"LAB-ITEM","quantity":1,"clientTotal":0}
```

```http
HTTP/1.1 200 OK

{"serverTotal":100,"currency":"TEST"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Server quote clientTotal=0 болгосноор actual serverTotal=0 болж unauthorized discount өгвөл confirmed.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Server quote clientTotal=0 болгосноор actual serverTotal=0 болж unauthorized discount өгвөл confirmed. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Free trial/test SKU, server applies legitimate promotion, quote-only UI. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** I High financial depending on business. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Compute price/tax/discount server-side from SKU, validate quantity bounds, signed price quotes. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Price / Quantity Trust on synthetic lab endpoint`
- **Summary:** Үнэ эсвэл тоо хэмжээг client-ээс итгэх; ажиглагдсан ялгаа нь `Server quote clientTotal=0 болгосноор actual serverTotal=0 болж unauthorized discount өгвөл confirmed.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `POST /lab/orders/quote HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** I High financial depending on business.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Compute price/tax/discount server-side from SKU, validate quantity bounds, signed price quotes.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `POST /lab/orders/quote HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `POST /lab/orders/quote HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 11.4 Workflow Bypass — Дараалсан процессын шат алгасах

**A. Vulnerability Name.** **Workflow Bypass** — Дараалсан процессын шат алгасах.

**B. What Is It? (Энгийнээр).** Шаардлагатай review/approval шатыг алгасаад дараагийн шатны result авах.

**C. Why Does It Happen? (Root cause).** Server-side state transition guard missing.

**D. Where to Look? (Тестийн байрлал).** `draft`, `submit`, `review`, `approved` action endpoints. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Own synthetic workflow item-н `DRAFT` state-ээс `APPROVED` зэрэг шатанд үсрэх оролдлогыг local fixture-д хийнэ.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'DRAFT -> APPROVED must be forbidden without REVIEWED'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
POST /lab/workflows/OWN_ITEM/approve HTTP/1.1
Host: isolated.lab.test
Content-Type: application/json

{}
```

```http
HTTP/1.1 409 Conflict

{"error":"invalid state transition"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Unreviewed own object approved state-д бодитоор орсон бол confirmed.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Unreviewed own object approved state-д бодитоор орсон бол confirmed. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Auto-approval rule, actor-specific workflow, test role permissions. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** I Medium/High. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Explicit state-machine checks, authorization per transition, audit trail. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Workflow Bypass on synthetic lab endpoint`
- **Summary:** Дараалсан процессын шат алгасах; ажиглагдсан ялгаа нь `Unreviewed own object approved state-д бодитоор орсон бол confirmed.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `POST /lab/workflows/OWN_ITEM/approve HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** I Medium/High.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Explicit state-machine checks, authorization per transition, audit trail.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `POST /lab/workflows/OWN_ITEM/approve HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `POST /lab/workflows/OWN_ITEM/approve HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 11.5 Multi-step Process Bypass — Олон алхамтай form/request тойрох

**A. Vulnerability Name.** **Multi-step Process Bypass** — Олон алхамтай form/request тойрох.

**B. What Is It? (Энгийнээр).** Step 1 баталгаагүй байхад step 3-г шууд дуудаж дуусгах.

**C. Why Does It Happen? (Root cause).** Server trusts client-side step field instead of state.

**D. Where to Look? (Тестийн байрлал).** `step`, `/wizard/finish`, `/onboarding/complete`. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Local onboarding fixture-д өөрийн account-ийн unfinished step state-тай `finish` request-г ганц удаа илгээж reject эсэхийг шалга.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'Own lab wizard: submit final step before prerequisite verification'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
POST /lab/onboarding/finish HTTP/1.1
Host: isolated.lab.test
Content-Type: application/json

{"wizardId":"OWN_LAB_WIZARD"}
```

```http
HTTP/1.1 409 Conflict

{"error":"required step missing"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Mandatory policy/verification step absent боловч final state persisted -> confirmed.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Mandatory policy/verification step absent боловч final state persisted -> confirmed. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Optional step, migration account, auto-completed server workflow. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** I Medium/High. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): Medium.** Нөлөө, шаардлагатай эрх, attacker interaction-аас хамаарч Low–High хооронд хэлбэлзэнэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Server-saved progress, per-step validation, authorization, idempotent transitions. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Multi-step Process Bypass on synthetic lab endpoint`
- **Summary:** Олон алхамтай form/request тойрох; ажиглагдсан ялгаа нь `Mandatory policy/verification step absent боловч final state persisted -> confirmed.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `POST /lab/onboarding/finish HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** I Medium/High.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Server-saved progress, per-step validation, authorization, idempotent transitions.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `POST /lab/onboarding/finish HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `POST /lab/onboarding/finish HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 11.6 Duplicate Transaction Processing — Давхардсан хүсэлтээр давхар гүйлгээ хийх

**A. Vulnerability Name.** **Duplicate Transaction Processing** — Давхардсан хүсэлтээр давхар гүйлгээ хийх.

**B. What Is It? (Энгийнээр).** Сүлжээний retry бүрт transaction хоёр удаа бичигдэх.

**C. Why Does It Happen? (Root cause).** Missing idempotency key, unique transaction ID, atomic commit.

**D. Where to Look? (Тестийн байрлал).** `POST /transactions`, payment retry, webhook delivery, checkout. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **Private zero-value transaction lab**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Тусгаарласан ledger mock-д zero-value synthetic transaction-г нэг `Idempotency-Key`-тэй **2 удаа дараалан** явуул; records count 1 байх ёстой.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'Idempotency-Key: OWN-LAB-KEY-001'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
POST /lab/transactions HTTP/1.1
Host: isolated.lab.test
Idempotency-Key: OWN-LAB-KEY-001
Content-Type: application/json

{"amount":0,"currency":"TEST"}
```

```http
HTTP/1.1 200 OK

{"transactionId":"OWN-TXN-1","duplicate":true}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** 2 separate ledger record (same key) байвал confirmed; 2 HTTP 200 нь alone proof биш.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** 2 separate ledger record (same key) байвал confirmed; 2 HTTP 200 нь alone proof биш. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Legitimate distinct transaction IDs, read replicas eventual consistency. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** I High financial context, production payment-д огт туршихгүй. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Idempotency table keyed by actor/intent, unique constraints, retry-safe handlers. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Duplicate Transaction Processing on synthetic lab endpoint`
- **Summary:** Давхардсан хүсэлтээр давхар гүйлгээ хийх; ажиглагдсан ялгаа нь `2 separate ledger record (same key) байвал confirmed; 2 HTTP 200 нь alone proof биш.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `POST /lab/transactions HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** I High financial context, production payment-д огт туршихгүй.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Idempotency table keyed by actor/intent, unique constraints, retry-safe handlers.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `POST /lab/transactions HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `POST /lab/transactions HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 11.7 Approval / Segregation of Duties Bypass — Зөвшөөрөл ба үүрэг тусгаарлалтын алдаа

**A. Vulnerability Name.** **Approval / Segregation of Duties Bypass** — Зөвшөөрөл ба үүрэг тусгаарлалтын алдаа.

**B. What Is It? (Энгийнээр).** Өөрөө хүсэлт үүсгэсэн хүн өөрийнхөө хүсэлтийг approve хийх.

**C. Why Does It Happen? (Root cause).** Role-only authorization, maker-checker identity constraint missing.

**D. Where to Look? (Тестийн байрлал).** `/requests/{id}/approve`, `requestedBy`, `approvedBy`, action role. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Own synthetic maker-checker lab-д maker account-аас өөрийн request-ийн approval preview/check request хий; actual approval test зөвхөн lab.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'Maker != Checker must be server-side invariant'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
POST /lab/requests/OWN_REQUEST/approve HTTP/1.1
Host: isolated.lab.test
Content-Type: application/json

{}
```

```http
HTTP/1.1 403 Forbidden

{"error":"self-approval prohibited"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Maker өөрийгөө approve болгож persisted decision үүсгэвэл confirmed.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Maker өөрийгөө approve болгож persisted decision үүсгэвэл confirmed. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Emergency override/dual-control rules documented, test role special. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** I High especially finance/compliance. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Check `approver.id != request.creator.id`, dual authorization and audit logging. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Approval / Segregation of Duties Bypass on synthetic lab endpoint`
- **Summary:** Зөвшөөрөл ба үүрэг тусгаарлалтын алдаа; ажиглагдсан ялгаа нь `Maker өөрийгөө approve болгож persisted decision үүсгэвэл confirmed.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `POST /lab/requests/OWN_REQUEST/approve HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** I High especially finance/compliance.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Check `approver.id != request.creator.id`, dual authorization and audit logging.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `POST /lab/requests/OWN_REQUEST/approve HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `POST /lab/requests/OWN_REQUEST/approve HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### Chapter 11 — Consolidated review

**Хамгийн чухал:** Confirmed finding бол зөвхөн response string биш, precondition + policy boundary + actual effect + negative control-оор дэмжигдсэн дүгнэлт. `Finding ID`, `confidence (hypothesis/likely/confirmed)`, severity rationale-г нэгтгэ.

<a id="chapter-12"></a>
## Chapter 12 — Security Misconfiguration

Configuration gap болон exploitable vulnerability-г заавал ялга. Banner/headers alone нь ихэвчлэн low/informational; нууц мэдээлэл, access control impact шаарддаг.

> **Сургалтын маршрут:** Эхлээд raw HTTP-г ойлго → baseline → own controlled change → negative control → state validation → report. Доорх бүх `/lab` URL ба response нь **synthetic**. Бодит дасгалыг дурдсан lab-ийн сэдвийн exercise-д хий.

### 12.1 Missing Security Headers — HTTP security header дутуу

**A. Vulnerability Name.** **Missing Security Headers** — HTTP security header дутуу.

**B. What Is It? (Энгийнээр).** Browser-д зааварлах хамгаалалтын header үгүй.

**C. Why Does It Happen? (Root cause).** Headers policy not deployed at app/reverse proxy, inconsistent routes.

**D. Where to Look? (Тестийн байрлал).** Response headers `CSP`, `HSTS`, `X-Content-Type-Options`, `Referrer-Policy`. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Own local or approved URL-д `curl -I` хийж policy inventory; missing header-ийг *ганцаараа exploit* гэж бүү бич.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
curl -sS -I --max-time 10 http://127.0.0.1:3000/
```

`curl` = HTTP client; `-sS` = progress нуух боловч error хэвлэх; `-i` = response header харуулах; `-I` = HEAD request; `--max-time 10` = 10 секунд timeout; `-X` = HTTP method; `-H` = header; `--data` = body. Зөвхөн ашигласан flag-ууд энэ command-д хамаарна.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
HEAD /lab/ HTTP/1.1
Host: app.lab.test
```

```http
HTTP/1.1 200 OK
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Header missing = configuration gap, exploitation to validate additional vulnerability required.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Header missing = configuration gap, exploitation to validate additional vulnerability required. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** HSTS HTTP localhost-д үгүй байх нь normal; app not using inline scripts, browser defaults. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** Typically Informational/Low standalone; chained impact higher. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): Low.** Нөлөө ихэнхдээ context-dependent; CVSS ихэвчлэн Low/Informational байж болно. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Set relevant HTTPS security headers and test compatibility; no blanket copy-paste CSP. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Missing Security Headers on synthetic lab endpoint`
- **Summary:** HTTP security header дутуу; ажиглагдсан ялгаа нь `Header missing = configuration gap, exploitation to validate additional vulnerability required.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `HEAD /lab/ HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** Typically Informational/Low standalone; chained impact higher.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Set relevant HTTPS security headers and test compatibility; no blanket copy-paste CSP.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `HEAD /lab/ HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `HEAD /lab/ HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 12.2 CORS Misconfiguration — CORS origin/credentials буруу тохиргоо

**A. Vulnerability Name.** **CORS Misconfiguration** — CORS origin/credentials буруу тохиргоо.

**B. What Is It? (Энгийнээр).** Private API өөр origin-д credentialed browser read эрх зөвшөөрсөн.

**C. Why Does It Happen? (Root cause).** Untrusted `Origin` reflected with `Access-Control-Allow-Credentials: true` for private data.

**D. Where to Look? (Тестийн байрлал).** `Origin` request header, ACAO/ACAC response, private endpoint, cookies. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **Web Security Academy CORS**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Own isolated lab Origin=`http://127.0.0.1:9001`-оор one-request check; browser cross-origin proof own data only.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
curl -sS -i --max-time 10 -H 'Origin: http://127.0.0.1:9001' http://127.0.0.1:3000/
```

`curl` = HTTP client; `-sS` = progress нуух боловч error хэвлэх; `-i` = response header харуулах; `-I` = HEAD request; `--max-time 10` = 10 секунд timeout; `-X` = HTTP method; `-H` = header; `--data` = body. Зөвхөн ашигласан flag-ууд энэ command-д хамаарна.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/private HTTP/1.1
Host: app.lab.test
Origin: http://127.0.0.1:9001
Cookie: sid=OWN_LAB_SESSION
```

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://app.lab.test
Vary: Origin
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** If reflected `http://127.0.0.1:9001` + `Access-Control-Allow-Credentials: true` + browser JS own sensitive data reads → confirmed.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** If reflected `http://127.0.0.1:9001` + `Access-Control-Allow-Credentials: true` + browser JS own sensitive data reads → confirmed. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** `ACAO: *` no credentials, public API, curl bypasses CORS (browser enforced), SameSite cookie not sent. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** C High if victim private data accessible to untrusted origin. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Exact allowed origins, never reflect arbitrary origin with credentials, Vary: Origin, SameSite and CSRF controls. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `CORS Misconfiguration on synthetic lab endpoint`
- **Summary:** CORS origin/credentials буруу тохиргоо; ажиглагдсан ялгаа нь `If reflected `http://127.0.0.1:9001` + `Access-Control-Allow-Credentials: true` + browser JS own sensitive data reads → confirmed.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/private HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** C High if victim private data accessible to untrusted origin.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Exact allowed origins, never reflect arbitrary origin with credentials, Vary: Origin, SameSite and CSRF controls.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/private HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/private HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 12.3 Debug Mode / Stack Traces — Debug алдаа нарийн мэдээлэл ил гаргах

**A. Vulnerability Name.** **Debug Mode / Stack Traces** — Debug алдаа нарийн мэдээлэл ил гаргах.

**B. What Is It? (Энгийнээр).** Алдаа гаргахад stack trace/absolute path хэрэглэгчид харагдах.

**C. Why Does It Happen? (Root cause).** Production debug mode on, verbose exception handler.

**D. Where to Look? (Тестийн байрлал).** `/error`, invalid input, error pages, stack trace, framework banner. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: One harmless wrong-type parameter илгээж response error verbosity хар; deliberate crashes/flood хийхгүй.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
curl -sS -i --max-time 10 'http://127.0.0.1:3000/?page=not-a-number'
```

`curl` = HTTP client; `-sS` = progress нуух боловч error хэвлэх; `-i` = response header харуулах; `-I` = HEAD request; `--max-time 10` = 10 секунд timeout; `-X` = HTTP method; `-H` = header; `--data` = body. Зөвхөн ашигласан flag-ууд энэ command-д хамаарна.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/items?page=not-a-number HTTP/1.1
Host: app.lab.test
```

```http
HTTP/1.1 400 Bad Request

{"error":"invalid page"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Internal code file path/DB query/secret in response бол information disclosure; log-only trace not exposed.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Internal code file path/DB query/secret in response бол information disclosure; log-only trace not exposed. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Developer lab intentionally debug, generic framework version exposure without sensitive details. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** C Low/Medium; secret exposure may High. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): Low.** Нөлөө ихэнхдээ context-dependent; CVSS ихэвчлэн Low/Informational байж болно. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Disable debug mode, generic client errors, secure server-side logging and redaction. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Debug Mode / Stack Traces on synthetic lab endpoint`
- **Summary:** Debug алдаа нарийн мэдээлэл ил гаргах; ажиглагдсан ялгаа нь `Internal code file path/DB query/secret in response бол information disclosure; log-only trace not exposed.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/items?page=not-a-number HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** C Low/Medium; secret exposure may High.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Disable debug mode, generic client errors, secure server-side logging and redaction.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/items?page=not-a-number HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/items?page=not-a-number HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 12.4 Directory Listing — Folder доторх файлуудын жагсаалт ил гаргах

**A. Vulnerability Name.** **Directory Listing** — Folder доторх файлуудын жагсаалт ил гаргах.

**B. What Is It? (Энгийнээр).** Web folder-ийн index file байхгүй үед бүх нэр харагдана.

**C. Why Does It Happen? (Root cause).** Web server `autoindex`/directory browse enabled on sensitive path.

**D. Where to Look? (Тестийн байрлал).** `/uploads/`, `/backup/`, `/static/`, Directory listing HTML. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Own lab public folder-руу `GET` хийж index content харах; listed files-ийг bulk download хийхгүй.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'Check /lab/public-files/ only; do not recursively download'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/public-files/ HTTP/1.1
Host: app.lab.test
```

```http
HTTP/1.1 403 Forbidden

{"error":"listing disabled"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Index of private artifact names гарвал context-оос severity; public static folder listing alone not necessarily issue.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Index of private artifact names гарвал context-оос severity; public static folder listing alone not necessarily issue. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Static asset directory public by design; generated index vs template list. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** C Low/Medium or High if private files exposed. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): Low.** Нөлөө ихэнхдээ context-dependent; CVSS ихэвчлэн Low/Informational байж болно. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Disable autoindex, authenticated file serving, separate non-web storage. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Directory Listing on synthetic lab endpoint`
- **Summary:** Folder доторх файлуудын жагсаалт ил гаргах; ажиглагдсан ялгаа нь `Index of private artifact names гарвал context-оос severity; public static folder listing alone not necessarily issue.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/public-files/ HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** C Low/Medium or High if private files exposed.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Disable autoindex, authenticated file serving, separate non-web storage.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/public-files/ HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/public-files/ HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 12.5 Exposed Backup Files — Backup/config файл public endpoint-д байх

**A. Vulnerability Name.** **Exposed Backup Files** — Backup/config файл public endpoint-д байх.

**B. What Is It? (Энгийнээр).** Backup архив санамсаргүйгээр web root-д нийтлэгдсэн.

**C. Why Does It Happen? (Root cause).** Deployment pipeline `.bak`, `.old`, `.zip`, config copies web root-д үлдээсэн.

**D. Where to Look? (Тестийн байрлал).** `/backup.zip`, `.old`, `.bak`, config directories. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Зөвшөөрсөн own local fixture-д **зөвхөн жижиг harmless** `lab-backup.bak` metadata/header шалга; real backups татахгүй.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'HEAD /lab/lab-backup.bak (only own local fixture)'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
HEAD /lab/lab-backup.bak HTTP/1.1
Host: app.lab.test
```

```http
HTTP/1.1 404 Not Found
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Sensitive archive public reachable гэдэг нь owner confirmation/limited evidence-аар батлагдана; contents bulk download хориотой.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Sensitive archive public reachable гэдэг нь owner confirmation/limited evidence-аар батлагдана; contents bulk download хориотой. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** 404 soft page, test fixture intentionally public, HEAD blocked but GET works. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** C High if credentials/source/PII included. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Exclude backups from web roots, secret scanning, restrict storage, deployment artifact policy. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Exposed Backup Files on synthetic lab endpoint`
- **Summary:** Backup/config файл public endpoint-д байх; ажиглагдсан ялгаа нь `Sensitive archive public reachable гэдэг нь owner confirmation/limited evidence-аар батлагдана; contents bulk download хориотой.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `HEAD /lab/lab-backup.bak HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** C High if credentials/source/PII included.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Exclude backups from web roots, secret scanning, restrict storage, deployment artifact policy.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `HEAD /lab/lab-backup.bak HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `HEAD /lab/lab-backup.bak HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 12.6 Information Disclosure — Системийн хэрэгцээгүй private metadata алдагдах

**A. Vulnerability Name.** **Information Disclosure** — Системийн хэрэгцээгүй private metadata алдагдах.

**B. What Is It? (Энгийнээр).** Error, headers эсвэл response-д нууц internal detail ил гарч байна.

**C. Why Does It Happen? (Root cause).** Over-verbose serializers/logs, debug flags, unfiltered responses.

**D. Where to Look? (Тестийн байрлал).** Response body, headers, JS bundles, logs, diagnostics endpoint. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Own in-scope lab app-ийн existing GET response-аас private synthetic marker leakage шалга; further collection хийхгүй.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'Inspect only authorized harmless response; redact any accidental secret'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/status HTTP/1.1
Host: app.lab.test
```

```http
HTTP/1.1 200 OK

{"status":"ok"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Internal credentials/API secret байгаа нь sensitive; mere version/banner informational.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Internal credentials/API secret байгаа нь sensitive; mere version/banner informational. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Public docs/config intentionally released, demo keys, client IDs vs credentials. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** C varies Low–High depending on secret/access. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): Medium.** Нөлөө, шаардлагатай эрх, attacker interaction-аас хамаарч Low–High хооронд хэлбэлзэнэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Data minimization, redaction, secrets manager, audit debug endpoints. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Information Disclosure on synthetic lab endpoint`
- **Summary:** Системийн хэрэгцээгүй private metadata алдагдах; ажиглагдсан ялгаа нь `Internal credentials/API secret байгаа нь sensitive; mere version/banner informational.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/status HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** C varies Low–High depending on secret/access.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Data minimization, redaction, secrets manager, audit debug endpoints.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/status HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/status HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 12.7 Verbose Error Messages — Оношилгооны алдаа хэт дэлгэрэнгүй

**A. Vulnerability Name.** **Verbose Error Messages** — Оношилгооны алдаа хэт дэлгэрэнгүй.

**B. What Is It? (Энгийнээр).** Invalid request response-д SQL query, stack trace хэвлэгдэнэ.

**C. Why Does It Happen? (Root cause).** Raw exception messages exposed to clients.

**D. Where to Look? (Тестийн байрлал).** `400/500` response body, DB error strings, trace IDs. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: One invalid type input with no state change; generic validation response expected.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'page=abc'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/items?page=abc HTTP/1.1
Host: app.lab.test
```

```http
HTTP/1.1 400 Bad Request

{"error":"invalid page","traceId":"LAB-TRACE"}
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Stack trace/file path/query exposure confirmed info-leak; SQL syntax error alone does **not** prove SQLi.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Stack trace/file path/query exposure confirmed info-leak; SQL syntax error alone does **not** prove SQLi. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Trace ID alone safe, server logs private, non-prod debug mode. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** C Low/Medium, credential leaks greater. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): Low.** Нөлөө ихэнхдээ context-dependent; CVSS ихэвчлэн Low/Informational байж болно. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Generic error responses, structured server logs, redaction. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Verbose Error Messages on synthetic lab endpoint`
- **Summary:** Оношилгооны алдаа хэт дэлгэрэнгүй; ажиглагдсан ялгаа нь `Stack trace/file path/query exposure confirmed info-leak; SQL syntax error alone does **not** prove SQLi.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/items?page=abc HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** C Low/Medium, credential leaks greater.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Generic error responses, structured server logs, redaction.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/items?page=abc HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/items?page=abc HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 12.8 Default Configurations / Credentials — Default тохиргоо хэвээр үлдэх

**A. Vulnerability Name.** **Default Configurations / Credentials** — Default тохиргоо хэвээр үлдэх.

**B. What Is It? (Энгийнээр).** Sample account/config production-д үлдэж хэт их эрхтэй байж болно.

**C. Why Does It Happen? (Root cause).** Hardening/deployment defaults not changed, sample endpoints available.

**D. Where to Look? (Тестийн байрлал).** Sample admin UI, install page, debug endpoints, sample config. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Own lab-д default pages/access policy review; **credential guessing эсвэл default password ашиглан real login хийхгүй**.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'Read deployment configuration; do not test credential lists on real systems'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/install-status HTTP/1.1
Host: app.lab.test
```

```http
HTTP/1.1 404 Not Found
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Exposed privileged installer functionality owner-owned fixture-ээр confirm; version banner alone not enough.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Exposed privileged installer functionality owner-owned fixture-ээр confirm; version banner alone not enough. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Intentionally public setup wizard requires authentication, nonproduction environment. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** C/I High if privileged access truly possible. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Disable installers, rotate defaults on deployment, secure baseline scans. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Default Configurations / Credentials on synthetic lab endpoint`
- **Summary:** Default тохиргоо хэвээр үлдэх; ажиглагдсан ялгаа нь `Exposed privileged installer functionality owner-owned fixture-ээр confirm; version banner alone not enough.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/install-status HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** C/I High if privileged access truly possible.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Disable installers, rotate defaults on deployment, secure baseline scans.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/install-status HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/install-status HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 12.9 Sensitive Data in JavaScript — JavaScript bundle дотор sensitive мэдээлэл

**A. Vulnerability Name.** **Sensitive Data in JavaScript** — JavaScript bundle дотор sensitive мэдээлэл.

**B. What Is It? (Энгийнээр).** Frontend `.js` файлд server secret санамсаргүй embed хийгдсэн.

**C. Why Does It Happen? (Root cause).** Build-time environment values client bundle-д орсон, secret classification wrong.

**D. Where to Look? (Тестийн байрлал).** JS bundles, runtime config JSON, `apiKey`, credentials, tokens. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Own app-ийн JS source-д hardcoded marker хай; finding болгохоос өмнө public client ID vs privileged secret-г зөвшөөрөлтэй owner review-аар ялга.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' 'const PUBLIC_CLIENT_ID="demo";' | grep -n 'CLIENT_ID'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
GET /lab/assets/app.js HTTP/1.1
Host: app.lab.test
```

```http
HTTP/1.1 200 OK
Content-Type: application/javascript

const API_BASE="/api";
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Privileged long-lived secret exposed гэдгийг owner verify хийж, secret value-г report-д бүрэн оруулахгүй.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Privileged long-lived secret exposed гэдгийг owner verify хийж, secret value-г report-д бүрэн оруулахгүй. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Public Firebase-style config/client ID, demo token, expired key. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** C/I High if real privileged key, otherwise Informational. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): High.** Precondition хангагдвал serious confidentiality/integrity risk; CVSS тоог AV/AC/PR/UI/S/C/I/A-гаар хэмжинэ. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Never bundle secrets client-side, rotate leaked credentials, secret scanning and least privilege. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Sensitive Data in JavaScript on synthetic lab endpoint`
- **Summary:** JavaScript bundle дотор sensitive мэдээлэл; ажиглагдсан ялгаа нь `Privileged long-lived secret exposed гэдгийг owner verify хийж, secret value-г report-д бүрэн оруулахгүй.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `GET /lab/assets/app.js HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** C/I High if real privileged key, otherwise Informational.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Never bundle secrets client-side, rotate leaked credentials, secret scanning and least privilege.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `GET /lab/assets/app.js HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `GET /lab/assets/app.js HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### 12.10 Exposed Source Maps — Source map-аар эх код харагдах

**A. Vulnerability Name.** **Exposed Source Maps** — Source map-аар эх код харагдах.

**B. What Is It? (Энгийнээр).** Minified JS-ийн source map хэт дэлгэрэнгүй эх код/URL илчилж болох.

**C. Why Does It Happen? (Root cause).** Production build `*.map` publishes sourcesContent or internal references.

**D. Where to Look? (Тестийн байрлал).** `app.js.map`, `sourceMappingURL`, JS asset server. `GET/POST`, request/response body, cookie, session state, `Authorization` header болон account role-ийг аль болох хамт харьцуул; тухайн feature-т хамаарахгүй field-г хүчээр бүү нэм.

**E. Step-by-Step Testing — only authorized lab.**

1. **Prerequisite:** Өөрийн test account, in-scope lab. Сургалтын орчин: **PortSwigger Web Security Academy**. Сургалтын lab-аа нээж энэ vulnerability сэдэвтэй exercise/fixture сонго (доорх `/lab` маршрутууд автоматаар байдаггүй).
2. Baseline: өөрийн test input / account-аар хэвийн request авч status, body, cookie/state, timestamp хадгал.
3. **Нэг** өөрчлөлт хий: Зөвхөн өөрийн lab JS-ийн `sourceMappingURL` болон map availability metadata-г шалга; credentials/PII олборлохгүй.
4. A/B control дахин харьцуулж `status`, `body`, **server-side state**, permission outcome-ийг хар. Impact үзүүлэхэд хангалттай хамгийн бага probe-оор зогс.

**F. Commands & Safe Payloads.**

```bash
printf '%s\n' '//# sourceMappingURL=app.js.map'
```

`printf` нь terminal дээр **зөвхөн test string хэвлэнэ**, target руу request явуулахгүй; `%s\n` = item бүрийг шинэ мөрөнд хэвлэх. Бодит HTTP туршилтыг зөвхөн isolated lab дахь Burp Repeater-аар хийнэ.

**Хүлээгдэх example output:** команд `printf` бол тайлбарласан marker; `curl` бол lab app-ийн HTTP headers/body; `python3` бол decoded JSON. Алдаа: `404` бол illustrative route бодит lab-д байхгүй; `401` бол өөрийн test session хүчингүй; `Connection refused` бол local lab унтарсан. Тестийн marker нь зөвхөн өөрийн fixture/data-д хамаарна.

**G. HTTP Request & Response — synthetic example.**

```http
HEAD /lab/assets/app.js.map HTTP/1.1
Host: app.lab.test
```

```http
HTTP/1.1 404 Not Found
```

> Эдгээр нь **жишээ request/response**; actual lab output өөр байна. Expected status нь дангаараа proof биш, semantic content ба state-ийг хамт шалгана.

**H. Expected vs Vulnerable Behavior.** **Secure:** эрх/validation/policy-г server талд enforce хийж sensitive operation/data-г зохих ёсоор reject/escape хийнэ. **Vulnerable:** Map public байх нь автоматаар vulnerability биш; sensitive logic/secrets actual exposure нотлогдох ёстой.

**I. How to Verify — controlled PoC.** Own test accounts/objects ашиглаж request A (baseline), request B (single controlled change), request C (negative control) гэсэн гуравхан evidence-г гарга. **Баталгаажуулалтын шалгуур:** Map public байх нь автоматаар vulnerability биш; sensitive logic/secrets actual exposure нотлогдох ёстой. Гадны хэрэглэгчийн мэдээлэл болон production state-д хүрэхгүй.

**J. Common False Positives.** Open-source app, normal build tooling, static map intentional for debugging. Status code өөрчлөгдөхөд root cause-ийг баталсан гэж үзэхгүй. Proxy cache/cookie/session state-г нягтал.

**K. Impact, Severity, Preconditions, CVSS.** C Low/Medium unless secrets included. **Нөхцөл:** Өөрийн test account, in-scope lab. **Typical severity (illustrative): Low.** Нөлөө ихэнхдээ context-dependent; CVSS ихэвчлэн Low/Informational байж болно. Confidentiality/Integrity/Availability-ийг тус бүр 'none/low/high' гэж бодит нөхцөлд үнэл; attacker privileges, user interaction, attack complexity-г тусад нь тодорхойл. Bounty program-ийн severity хүснэгт CVSS-ээс давуу байж болно.

**L. Remediation.** **Developer:** Restrict sourcemaps as policy, strip sourcesContent if unnecessary, secret scan bundles. **Security/operations:** negative authorization tests, security regression CI, security logging, code review, configuration hardening, least privilege.

**M. Bug Bounty Report — бөглөх жишиг.**

- **Title:** `Exposed Source Maps on synthetic lab endpoint`
- **Summary:** Source map-аар эх код харагдах; ажиглагдсан ялгаа нь `Map public байх нь автоматаар vulnerability биш; sensitive logic/secrets actual exposure нотлогдох ёстой.` (зөвхөн real evidence нотолсон үед).
- **Affected endpoint:** `HEAD /lab/assets/app.js.map HTTP/1.1` — illustrative; report-д exact in-scope URL бич.
- **Preconditions:** Өөрийн test account, in-scope lab.
- **Steps to reproduce:** (1) Own fixture бэлдэх; (2) valid baseline; (3) дээрх controlled test; (4) negative control; (5) result/state compare.
- **Expected result:** Server policy enforce, unauthorized/unexpected behavior reject.
- **Actual result:** `[ЭНД ӨӨРИЙН БОДИТ LAB АЖИГЛАЛТ, STATUS, MARKER БИЧ]` — synthetic example-ийг confirmed finding гэж илгээхгүй.
- **Impact:** C Low/Medium unless secrets included.
- **Evidence:** redacted request/response, own object ID, timestamp/timezone, expected-vs-actual screenshot, reproducibility, version.
- **Remediation:** Restrict sourcemaps as policy, strip sourcesContent if unnecessary, secret scan bundles.

**N. Quick Reference.**

| Test | Where | Command / Payload | Expected Result | Evidence |
|---|---|---|---|---|
| Baseline | `HEAD /lab/assets/app.js.map HTTP/1.1` | Own valid request | Normal authorized result | status + own marker |
| Negative control | `HEAD /lab/assets/app.js.map HTTP/1.1` | One changed input/session | Reject/sanitize/bound | response + state |
| Confirm | same isolated lab | compare A/B/C | No cross-boundary behavior | 3 redacted captures |

### Chapter 12 — Consolidated review

**Хамгийн чухал:** Confirmed finding бол зөвхөн response string биш, precondition + policy boundary + actual effect + negative control-оор дэмжигдсэн дүгнэлт. `Finding ID`, `confidence (hypothesis/likely/confirmed)`, severity rationale-г нэгтгэ.

<a id="chapter-13"></a>
## Chapter 13 — Burp Suite Practical Guide

Burp Suite нь browser ↔ proxy ↔ server урсгал дахь HTTP request/response-г харж, copy/replay/edit хийхэд тусална. **Community** хувилбарт Proxy, HTTP history, Repeater, Decoder, Comparer, Intruder-ийн зарим боломж бий; **Professional**-д Scanner болон өргөтгөсөн automation/organization features байдаг. UI нэр/цэс version-оос бага зэрэг өөрчлөгдөж болно.

### 13.1 Scope тохируулах — screenshot-гүйгээр яг хийх дараалал

1. Burp ажиллуулаад шинэ temporary project үүсгэ.
2. **Target → Scope** (эсвэл **Settings → Project → Scope**)-оос **Add** → Protocol `http`, Host `127.0.0.1`, Port `3000` гэж зөвшөөрөгдсөн local lab-аа нэм.
3. **Target → Site map** болон **Proxy → HTTP history**-ийн filter-д **Show only in-scope items** сонго.
4. Exclude rules-д logout, delete, payment, upload, external SSO, third-party callback, production-state-changing endpoint оруул; scope rules нь crawler бүх follow-up-г аюулгүй болгоно гэсэн баталгаа биш.
5. **Proxy → Proxy settings → Proxy listeners**-т listener `127.0.0.1:8080` байгаа эсэхийг шалга. Port collision үүсвэл 8081 болго.
6. **Proxy → Intercept → Open Browser**-г сонгож local lab нээ.
7. Intercept `On` болгож хүсэлт нэг удаа бариад **Forward** хий; дараа `Off` болго.

**Алдаа:** HTTP history-д олон гаднын request орвол scope filter зөв үү шалга; browser extensions, analytics third-party outbound request-ийг exclude хийнэ. `127.0.0.1`-д өгсөн scope нь public site руу тест хийх зөвшөөрөл биш.

### 13.2 Proxy / HTTP history

- **Proxy → Intercept**: request-г түр саатуулж, параметр өөрчилж Forward эсвэл Drop хийх.
- **Proxy → HTTP history**: actual browsing request-үүдийг method, host, URL, status, MIME type-ээр эрэмбэлэх; зөвхөн in-scope.
- **Target → Site map**: visited URL, folder, params map — discovery list биш authentication proof.
- **Inspector**: params, cookies, headers-ийг structured хэлбэрээр харах.

**Жишээ:** Own lab profile page нээ → History дахь `GET /api/me` → request/response save → role/cookie-г redact → comparator baseline.

### 13.3 Repeater — гар аргаар баталгаажуулах хамгийн чухал хэрэгсэл

1. History дахь `GET /lab/api/documents/A-OWNED` request сонго → **Send to Repeater** (context menu).
2. Repeater tab-д request-ийг хадгалаад **Send** дар. `200` ба `A_PRIVATE` marker бол baseline.
3. Өөрийн Account B-ийн `B-OWNED` test object ID-гаар **зөвхөн path** өөрчил; `Cookie: A_SESSION` хэвээр байлгана.
4. **Send**. Correct: `403/404` эсвэл authorization-safe response. Vulnerable: A_SESSION B_PRIVATE data уншина.
5. Own B account-аар B object exists/private гэдгийг тусад нь confirm хийнэ; public/shared object биш гэдгийг нягтал.
6. **Comparer**-т хоёр response-ийг шилжүүлэн response differences харна. `Content-Length`, CSRF token, timestamp, telemetry bytes-ийг evidence гэж хэтрүүлэхгүй.

**Repeater settings:** redirects автоматаар follow хийхийг зөвшөөрөгдсөн scope руу л; HTTP/2 ↔ HTTP/1.1 conversion-д raw request semantics өөр байж болно.

### 13.4 Intruder — зөвхөн lab, бага хурдтай

1. Lab request Repeater/History → **Send to Intruder**.
2. **Positions**-д зөвхөн нэг marker (жишээ `id=§A-OWNED§`), бусад params-г clear.
3. Payload list-ээ **2–3 own test IDs**-ээр хязгаарла.
4. Concurrency/rate settings-ийг боломжтой хамгийн бага болго; production brute force, credential guessing бүү хий.
5. Result status/length ялгааг **Repeater**-ээр гар аргаар батал; status diff өөрөө bug биш.

**Community limitation:** Intruder performance болон feature limits байдаг; Pro Scanner-гүйгээр manual testing хийх бүрэн боломжтой. Program-д active scanning explicitly permitted үед л Scanner ашигла.

### 13.5 Decoder / Comparer / Organizer / Match and Replace

- **Decoder**: URL percent encoding, Base64, HTML encode/decode; decode нь signature/decryption биш. Test JWT header/payload-г decode хийхэд sensitive token value-г report-д paste хийхгүй.
- **Comparer**: `Response A` vs `Response B` byte/word diff. Cache, dynamic CSRF token, random request IDs normal differences.
- **Organizer**: Pro/feature availability нь version-оос хамаарна; candidate requests, notes, manual follow-up stage-ийг зохион байгуулахад ашигла.
- **Match and Replace**: Proxy outbound headers/response-г automatic өөрчилж болно; rule active байвал normal browsing хүртэл өөрчлөгдөнө. Зөвхөн local lab, тодорхой rule, test дуусмагц disable.
- **Session handling rules**: login sequence/CSRF/session cookie auto-update. Burp edition болон app flow-оос хамааран боломж өөр; буруу rule бүх comparison-д өөр account token оруулж false positive үүсгэнэ.

### 13.6 Бүрэн manual test жишээ — session / authorization

```http
GET /lab/api/me HTTP/1.1
Host: app.lab.test
Cookie: sid=A_OWN_SESSION
Accept: application/json
```

**Baseline:** `200`, `{"id":"A"}`. **Negative control:** cookie-г авч хаяхад `401`. **Cross-account control:** `A_OWN_SESSION` + B-ийн private object path-д `403/404`. **Evidence:** 3 request, 3 response, role/ownership proof, one screenshot, timestamp; **sensitive cookie-г redact**.

### 13.7 Burp troubleshooting

| Symptom | Шалгах зүйл |
|---|---|
| Browser hangs | Intercept On, Forward хийх эсвэл Off болго |
| `Proxy connection failed` | Listener порт/loopback; Docker 8080 conflict |
| HTTPS warning external browser | Burp CA certificate зөв trust store-д суусан эсэх |
| History хоосон | Burp browser ашигласан эсэх, proxy settings, in-scope filter |
| Repeater `401` | Test session expired, CSRF required, wrong cookie scope |
| OAuth login эвдэрсэн | Third-party host out-of-scope; program auth flow зөвшөөрөл шалга |
| Request хооронд result өөр | Cache, LB, CSRF, timestamp, race, background requests |

Эх сурвалж: [PortSwigger Burp Suite documentation](https://portswigger.net/burp/documentation/desktop), [Proxy Intercept](https://portswigger.net/burp/documentation/desktop/tools/proxy/intercept-messages), [Target Scope](https://portswigger.net/burp/documentation/desktop/settings/key-settings).

<a id="chapter-14"></a>
## Chapter 14 — Bug Bounty Methodology (15-step Workflow)

Доорх 15 алхам нь бүрэн authorized workflow. Хүснэгтийн command дахь `lab.test` нь **зөвшөөрөгдсөн owner-controlled lab placeholder**; DNS дээр бодит домэйн биш байж болно. Нотолгоо цуглуулахын өмнө scope permit баримтжуулсан байна.

| # | Алхам / Goal | Tools, safe command | Юуг ажиглах / Expected output | Common mistake |
|---|---|---|---|---|
| 1 | **Review program scope** — дүрэм, target-аа тогтоох | Program page + `00_scope/authorization.md` | hostname/API/method/automation permission | wildcard-г автоматаар хамруулах |
| 2 | **Inventory authorized assets** | CSV/Sheets: approved-only list | asset, owner, proof, exclusions | archive-д олдсон URL-г шууд test хийх |
| 3 | **Passive reconnaissance** | `subfinder -d lab.test -silent` | candidate host list | discovery=authorization гэж үзэх |
| 4 | **Identify technologies** | `curl -sS -I --max-time 10 http://127.0.0.1:3000/` | headers, reverse-proxy banner | header-оос CVE батлах |
| 5 | **Map application functionality** | Browser DevTools Network / Burp History | endpoint/feature map | payment/delete flow-г crawl хийх |
| 6 | **Identify user roles** | Own A/B viewer/admin, tenant matrix | role→allowed actions table | role shared membership анзаарахгүй |
| 7 | **Enumerate permitted endpoints** | `katana -u http://127.0.0.1:3000 -d 2 -rl 2 -c 1 -silent` | small URL list | cross-host redirect/follow |
| 8 | **Test authentication** | Burp Repeater baseline/negative test | valid 200, no-token 401 where protected | 200 alone sufficient гэж үзэх |
| 9 | **Test authorization** | Own A token + B own object ID (GET only) | correct 403/404 or safe response | public/shared object test |
| 10 | **Test input validation** | Non-destructive marker / lab | encoded vs raw output | 500 = SQLi гэж үзэх |
| 11 | **Test API security** | REST/GraphQL own data | object/property/function policy | GraphQL 200+errors-г ignore |
| 12 | **Test business logic** | Isolated zero-value fixture | state transition/price server-side | production purchase хийх |
| 13 | **Validate findings safely** | Repeater A/B/C & manual compare | reproduce, negative control, actual state | cache/dynamic UI effect |
| 14 | **Collect evidence** | `02_requests/`, screenshots | timestamp, redacted traffic | token/password илгээх |
| 15 | **Write reports** | Chapter 15 template | title, steps, impact, remediation | only screenshots with no repro |

### Алхам бүрийн minimum acceptance criteria

1. **Authorization proof:** scope document URL, date, included/excluded hosts, test boundaries хадгалсан.
2. **Inventory:** бүх host-д `in_scope = yes/no/unknown`, unknown host active test-д орохгүй.
3. **Passive recon:** discovered list file ба source timestamp; discovered-only host-г allowed list-т автомат copy хийхгүй.
4. **Fingerprint:** HTTP status, server header, app identifier; version banner-г finding болгохгүй.
5. **Map features:** action→HTTP method→endpoint→role→side effect тэмдэглэ.
6. **Role matrix:** Anonymous/A/B/Viewer/Admin/Tenant T1/T2 хүснэгт, shared data ялгагдсан.
7. **Enumeration:** candidate route бүрийг in-scope, owned, non-destructive гэж ангилсан; ffuf/katana low rate.
8. **Authentication:** valid login, invalid own login, own logout, session age, MFA state.
9. **Authorization:** private object owner proof, A-to-B negative test, secure expected result.
10. **Input validation:** input context HTML/SQL/OS/template/LDAP аль нь болох, false positive analysis.
11. **API:** schema property allowlist, query complexity, route inventory, object-level policy.
12. **Business logic:** expected workflow specification, synthetic test, final persistent state.
13. **Validation:** repeated **бага хэмжээтэй** test дээр result repeatable, cache/time/token effect ruled out.
14. **Evidence:** request/response exact, relevant sensitive fields masked, timestamps timezone.
15. **Report:** actionable root cause + minimal evidence + severity rationale, no live exploit escalation.

### Field notes template

```markdown
Finding ID: FIND-001
Status: Hypothesis | Likely | Confirmed | Not reproducible
In-scope asset: [authorized host]
Role/account: A viewer; B viewer (both owned)
Endpoint/method: GET /api/items/{id}
Baseline: A cookie + A object -> 200 (A marker)
Negative control: A cookie + B object -> 403 expected
Observed: [record actual result; do not assume 200 is an issue]
False positive checks: public/shared? cache? previous cookies?
Impact (C/I/A): [evidence-backed]
Evidence: [redacted captures, screenshot, timestamp]
Remediation: per-object server authorization
```

<a id="chapter-15"></a>
## Chapter 15 — Reporting

### 15.1 Professional vulnerability report template

```markdown
# [Severity] [Vulnerability] in [In-scope Feature]
**Status:** Hypothesis | Confirmed (only if evidence supports)
**Affected asset / endpoint:** https://<IN_SCOPE_HOST>/path (method)
**Date & timezone:** YYYY-MM-DD HH:MM +08:00
**Researcher / test account:** redacted test account ID

## Summary
[One paragraph: boundary, missing check, observed effect]

## Preconditions
[Own accounts / roles / test data; no real third-party data]

## Steps to reproduce
1. Create owned test fixtures A/B.
2. Capture control request with expected result.
3. Modify ONLY [one parameter/header/session] in Repeater.
4. Record result, response body, and actual server-side state.
5. Verify negative control and rule out cache/shared/public data.

## Expected result
[401/403/404 or safely encoded/validated outcome]

## Actual result
[Exact status and REDACTED own synthetic marker; screenshot]

## Security impact
Confidentiality: [None/Low/High + why]
Integrity: [None/Low/High + why]
Availability: [None/Low/High + why]
Prerequisites / user interaction: [details]
Severity / CVSS rationale: [why; not assumed]

## Evidence
- Request/Response A (redacted)
- Request/Response B (redacted)
- Timestamp, reproducibility, own object ownership proof

## Remediation
[Backend fix; regression tests; operational controls]
```

### 15.2 Six completed-style **illustrative** reports (not real findings)

**Эдгээр report нь reporting technique-ийн жишээ; `/lab/` endpoint бодит target-т байх албагүй.**

#### Report 1 — IDOR / BOLA

- **Title:** `[High] Insecure Direct Object Reference in GET /lab/api/documents/{id}`
- **Summary:** Account A-аас Account B-ийн private synthetic document marker уншигдах hypothetical authorization failure.
- **Affected endpoint:** `GET /lab/api/documents/B-OWNED-002`; **Preconditions:** A/B хоёр өөрийн test accounts, B-д `B_PRIVATE_TEST` object.
- **Steps:** (1) B private object үүсгэнэ. (2) A token-аар own A object GET → 200. (3) A token-ийг хадгалж path ID-ийг B ID болгоно. (4) response/state compare.
- **Expected:** 403/404; **Actual (hypothetical vulnerable):** 200 + B_PRIVATE_TEST marker; **Impact:** C High; **Evidence:** redacted A/B request/response and owner proof.
- **Remediation:** Resource owner/tenant scoped query on every endpoint.

#### Report 2 — Reflected XSS

- **Title:** `[Medium] Reflected XSS in search parameter on local lab`
- **Summary:** `q` output encoding missing; JavaScript execution only in own lab browser.
- **Affected endpoint:** `GET /lab/search?q=...`; **Preconditions:** Own local intentionally vulnerable test page.
- **Steps:** plain marker → HTML marker → `alert(1)` isolated execution and Console observation → control escaped response.
- **Expected:** `&lt;script&gt;...`; **Actual (hypothetical):** own browser `alert(1)` executed. **Impact:** Browser origin JS context; real victims never targeted.
- **Evidence:** escaped vs executed page screenshot, raw response, lab URL. **Remediation:** contextual output encoding, safe templating, CSP defense-in-depth.

#### Report 3 — SQL Injection

- **Title:** `[High] Boolean-based SQL injection in local product filter`
- **Summary:** Dynamic SQL query input changes result semantics beyond intended filter.
- **Affected endpoint:** `GET /lab/products?id=...`; **Preconditions:** Seeded synthetic local product DB.
- **Steps:** baseline `id=1` → boolean true `id=1 AND 1=1` → false `id=1 AND 1=2` → control literal text; compare stable results.
- **Expected:** strict numeric validation/parameter binding. **Actual (hypothetical):** true returns seeded row, false none; code review confirms unsafe concatenation.
- **Impact:** Potential C/I if same flaw reachable against protected data; **do not dump database**. **Evidence:** three redacted responses + relevant safe code excerpt. **Remediation:** prepared statements and allowlisted identifiers.

#### Report 4 — SSRF

- **Title:** `[High] SSRF via preview URL in isolated network`
- **Summary:** Server accepts user-supplied URL to own test listener instead of enforcing destination policy.
- **Affected endpoint:** `POST /lab/fetch-preview`; **Preconditions:** Isolated app + owned callback service in same private test network.
- **Steps:** submit harmless `http://127.0.0.1:9001/ping` fixture → confirm exact inbound request in owned listener → control disallowed address.
- **Expected:** 400 private host rejected; **Actual (hypothetical):** owned listener sees request from app context. **Impact:** Internal access could be possible, **not tested**. **Evidence:** one server log entry/time and redacted request. **Remediation:** URL allowlist, DNS/IP validation, egress controls.

#### Report 5 — Broken Access Control / BFLA

- **Title:** `[High] Read-only admin summary exposed to viewer role`
- **Summary:** Viewer token can access synthetic admin-only summary.
- **Affected endpoint:** `GET /lab/admin/audit-summary`; **Preconditions:** Own Viewer/Admin lab roles.
- **Steps:** Admin control 200 → Viewer 403 expected → viewer response actual compare; no admin mutation.
- **Expected:** 403 viewer; **Actual (hypothetical):** 200 + ADMIN_MARKER. **Impact:** C High if real protected summary. **Evidence:** ownership/role table plus two responses. **Remediation:** deny-by-default function-level authorization.

#### Report 6 — Business Logic / Coupon reuse

- **Title:** `[High] Duplicate single-use coupon redemption on isolated zero-value cart`
- **Summary:** Server applies single-use coupon twice to one synthetic test cart.
- **Affected endpoint:** `POST /lab/cart/coupon`; **Preconditions:** Own local zero-value cart/coupon, no real financial records.
- **Steps:** server marks coupon used → send second application once → read local ledger and total with own test admin fixtures.
- **Expected:** 409/already used, no additional discount. **Actual (hypothetical):** two persisted redemptions. **Impact:** Integrity/financial potential, not quantified from one lab. **Evidence:** two redacted requests + ledger state. **Remediation:** atomic one-time constraint, idempotency, server calculation.

### 15.3 Triage-ийн сайн/муу нотолгоо

| Сайн нотолгоо | Сул нотолгоо |
|---|---|
| Own role A/B private object comparison | “200 OK — hacked” |
| Parser/DOM execution proven in lab | Input reflected in HTML only |
| SQL true/false plus code/DB semantics | Error `syntax error near` only |
| SSRF request in owned listener | URL echoed in UI |
| Duplicate **ledger records** | Two successful-looking HTTP statuses |
| Redacted request/response + timestamp | Screenshot only with no reproducible steps |

**Disclosure etiquette:** Report-д live token, credentials, unrelated account data, production exploitation script, credential dump, personal details бүү хавсарга. Owner-т secure channel-аар private details-г зөвшөөрсөн хэлбэрээр өг.

<a id="chapter-16"></a>
## Chapter 16 — Quick Command Reference (with explanations)

**Энд `lab.test` илэрхийлсэн зөвшөөрөгдсөн нэр; working sample болгон ашиглах бол domain/DNS-ээ өөрийнхөөрөө бэлтгэ.** `127.0.0.1:3000` local Juice Shop, харин `/lab/*` paths нь synthetic fixture гэж үзнэ. CLI суулгасан хувилбар бүрт `tool -h` шалгах нь зөв.

### 16.1 DNS / Subdomains

| Command | Purpose / flags | Sample output; how to interpret | Error / limitation |
|---|---|---|---|
| `dig A lab.test +short` | A record, `+short` богино output | `192.0.2.10` = resolved documentation IP | DNS resolution ≠ scope approval |
| `dig TXT lab.test +short` | TXT records | `"v=spf1 ..."` = mail policy metadata | Mail record ≠ mail server attack permission |
| `subfinder -d lab.test -silent` | `-d` domain, `-silent` results | `api.lab.test` = candidate | third-party/passive dataset stale |
| `amass enum -passive -d lab.test -o passive.txt` | passive enum, output file | file-д subdomain names | Active mode өөр permission |
| `dnsx -l approved-hosts.txt -a -resp -silent` | approved list A lookup, response | `api.lab.test [A] ...` | wildcard DNS/CT duplicate |

### 16.2 HTTP / Headers / Parameters

| Command | Purpose / flags | Sample output; interpretation | Limitation |
|---|---|---|---|
| `curl -sS -I --max-time 10 http://127.0.0.1:3000/` | HEAD headers, timeout | `HTTP/1.1 200 OK` | HEAD may differ from GET |
| `curl -sS -i --max-time 10 http://127.0.0.1:3000/` | body + headers | response HTML | not vulnerability by itself |
| `curl -sS -i -H 'Origin: http://127.0.0.1:9001' http://127.0.0.1:3000/` | test CORS response header | `Access-Control-Allow-Origin: ...` | curl can't enforce browser CORS |
| `curl -sS --max-time 10 'http://127.0.0.1:3000/robots.txt'` | read robots policy | `Disallow: /admin` | not access-control proof |
| `curl -sS --max-time 10 'http://127.0.0.1:3000/sitemap.xml'` | sitemap | `<loc>...</loc>` | discovery only |
| `printf '%s\n' '{"id":7}' | jq -r '.id'` | parse JSON field | `7` | invalid JSON parse error |
| `python3 -c 'from urllib.parse import quote; print(quote("a b"))'` | URL encode | `a%20b` | encoding ≠ filtering |

### 16.3 Tool-based URL discovery — tightly limited

| Command | What/flags | Expected output | Guardrails |
|---|---|---|---|
| `httpx -l approved-hosts.txt -sc -title -rl 2 -silent` | HTTP probe, status, title, 2 req/s | `[200] [Lab Portal]` | only approved hosts |
| `gau lab.test --o urls.txt` | archive providers to file | `/api/v1/...` URLs | archive ≠ active scope |
| `printf '%s\n' lab.test | waybackurls` | stdin → Wayback URLs | historical endpoints | may be removed/live out-of-scope |
| `katana -u http://127.0.0.1:3000 -d 2 -rl 2 -c 1 -silent` | crawl depth2, 2rps, concurrency1 | path list | excludes/logout/payment manually |
| `ffuf -w tiny-lab-words.txt -u http://127.0.0.1:3000/FUZZ -rate 1 -t 1 -maxtime 15` | small lab fuzz | `[Status: 200,...]` | auto scan elsewhere not allowed |

### 16.4 JavaScript / Local files

| Command | Purpose | Output | Limitation |
|---|---|---|---|
| `grep -En 'fetch\(|/api/|sourceMappingURL' demo.js` | Regex matches with line numbers | `1:const ...` | hidden source != secret |
| `head -n 20 demo.js` | First 20 local lines | JS preview | don't print sensitive secrets to shared logs |
| `sha256sum redacted-request.http` | Evidence integrity hash | 64-char SHA-256 | hash does not prove origin |

### 16.5 Authentication / JWT inspection

```bash
# Local/offline: token value is synthetic, not a live access token.
python3 - <<'PY'
import base64, json
header = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'
padded = header + '=' * (-len(header) % 4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(padded)), indent=2))
PY
```

**Output:**

```json
{"alg": "HS256", "typ": "JWT"}
```

`python3 - <<'PY'` = shell here-doc inline Python; `urlsafe_b64decode` = Base64URL decode; `json.loads` = JSON parse; `indent=2` = формат. **Decode хийх ≠ signature verify хийх**. Verification-д signature, trusted key, issuer/audience/expiry зэрэг шаардлагатай.

### 16.6 API / Burp Suite

| Task | Command / Action | Expected output | Warning |
|---|---|---|---|
| API JSON | `curl -sS ... | jq .` | formatted JSON | HTML алдаа `jq parse error` үүсгэнэ |
| POST JSON local | `curl -sS -i -X POST -H 'Content-Type: application/json' --data '{"test":"LAB"}' http://127.0.0.1:3000/` | route-specific status | `/` POST endpoint биш байж болно |
| Burp proxy | `curl -i --proxy http://127.0.0.1:8080 http://127.0.0.1:3000/` | HTTP history hit | port listener check |
| Repeater | HTTP history → Send to Repeater → Send | own request replay | one controlled variable |
| Comparer | Repeater response → Send to Comparer | byte/word diff | dynamic token noise |
| Decoder | paste synthetic text → Base64 Decode | readable text | not cryptographic validation |

### 16.7 Universal flags and troubleshooting

`-sS` (curl): progress нуух, error хэвлэх; `-i`: response headers; `-I`: HEAD; `-H`: header; `-X`: method; `--data`: body; `--data-urlencode`: form encoding; `--max-time`: секунд. `-rl` (httpx, katana): rate limit; `-rate` (ffuf): request/s; `-c` (katana), `-t` (ffuf): concurrency; `-d` (katana) crawl depth, `-d` (subfinder) domain. `-h` / `--help`-ээр installed version шалга.

`command not found` → tool/PATH; `Connection refused` → local app/listener down; `401` → own session invalid; `403` → expected policy/WAF; `429` → immediately slow/stop; `500` → security finding дангаараа биш.

<a id="chapter-17"></a>
## Chapter 17 — Testing Checklist

### Scope, ethics, recon

- [ ] Written authorization, exact in-scope assets, excluded paths/hosts recorded.
- [ ] Testing time/rate/automation policy, impact stop conditions checked.
- [ ] Own lab users A/B, roles Viewer/Admin, own T1/T2 synthetic tenants prepared.
- [ ] Candidate DNS/CT names are not treated as active-scope automatically.
- [ ] CT, robots.txt, sitemap.xml, passive archive URLs checked with scope filter.
- [ ] JavaScript bundles, source maps, endpoint inventory, technology fingerprint documented.
- [ ] No third-party SSO/CDN/payment URL actively scanned.

### Authentication and sessions

- [ ] Login controls (valid/invalid own credentials) compared.
- [ ] Password reset token short-lived, account-bound and single-use.
- [ ] Registration verification gate enforced backend.
- [ ] MFA pending session cannot access protected own profile.
- [ ] Session fixation, rotation and logout revocation checked.
- [ ] Remember-me token revocation and expiry checked.
- [ ] Cookie flags Secure, HttpOnly, SameSite, Path, Domain reviewed.
- [ ] JWT signature, issuer, audience, expiry, algorithm policy checked.
- [ ] OAuth2 redirect_uri, state, PKCE; OIDC issuer, nonce validated.
- [ ] Account enumeration false positives reviewed without username harvesting.

### Authorization, API

- [ ] Anonymous vs authenticated route tested.
- [ ] Own A session vs own B private object ID (IDOR/BOLA) tested read-only.
- [ ] Same-role horizontal and viewer/admin vertical checks.
- [ ] Tenant T1/T2 shared-data semantics clarified.
- [ ] BFLA/admin function permission and object-level checks.
- [ ] Mass assignment, sensitive property exposure, field-level auth.
- [ ] REST API authorization and deprecated version inventory.
- [ ] GraphQL root and field resolver authorization (200+errors parsed).
- [ ] API rate/pagination assessed with single bounded query, no stress.
- [ ] External API provider response/webhook integrity verified in mock.

### Input/browser

- [ ] SQLi safe boolean TRUE/FALSE tests only local/Academy lab.
- [ ] NoSQL structured operator vs string schema validation.
- [ ] Command injection only benign local marker on isolated host.
- [ ] SSTI arithmetic marker vs client render distinguished.
- [ ] LDAP/XPath metacharacter handling with own lab content.
- [ ] CRLF/header reflection vs real header splitting.
- [ ] Reflected, stored, DOM-based XSS actual execution proof in own lab only.
- [ ] HTML injection not mislabeled as XSS without execution.
- [ ] CSP limitations/unsafe sinks evaluated contextually.

### Server-side and business logic

- [ ] SSRF only owned callback, no private cloud metadata/system probing.
- [ ] Path traversal and LFI only own outside-marker fixture.
- [ ] RFI only owned harmless remote text fixture in isolated lab.
- [ ] XXE internal entity alone not counted as external entity finding.
- [ ] Unsafe deserialization inspected without gadget execution.
- [ ] File upload harmless test `.txt`, storage/permissions reviewed.
- [ ] Open redirects observed without following unknown domains.
- [ ] HTTP Request Smuggling tested only dedicated isolated lab.
- [ ] Race test capped two requests, only synthetic fixture.
- [ ] Coupon single use, checkout state, price, workflow checked in mock.
- [ ] Duplicate transactions verified via mock ledger, zero real value.
- [ ] Maker-checker and approval role constraints checked.

### Security misconfig and reporting

- [ ] CSP, HSTS, nosniff, Cache-Control assessed by context.
- [ ] CORS credentials with browser-mediated own data proof.
- [ ] Debug, stack traces, backup files and listing reviewed without data dump.
- [ ] Default config reviewed but no credential guessing.
- [ ] JavaScript sensitive keys distinguished from public IDs.
- [ ] Confirmed vs suspected findings separated.
- [ ] Baseline, single change, negative control and server-side state captured.
- [ ] False positives: cache, public/shared object, stale session, UI-only behavior ruled out.
- [ ] Severity/CVSS evaluated with C/I/A, privileges, user interaction, complexity.
- [ ] Report contains title/summary/endpoint/prereqs/steps/expected/actual/impact/evidence/fix.
- [ ] Token, password and PII redacted; submitted via authorized disclosure channel.

### OWASP Top 10:2025 coverage

| Official category | Main chapters |
|---|---|
| A01 Broken Access Control | 6, 10, 11 |
| A02 Security Misconfiguration | 12 |
| A03 Software Supply Chain Failures | 2, 3, 12; additionally dependency review |
| A04 Cryptographic Failures | 4, 5; additionally cryptographic design review |
| A05 Injection | 7, 8 |
| A06 Insecure Design | 11 |
| A07 Authentication Failures | 5 |
| A08 Software or Data Integrity Failures | 9, 10, 11 |
| A09 Security Logging and Alerting Failures | 1, 13, 14; additionally detection/response review |
| A10 Mishandling of Exceptional Conditions | 4, 12 |

**Gap:** Supply chain, cryptography, alerting, exceptional-condition design may need source, configuration and owner review. Absence of scanner alerts is not a pass.

<a id="chapter-18"></a>
## Chapter 18 — Practice Labs & Learning Path

### Lab comparison

| Lab | Skill focus | Safe setup / reference |
|---|---|---|
| [PortSwigger Web Security Academy](https://portswigger.net/web-security/) | XSS, SQLi, Access Control, OAuth, JWT, SSRF, GraphQL, race, request smuggling guided isolated labs | Website lab instances; follow official instructions |
| [OWASP Juice Shop](https://help.owasp-juice.shop/part1/running.html) | Modern SPA, REST, auth, XSS, shopping logic | `docker run --rm -p 127.0.0.1:3000:3000 bkimminich/juice-shop` |
| [OWASP WebGoat](https://owasp.org/www-project-webgoat/) | OWASP vulnerability lessons and WebWolf helper | `docker run --rm -p 127.0.0.1:8080:8080 -p 127.0.0.1:9090:9090 webgoat/webgoat` |
| [DVWA](https://github.com/digininja/DVWA) | Classic SQLi/XSS/upload/CSRF/command injection, security levels | Follow current official Docker instructions; localhost bind |
| [OWASP crAPI](https://github.com/OWASP/crAPI/blob/develop/docs/setup.md) | API BOLA/BFLA/auth/business logic | Official Docker Compose setup in isolated VM; restrict exposed ports |

### 6-week practical roadmap

| Week | Topics | Practical task | Completion evidence |
|---|---|---|---|
| 1 | HTTP, headers, cookies, DevTools, Burp | Capture 10 own GET/POST lab requests | Explain method, status, headers |
| 2 | Auth/session/MFA/JWT/OAuth | Own account controls | Login/logout test matrix |
| 3 | IDOR/BOLA/BFLA/tenants | Own A/B objects in crAPI/Academy | Redacted 3-request evidence |
| 4 | SQLi/XSS/injection | Academy/DVWA local challenges | False-positive checks documented |
| 5 | SSRF/traversal/GraphQL/API | Owned fixture, no external targets | API permission matrix |
| 6 | Business logic and reporting | Local zero-value mock checkout | Six synthetic-to-lab reports |

### Lab operations

```bash
docker ps --format 'table {{.Names}}	{{.Ports}}	{{.Status}}'
curl -sS -I --max-time 10 http://127.0.0.1:3000/
```

`docker ps` shows running containers; `--format` controls columns; curl `-I` HEAD, `--max-time 10` seconds. `Connection refused` means service/port unavailable, not a vulnerability. Run intentionally vulnerable systems only on localhost or a secured isolated VM, not the public Internet.

---

## References — official sources

1. [OWASP WSTG v4.2 stable](https://wstg.owasp.org/stable/) and [WSTG project](https://owasp.org/projects/web-security-testing-guide).
2. [OWASP Top 10:2025](https://top10.owasp.org/2025/).
3. [OWASP API Security Top 10:2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/).
4. [PortSwigger Web Security Academy](https://portswigger.net/web-security/) and [Burp documentation](https://portswigger.net/burp/documentation/desktop).
5. [ProjectDiscovery documentation](https://docs.projectdiscovery.io/) and [katana repository](https://github.com/projectdiscovery/katana).
6. [ffuf](https://github.com/ffuf/ffuf), [gau](https://github.com/lc/gau), [waybackurls](https://github.com/tomnomnom/waybackurls).
7. [Juice Shop official runner](https://help.owasp-juice.shop/part1/running.html), [WebGoat official](https://owasp.org/www-project-webgoat/), [crAPI setup](https://github.com/OWASP/crAPI/blob/develop/docs/setup.md).

**Reminder:** Tool flags and lab versions can change. Confirm installed `-h` output and current program rules before any active testing. All `/lab` HTTP fixtures are illustrative and not guaranteed endpoints of the named training applications.

