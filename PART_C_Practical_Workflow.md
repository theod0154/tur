# PART C — Authorized Web Pentesting Practical Workflow

**15 алхамтай ажиллагааны checklist + evidence + gate-based workflow.**  
**Хэл:** Монгол + English technical terms; **Шинэчилсэн:** 2026-11-20.  
Дэлгэрэнгүй: [PART A — Handbook](./PART_A_Detailed_Handbook.md). Товч команд: [PART B — Quick Cheat Sheet](./PART_B_Quick_Cheat_Sheet.md).

> **Бүх workflow зөвхөн бичгээр зөвшөөрсөн in-scope target, owner-controlled local lab, эсвэл intentionally vulnerable course lab-д хүчинтэй.** Passive discovery хийсэн host нь active-test scope биш. Аливаа үйлдэл production records, financial transactions, гуравдагч этгээдийн мэдээлэл, SLA/availability-д нөлөөлөх бол зогсоо. Brute-force, credential stuffing, data dumping, persistence, evasion, service stress, internal metadata access, массов fuzzing хийхгүй.

## 0. Engagement cover sheet — тест эхлэхээс өмнө бөглөнө

```yaml
engagement_id: WEB-LAB-2026-001
program_name: "[Authorized program / own lab]"
authorization_reference: "[policy URL, contract, signed approval]"
owner_contact: "[security contact]"
start_end_date_timezone: "YYYY-MM-DD to YYYY-MM-DD, UTC+08:00"
in_scope_hosts:
  - "app.lab.test  # owned placeholder: replace with exact approved host"
  - "api.lab.test  # only when separately in scope"
out_of_scope:
  - "third-party SSO, payment, CDN unless explicitly listed"
  - "production delete, real purchase, email/SMS bulk, account guessing"
allowed_methods:
  - "manual browsing, Repeater, low-rate inventory only if authorized"
max_request_rate: "Policy value; otherwise manual only"
accounts: "Owned A, B, Viewer, Admin, T1/T2 (all synthetic)"
stop_conditions:
  - "429 rate limit or unusual 5xx/latency"
  - "other person's data or a real secret appears"
  - "unintended state change or financial consequence"
evidence_storage: "Encrypted local folder; redaction and retention policy"
report_channel: "[official private disclosure portal]"
```

**GO / NO-GO gate:** Scope эсвэл consent тодорхойгүй нэг ч hostname дээр active test эхлэхгүй. `example.com` documentation domain-г `in_scope` гэж ашиглахгүй. `lab.test` нь бодит DNS дээр заавал resolve болохгүй; command-ыг approved domain/local loopback болгон өөрчил.

## 1. Fifteen-step operational checklist

### Step 1 — Review program scope (Rules of Engagement)

- [ ] Approved URLs, wildcard terms, API paths, IP ranges, hosting boundaries-ийг яг тэмдэглэ.
- [ ] “Out-of-scope” болон third-party authentication/payment/CDN хэсгүүдийг тусад нь ялга.
- [ ] Allowed active methods, automated scanners, max requests/s, time window, disclosures шалга.
- [ ] Contact болон аваргын stop/escalation procedure тогтоож бич.

**Tool:** policy document, `authorization.md`. **Output:** signed/dated scope matrix. **Common error:** `*.example` гэж хараад бүх third-party CNAME-г шалгах. **Gate:** written authorization present.

### Step 2 — Inventory authorized assets

- [ ] `approved-hosts.txt`-д **зөвхөн** policy-оор зөвшөөрсөн FQDN (Fully Qualified Domain Name)-ийг бич.
- [ ] API/method/protocol scope-ийг hostname-оос тусад нь тэмдэглэ.
- [ ] Candidate/discovered hosts-ийг `unknown` гэж тэмдэглэж active-tool input-д оруулахгүй.

```text
asset,approved,source,notes
app.lab.test,yes,program-policy,main application
api.lab.test,yes,program-policy,authorized v1 API
cdn.vendor.test,no,link-from-app,third-party
```

**Output:** CSV, separate `approved-hosts.txt`. **Gate:** target list checked manually. **Common error:** CT/GitHub/Wayback-д олдсон нэр бүхэлдээ in-scope гэж үзэх.

### Step 3 — Passive reconnaissance

- [ ] Certificate Transparency (CT), public archive, passive subdomain sources-оос candidates аваарай.
- [ ] `subfinder -d OWN_DOMAIN -silent`, `amass enum -passive -d OWN_DOMAIN -o passive.txt` — зөвхөн эзэмшигчийн зөвшөөрсөн domain.
- [ ] `gau OWN_DOMAIN --o archive.txt` / `printf '%s\n' OWN_DOMAIN | waybackurls` historical URLs авахад хэрэглэ.
- [ ] Archive URL-д sensitive query/token харагдвал report evidence-ээс нууцал, request руу оруулахгүй.

**Output:** `candidate-subdomains.txt`, `archive.txt` plus collected timestamps. **Expected:** host/URL candidates. **Mistake:** passive result → live vulnerability гэж үзэх. **Gate:** each candidate manually scoped.

### Step 4 — Identify application technologies

- [ ] One HTTP `HEAD`/`GET` request from approved local app; headers, `Content-Type`, `Server`, cache, cookies хар.
- [ ] Browser DevTools Network/Sources-аас app framework ба API interactions ажигла.
- [ ] Version banner, framework hint нь CVE эсвэл exploit proof биш.

```bash
curl -sS -I --max-time 10 http://127.0.0.1:3000/
```

**Flag:** `-sS` quiet+errors; `-I` HEAD; `--max-time 10` timeout. **Output:** HTTP status + headers. **Common error:** HTTP banner-аар vulnerability confirmed болгох.

### Step 5 — Map application functionality

- [ ] Own account-аар normal browsing, login/logout, profile, search, form, read-only APIs map хий.
- [ ] DevTools Network → Fetch/XHR filter; Burp Proxy → HTTP history; method, path, parameters/response type тэмдэглэ.
- [ ] Features-д side effect: read-only / reversible / irreversible, public / private / admin гэж ангил.
- [ ] Upload/payment/send-mail/delete маршрутуудад automatic crawling бүү хий.

**Output:** `endpoint-inventory.csv` (method, path, role, auth requirement, side effect, owner). **Gate:** risky routes excluded.

### Step 6 — Identify user roles

- [ ] Anonymous, User A, User B, Viewer, Admin, Tenant T1, Tenant T2 гэсэн **өөрийн** fixtures бэлтгэ.
- [ ] A/B private/shared objects болон tenant-specific test marker-ууд тусад нь оруул.
- [ ] Role/permission matrix бэлтгэж, shared access vs private access тодорхойл.

| Role | Own profile | Other own test account's private doc | Admin preview |
|---|---|---|---|
| Anonymous | No | No | No |
| User A | Yes | No (B private) | No |
| User B | Yes | No (A private) | No |
| Admin (own lab) | Per documented policy | Per documented policy | Yes |

**Output:** role permission matrix. **Gate:** A/B test ownership proof available.

### Step 7 — Enumerate permitted endpoints (bounded)

- [ ] Only explicitly permitted read-only local lab routes active crawl хийнэ.
- [ ] Depth=2, concurrency=1, low rate=2 req/s эсвэл program-specific lower bound тохируул.
- [ ] Detect scope redirects, SSO providers, destructive paths, 429/5xx → immediately stop.

```bash
katana -u http://127.0.0.1:3000 -d 2 -rl 2 -c 1 -silent
printf '%s\n' api health robots.txt > tiny-lab-words.txt
ffuf -w tiny-lab-words.txt -u http://127.0.0.1:3000/FUZZ -rate 1 -t 1 -maxtime 15
```

**Flags:** `katana -u` starting URL, `-d` depth, `-rl` request/s, `-c` concurrency; `ffuf -w` wordlist, `FUZZ` slot, `-rate` request/s, `-t` threads, `-maxtime` max seconds. **Output:** paths/status. **Mistake:** every `200` is accessible sensitive endpoint.

### Step 8 — Test authentication

- [ ] Own valid vs invalid login once, compare server session state (`/me`), not UI banner.
- [ ] Login, logout, reset token, MFA, remember-me, cookie flags tested safely.
- [ ] JWT decode **offline**, signature/issuer/audience/expiry verify conceptually or local fixture.
- [ ] OAuth/OIDC callback, state, PKCE, nonce in mock flow; third-party IdP probing excluded.

**Output:** auth flow state diagram and 2–3 controlled captures per issue. **Expected:** server enforces authenticated state. **Mistake:** no-token test still has old cookie or MFA remembered device.

### Step 9 — Test authorization (A/B and role)

- [ ] Account A's own object GET baseline.
- [ ] Account B's **own, synthetic, private** object ID obtained using B account.
- [ ] A token + B private object ID GET once, other fields identical.
- [ ] Public/shared status, tenant membership, cache/session checked.
- [ ] Viewer vs admin **read-only preview** and GraphQL fields (if in scope).

```http
GET /lab/api/documents/B-OWNED HTTP/1.1
Host: app.lab.test
Cookie: sid=OWN_ACCOUNT_A_SESSION
```

**Expected:** 403/404 (or masking behavior) for B private object. **Possible finding:** A session receives B private synthetic marker. **Never** switch to real user IDs. **Output:** 3-request matrix, ownership evidence.

### Step 10 — Test input validation (lab-only)

- [ ] Test context = SQL query / HTML / JS / template / shell / XML / LDAP / header гэж тодорхойл.
- [ ] Start benign marker (`LAB_MARKER`) → one changed encoded/contextual input.
- [ ] SQLi TRUE/FALSE pair; HTML `<b>` vs XSS actual execution; SSTI `{{7*7}}` only isolated lab.
- [ ] Command injection, XXE external entity, file include, HTTP smuggling — only dedicated isolated lab.
- [ ] Error `500`, reflected text, unverified CORS header-ийг confirmed findings гэж үзэхгүй.

**Output:** input→server handling→response/actual execution evidence. **Gate:** no destructive payload or unintended state.

### Step 11 — Test API security

- [ ] REST BOLA, BFLA, property-level access, mass assignment from own fixtures.
- [ ] GraphQL `data` + `errors` body; root permission and field resolver checks.
- [ ] JWT/API key scopes, API version mismatch, exposed OpenAPI inventory (if approved).
- [ ] One bounded pagination `limit` out-of-range request; no load tests.
- [ ] Mock third-party webhook verify signature/status state; never real vendor callback.

**Output:** API control matrix and negative permissions evidence. **Common error:** GraphQL HTTP 200 treated as success without inspecting `errors`.

### Step 12 — Test business logic (synthetic only)

- [ ] Local zero-value cart, test coupon, test order, mock payment provider ready.
- [ ] Server-calculated price/quantity/discount independent of client fields.
- [ ] One-time coupon, duplicate request, idempotency, workflow stage, self-approval constrained.
- [ ] Final persistent state/ledger verified; HTTP 200 alone not proof.

**Output:** state diagram (`DRAFT → REVIEW → APPROVED`), mock ledger count, test-only order ID. **Prohibited:** real payments, actual refunds, order fulfillment, email/SMS flooding.

### Step 13 — Validate findings safely

- [ ] `Hypothesis`, `Likely`, `Confirmed`, `Not reproducible` status tracked.
- [ ] Baseline A, controlled change B, negative control C. Change **one variable** per test.
- [ ] Verify actual object owner, role, permission, backend state or browser execution.
- [ ] Cache, redirects, cookie expiry, public/shared resource, false result from UI, timing jitter ruled out.
- [ ] Once minimal reproducible evidence exists, stop further exploitation.

**Output:** concise PoC + evidence of cause-effect. **Mistake:** proof based on response code/text alone.

### Step 14 — Collect redacted evidence

- [ ] Exact method, path, query, relevant body; timestamp with timezone.
- [ ] `Authorization` Bearer, `Cookie`, `Set-Cookie`, emails, tokens, PII fully/partially redacted as policy.
- [ ] Screenshot of expected/actual in own lab, no unrelated user data.
- [ ] Context: account A/B, object ownership, roles, URL, response server state.
- [ ] Evidence file permission/retention/encrypted storage policy.

**Output:** `03_evidence/FIND-001` with sanitized `baseline.http`, `negative.http`, `result.http`, `evidence.png`, `notes.md`. **Mistake:** screenshot without reproducible HTTP steps.

### Step 15 — Write and submit vulnerability report

- [ ] Title: `[Severity] [Name] in [Feature / Endpoint]`.
- [ ] Summary: boundary violated, method and real observed result.
- [ ] Affected in-scope URL / method / required role.
- [ ] Preconditions, exact reproduction, expected vs actual.
- [ ] Evidence and false positives ruled out.
- [ ] Impact: C/I/A + preconditions + CVSS consideration.
- [ ] Remediation for developer + regression test.
- [ ] Send privately through program's authorized disclosure channel; duplicates policy review.

**Output:** complete report; confirmation status based on evidence, not assumptions.

## 2. Finding tracker template

| ID | Vulnerability | Asset / Endpoint | Role | Evidence | Confidence | Severity | Status |
|---|---|---|---|---|---|---|---|
| FIND-001 | IDOR/BOLA | `GET /lab/api/documents/{id}` | A vs B own | `FIND-001/redacted` | Hypothesis | TBD | Review |
| FIND-002 | CORS | `GET /lab/private` | own session | `FIND-002/redacted` | Not confirmed | TBD | Need browser proof |
| FIND-003 | HTML Injection | `GET /lab/preview` | own user | `FIND-003/redacted` | Likely | Low | Review |

**Confidence:** `Hypothesis` (not validated) → `Likely` (strong indicator) → `Confirmed` (repeatable actual impact) → `Not reproducible`/`Resolved`. `TBD` гэдэг нь severity-г proof-гүй оноогоогүй гэсэн үг.

## 3. Evidence capture sample: IDOR/BOLA lab

**Prerequisites:** two owned test accounts (A/B); B has private document `B-OWNED`; both objects explicitly private and not shared.

```http
# Request A — baseline, own A object
GET /lab/api/documents/A-OWNED HTTP/1.1
Host: app.lab.test
Cookie: sid=<REDACTED_ACCOUNT_A_SESSION>
```

```http
# Request B — single controlled change, B-owned object
GET /lab/api/documents/B-OWNED HTTP/1.1
Host: app.lab.test
Cookie: sid=<REDACTED_ACCOUNT_A_SESSION>
```

**Expected B response:**

```http
HTTP/1.1 403 Forbidden
Content-Type: application/json

{"error":"forbidden"}
```

**Vulnerable-only hypothetical response:**

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"id":"B-OWNED","marker":"B_PRIVATE_TEST"}
```

**Control C:** Account B-аас B object exists бөгөөд private гэдгийг баталгаажуул; A/B shared permission, old A cookie, cached response, user roles-ийг нягтал. **Only after** B marker appeared under A auth and false positives eliminated, escalate as *confirmed* finding. `/lab` is synthetic, not a promised lab endpoint.

## 4. Risk and stopping checklist

| Trigger | Action | Why |
|---|---|---|
| Scope uncertain / out-of-scope redirect | **STOP**; obtain approval | prevents unauthorized traffic |
| `429`, rising errors/latency | **STOP** active probing | protects availability |
| Real user data unexpectedly appears | **STOP**, do not browse more; redact and report | prevents privacy harm |
| Real payment/inventory state change | **STOP**, notify owner | avoids production integrity impact |
| Cloud metadata/internal address suspected | no further probing | SSRF exposure without exploitation |
| Scanner proposes brute force or destructive check | decline | exceeds safe testing |
| Confirmation achieved with own marker | stop and report | minimum necessary PoC |

## 5. Daily session checklist (print/use repeatedly)

### Before testing

- [ ] Exact scope and permission are current.
- [ ] Low rate, small wordlist, no disruptive payload.
- [ ] Owned A/B lab accounts and fixture IDs ready.
- [ ] Burp browser/Proxy scoped correctly.
- [ ] Evidence folder and redaction available.

### During testing

- [ ] Map normal workflow first.
- [ ] Request baseline captured.
- [ ] Only one variable changed at a time.
- [ ] Negative controls applied.
- [ ] Unrecognized third-party host excluded.
- [ ] New unexpected data/errors trigger stop.

### After testing

- [ ] Every finding confidence checked.
- [ ] No credentials or PII left in notes.
- [ ] Evidence indexed and backed up securely.
- [ ] Report includes expected/actual/impact/fix.
- [ ] Manual lab session stopped, proxy settings reset.
- [ ] Authorized disclosure and follow-up logged.

## 6. Copy-paste report handoff

```markdown
# [High/Medium/Low] [Finding Name] — [In-scope Endpoint]
Date/time (+08:00):
Confidence: Hypothesis / Likely / Confirmed
Affected asset / method:
Preconditions / account roles:
Summary / violated trust boundary:
Steps to reproduce:
  1. [Own test fixture]
  2. [Baseline HTTP request]
  3. [Single controlled change]
  4. [Negative control and actual state]
Expected result:
Actual result (redacted):
Evidence files / timestamps:
False positives ruled out:
Impact / C-I-A / preconditions / severity rationale:
Remediation / backend fix / regression test:
Disclosure channel / tracker ID:
```

## 7. Sources and cross-reference

- [OWASP WSTG v4.2](https://wstg.owasp.org/stable/)
- [OWASP Top 10:2025](https://top10.owasp.org/2025/)
- [OWASP API Security Top 10:2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security/)
- [Part A full handbook](./PART_A_Detailed_Handbook.md) · [Part B quick commands](./PART_B_Quick_Cheat_Sheet.md)

**Зорилго нь exploit хийх бус, зөвшөөрөгдсөн хүрээнд эрсдэлийг найдвартай, минимал нөлөөгөөр тогтоож засварын баримт гаргах явдал юм.**
