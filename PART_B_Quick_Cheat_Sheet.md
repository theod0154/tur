# PART B — Bug Bounty & Web Pentesting Quick Cheat Sheet

**Хэл:** Монгол + English technical terms / commands / HTTP. **Огноо:** 2026-11-20. **Зориулалт:** authorized in-scope web tests, PortSwigger labs, owner-controlled `localhost` fixtures. Дэлгэрэнгүй тайлбар [PART A](./PART_A_Detailed_Handbook.md), checklist [PART C](./PART_C_Practical_Workflow.md).

> ⚠️ **Scope first:** `lab.test` бол user-owned hypothetical domain, `example.com` бол documentation URL бөгөөд active scanning permission биш. Бодит URL орлуулахдаа program policy-г шалга. `127.0.0.1:3000` нь local Juice Shop жишээ; `/lab/*` route-ууд нь **synthetic fixture**, Juice Shop-ийн actual route гэж ойлгож болохгүй. Scanner-ууд default өндөр хурдтай байж болно — rate limit тавь. Production data/credentials, account takeover, external callback, service disruption, data exfiltration хийхгүй.

## 1. One-page mental model

| Асуулт | Шалгах зүйл | Proof criteria |
|---|---|---|
| “Хэн бэ?” | Authentication/session/JWT/OAuth | Server-side auth state, not UI label |
| “Юу хийж болох вэ?” | Authorization/BOLA/BFLA | Own A token cannot read B private marker |
| “Input яаж тайлбарлагдав?” | SQLi/XSS/NoSQL/SSTI | Safe semantic difference/execution in isolated lab |
| “Сервер хаашаа хүрэв?” | SSRF/XXE/file handling | Owned local fixture/log evidence only |
| “Бизнес дүрэм хадгалагдав уу?” | Coupon/price/workflow | Synthetic persistent state/ledger check |
| “Тохиргооны эрсдэл үү?” | CORS/CSP/headers/debug | Actual private data boundary; no claim from missing header alone |
| “Finding батлагдсан уу?” | A/B controls + false positives | Baseline + single change + negative control |

**Severity rule:** Low/Medium/High/Critical нь **нөхцөлт жишиг**; CVSS (Common Vulnerability Scoring System) болон program-specific severity-ийг risk scenario, Confidentiality/Integrity/Availability, privileges, user interaction, exploit complexity-аар тогтооно.

## 2. Environment essentials

| Action | Command / UI | Expected output / troubleshooting |
|---|---|---|
| Verify tools | `curl --version; jq --version; python3 --version` | installed versions, not `command not found` |
| Start Juice Shop | `docker run --rm --name juice-lab -p 127.0.0.1:3000:3000 bkimminich/juice-shop` | open `http://127.0.0.1:3000/` |
| Start WebGoat | `docker run --rm -p 127.0.0.1:8080:8080 -p 127.0.0.1:9090:9090 webgoat/webgoat` | `/WebGoat` at 8080, `/WebWolf` at 9090 |
| Check containers | `docker ps --format 'table {{.Names}}\t{{.Ports}}'` | inspect localhost-only port mapping |
| Burp browser | Proxy → Intercept → **Open Browser** | proxy/CA ready by default |
| Burp scope | Target → Scope; include `127.0.0.1:3000` | history filters to in-scope |
| Repeater | History → right click → Send to Repeater → Send | one request replay; don't modify multiple variables |
| Proxy curl | `curl -i --proxy http://127.0.0.1:8080 http://127.0.0.1:3000/` | Burp History hit; listener conflict 8080? |

**Important flags:** `docker --rm` container auto-remove; `-p hostIP:hostPort:containerPort` port publish. `curl -i` response headers+body; `--proxy` routes via Burp. If 8080 collides with WebGoat, use different listener or port.

## 3. DNS, passive recon, and active discovery

| Tool | Command (owned or explicitly authorized targets only) | Flag/goal | Expected output, interpretation |
|---|---|---|---|
| `dig` | `dig A app.lab.test +short` | `A` address, `+short` condensed | IP, but resolve ≠ authorized |
| `dig` | `dig CNAME app.lab.test +short` | alias records | CNAME target may be third party |
| `subfinder` | `subfinder -d lab.test -silent` | passive subdomains | candidates, **filter against scope** |
| `amass` | `amass enum -passive -d lab.test -o names.txt` | passive mode and output | discovered names, not test list |
| `dnsx` | `dnsx -l approved-hosts.txt -a -resp -silent` | A resolution of approved list | domain + DNS address |
| `httpx`¹ | `httpx -l approved-hosts.txt -sc -title -td -rl 2 -silent` | HTTP status, title, tech, <=2 req/s | `[200] [title] [tech]` |
| `gau` | `gau lab.test --o archives.txt` | public URL archive to file | historical URLs, scope filtering needed |
| `waybackurls` | `printf '%s\n' lab.test \| waybackurls` | Wayback URLs via stdin | old endpoints, not proof live |
| `katana` | `katana -u http://127.0.0.1:3000 -d 2 -rl 2 -c 1 -silent` | crawl depth 2, 2rps, concurrency1 | small lab URL list |
| `ffuf` | `ffuf -w tiny.txt -u http://127.0.0.1:3000/FUZZ -rate 1 -t 1 -maxtime 15 -mc 200,301,403` | tiny wordlist, max1rps, 1 thread, 15s | response candidates, status diff ≠ vuln |

¹ `httpx` = **ProjectDiscovery HTTP probe**, Python `httpx` library-аас өөр.

**`ffuf` fixture wordlist:**

```bash
printf '%s\n' api health robots.txt > tiny.txt
```

`printf` local text хэвлэнэ, `> tiny.txt` файлд хадгална. `-w` wordlist; `FUZZ` word replacement; `-rate` rate/sec; `-t` worker count; `-maxtime` секунд; `-mc` matching codes. `429/5xx` өсвөл зогсоо.

## 4. HTTP / status / headers

| Test | Location | Safe command | Expected / evidence |
|---|---|---|---|
| Headers | Response | `curl -sS -I --max-time 10 http://127.0.0.1:3000/` | headers; `-I` HEAD differs from GET sometimes |
| Request+response | HTTP | `curl -sS -i --max-time 10 http://127.0.0.1:3000/` | status + headers + body |
| CORS | `Origin` | `curl -sS -i -H 'Origin: http://127.0.0.1:9001' http://127.0.0.1:3000/` | ACAO/ACAC headers; curl doesn't enforce browser CORS |
| Robots | `/robots.txt` | `curl -sS --max-time 10 http://127.0.0.1:3000/robots.txt` | `Disallow` is NOT authorization |
| Sitemap | `/sitemap.xml` | `curl -sS --max-time 10 http://127.0.0.1:3000/sitemap.xml` | URL discovery only |
| JSON | Response JSON | `printf '%s\n' '{"id":7}' \| jq -r '.id'` | `7`; `jq` requires valid JSON |
| URL encode | local | `python3 -c 'from urllib.parse import quote; print(quote("a b"))'` | `a%20b` |

**HTTP statuses:** `200` success ≠ auth proven; `201` created; `204` no body; `301/302` redirect; `400/422` invalid input; `401` unauthenticated; `403` forbidden; `404` absent or masked; `409` conflict; `429` slow/stop; `500` error ≠ injection confirmed.

| Header | Check | Secure meaning / nuance |
|---|---|---|
| `Set-Cookie` | `Secure`, `HttpOnly`, `SameSite`, `Path`, `Domain` | policy appropriate to cookie flow |
| `Authorization` | `Bearer OWN_TEST_TOKEN` | per-request auth and expiry; redact evidence |
| `Access-Control-Allow-Origin` | restricted origin | only paired with credentials + actual browser read can be high-impact |
| `Content-Security-Policy` | `script-src` policy | defense-in-depth; missing CSP alone not XSS |
| `Cache-Control` | `no-store` on private data | caching decisions require context |
| `Content-Type` | JSON/HTML/XML actual type | output context matters |
| `X-Content-Type-Options` | `nosniff` | MIME sniff protection |
| `Strict-Transport-Security` | HTTPS only | localhost HTTP absence expected |

## 5. Authentication / authorization quick tests

| Vulnerability | Where | Safe test (owned accounts only) | Secure expected | Strong evidence |
|---|---|---|---|---|
| Login weakness | `/login` and `/me` | own valid vs invalid password once | invalid cannot access `/me` | authenticated state not UI banner |
| Password reset | reset token | own token used once, then validation-only | used token invalid | server reuse confirmed in lab |
| MFA bypass | own pending session | pre-MFA `/me` read | `401/mfa_required` | private marker accessible before MFA |
| Session fixation | `Set-Cookie` | compare pre/post-login own ID | regenerated as designed | exploitable fixation precondition |
| Logout invalidation | `/logout`, `/me` | replay own token after logout | `401` or designed short-lived policy | authenticated data after revoke |
| JWT validation | own JWT | decode offline; invalid-signature token local lab | `401` | acceptance despite invalid signature |
| OAuth/OIDC | callback and token claims | own mock provider/state/nonce | callback/claims validated | invalid audience/state accepted |
| Account enumeration | login/reset | one registered+one unregistered synthetic email | generic public response | stable meaningful differential |
| IDOR/BOLA | `/api/items/{id}` | A session + B-owned synthetic private ID | `403/404` | B_PRIVATE marker in A response |
| Horizontal escalation | user settings | same-role A vs B private item | deny B item | own role+ownership proof |
| Vertical/BFLA | admin read-only preview | viewer token to protected preview | `403` | admin-only marker for viewer |
| Mass assignment | profile JSON | harmless extra `labExtra` field | ignored/rejected | protected server-managed field actually changed **in lab** |
| Tenant isolation | tenant T1/T2 object | T1 token + own T2 private ID | `403/404` | synthetic T2 private marker returned |

**JWT offline header inspection:**

```bash
python3 -c 'import base64,json;x="eyJhbGciOiJIUzI1NiJ9";print(json.loads(base64.urlsafe_b64decode(x+"="*(-len(x)%4))))'
# {'alg': 'HS256'}
```

`python3 -c` runs offline snippet; Base64URL decode reveals claims but **does not verify signature**. Do not paste live tokens to public decoder sites.

## 6. Injection / XSS — isolated lab payload reference

| Vulnerability | Entry point | Small safe payload / marker | What confirms / not confirms |
|---|---|---|---|
| SQLi | `?id=` in seeded local DB | `1 AND 1=1` vs `1 AND 1=2` | stable semantic difference + query context; error alone no |
| NoSQLi | JSON string field | `{"sku":{"$eq":"LAB-001"}}` | server unexpectedly treats operator as query; schema may allow it |
| Command injection | local diagnostics fixture only | `127.0.0.1; printf LAB_CMD_OK` | owned fixture stdout marker from shell, not echo |
| SSTI | template preview | `{{7*7}}` | server-side `49` with correct template context, not client math |
| LDAPi | local LDAP fixture search | `lab-user*` | unintended filter semantics, not intentional wildcard search |
| XPathi | local XML search | `LAB_ITEM'` | safe parser/query behavior, not generic validation error |
| CRLF | redirect/header input | `%0D%0AX-Lab-Marker%3A%201` | **separate response header** appears |
| Reflected XSS | query string | `<b>LAB</b>` then `<script>alert(1)</script>` *lab only* | JavaScript executes in own browser; HTML marker alone not XSS |
| Stored XSS | own lab comment | `<b>LAB_STORED</b>` | persisted unsafe render + lab script execution, no real users |
| DOM XSS | URL `#fragment` | `#<b>DOM_TEST</b>` | source→unsafe sink DOM execution; fragment not sent over HTTP |
| HTML injection | rendering area | `<b>LAB_HTML_OK</b>` | inserted HTML but no script = HTML injection only |

**Interpretation rule:** Browser `<b>` rendering does not prove XSS; SQL exception does not prove data access; HTTP status mismatch does not prove injection. Use controls and expected-vulnerable comparison.

## 7. Server-side / API / business logic

| Test | Where | Safe lab-only input | Expected | Evidence / false positive |
|---|---|---|---|---|
| SSRF | URL fetcher | `http://127.0.0.1:9001/ping` to own listener | reject private targets | own listener request; note container localhost differs |
| Path traversal | `file` path | `../outside-marker.txt` own fixture | reject outside base | actual own marker, not echo |
| LFI | template selector | `../lab-marker.txt` own fixture | allowlisted templates only | included file content (local lab) |
| RFI | remote template | own localhost harmless `.txt` | remote include denied | server include vs browser fetch distinguished |
| XXE | XML parser | `<!DOCTYPE r [<!ENTITY lab "LAB_OK">]><r>&lab;</r>` | block DTD as policy | internal entity expansion **not sufficient** to prove XXE |
| Insecure deserialization | local import | benign JSON settings changes | schema/type enforcement | native unsafe class behavior, not Base64 blob |
| File upload | multipart | local `lab-upload.txt` | safe storage/type enforcement | accepted text alone not finding |
| Open redirect | `next=` | `http://127.0.0.1:9001/landing` | redirect to relative/allowlisted path only | `Location` offsite; don't use `curl -L` |
| HTTP Request Smuggling | proxy chain | **conceptual + dedicated isolated lab only** | consistent request parsing | dedicated lab's boundary logs; no production desync |
| Race condition | `/redeem` | two zero-value own requests max | one effect; second conflict/idempotent | final database ledger count |
| GraphQL BOPLA | nested `internalNotes` | shallow own A/B field query | field null/forbidden | inspect `data` and `errors`, not HTTP 200 alone |
| API quota | `?limit=` | one `limit=9999` lab request | reject/clamp to max | 200 response alone isn't rate-limit proof |
| Coupon | `/coupon` | own `LAB_COUPON_ONCE` twice in mock | second blocked | persisted discount count, not status only |
| Price | `/quote` | `clientTotal: 0` own mock | server recomputes | authoritative serverTotal unchanged |
| Approval | `/approve` | own synthetic maker object | self-approval denied | saved workflow state |
| Duplicate transaction | mock `/transactions` | one `Idempotency-Key` twice | one ledger record | backend records, zero real value |

## 8. Misconfiguration reference

| Observation | Is it confirmed? | Further safe check | Fix |
|---|---|---|---|
| `CSP` absent | No XSS proof | unsafe sink and controlled execution | context encoding, CSP |
| `HSTS` absent HTTP localhost | Usually not relevant | production HTTPS policy | enable HSTS on HTTPS |
| `ACAO: *` | Not always a flaw | private data, credential usage, real browser read | exact allowlist |
| `Debug: true` | Context-dependent | one harmless invalid field | disable production debug |
| `Index of /` | Public listing alone may be allowed | assess file sensitivity; no bulk fetch | turn off sensitive directory indexing |
| `*.bak` URL | Hypothesis | owner confirms sensitivity; do not download archive | remove backup from web root |
| JS `apiKey` | Not always a secret | public client ID vs privileged credential | secret scanning, rotate if exposed |
| `app.js.map` exists | Not necessarily a finding | actual secret/source data risk | restrict source maps as policy |

## 9. Reporting mini-template

```markdown
Title: [Severity] [Vulnerability] in [Feature]
Status: Hypothesis / Confirmed
Affected in-scope endpoint: METHOD https://<host>/path
Preconditions: Own A/B lab accounts, synthetic objects
Steps: 1) Baseline 2) One controlled change 3) Negative control
Expected: [policy/validation blocks it]
Actual: [exact redacted response + confirmed state]
Impact: C/I/A, role, user interaction, exploit complexity
Evidence: redacted request/response, own marker, timestamp/timezone
False positives ruled out: cache/shared/public object/stale session
Remediation: backend authorization/validation, regression test
```

**Result classification:** `Hypothesis` → `Likely` → `Confirmed` only when permission boundary, owned data and actual behavior have been validated. Stop at the minimum demonstration.

## 10. Five essential links

- [OWASP WSTG](https://wstg.owasp.org/stable/)
- [OWASP Top 10:2025](https://top10.owasp.org/2025/)
- [OWASP API Top 10:2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security/)
- [Burp Suite documentation](https://portswigger.net/burp/documentation/desktop)

*All command examples and example outputs are illustrative. For full prerequisite, risk, false positives, verification and reporting, use PART A.*
