# PortSwigger Bug Bounty — Study Workflow

**Түвшин:** Beginner  
**Хугацаа:** 8 долоо хоног · 7 хоногт 6 өдөр · өдөрт 90 минут  
**Зорилго:** Vulnerability-г ойлгох → lab дээр бие дааж олох → нотлох → report бичих.

## Өдөр тутмын хуваарь (90 мин)

| Хугацаа | Хийх ажил |
|---|---|
| 10 мин | Өмнөх тэмдэглэл, алдаагаа давтах |
| 15 мин | Тухайн vulnerability-ийн theory унших |
| 45 мин | Burp Suite ашиглан lab ажиллах |
| 15 мин | Root cause, payload, evidence, fix-ийг тэмдэглэх |
| 5 мин | Ахиц бүртгэж маргаашийн lab сонгох |

## 8 долоо хоногийн roadmap

| 7 хоног | Сэдэв |
|---|---|
| 1 | HTTP basics, Burp Proxy/Repeater, request/response |
| 2 | Path Traversal, Access Control |
| 3 | Authentication, Session Management |
| 4 | SQL Injection |
| 5 | XSS (Reflected, Stored, DOM) |
| 6 | CSRF, File Upload |
| 7 | SSRF, OS Command Injection |
| 8 | Давтлага, сонгосон Practitioner lab, bug bounty report |

**Дараалал:** Эхлээд **Apprentice**, ойлгосны дараа **Practitioner**. Долоо хоног бүр 1 өдрийг давтлага, тэмдэглэл цэгцлэхэд зориул.

## Lab хийх 6 алхам

1. **Read:** Зорилго, vulnerability-ийн нөхцөлийг унш.
2. **Explore:** App-ын урсгал, параметр, cookie, request-үүдийг ажигла.
3. **Hypothesize:** Аль оролт/логик эмзэг байж болохыг таамагла.
4. **Test:** Burp Repeater дээр нэг нэг өөрчлөлт хийж, response харьцуул.
5. **Verify:** Үр дүнг давтаж баталгаажуул; screenshot/request хадгал.
6. **Document:** Яагаад үүссэн, хэрхэн олсон, нөлөө, засварыг 5–10 мөрөөр бич.

**Гацвал:** 15 мин бие даа → 10 мин theory → 10 мин hint → шаардлагатай бол solution үзээд хааж, өөрөө дахин хий. Маргааш нь hint-гүй давт.

## Lab тэмдэглэлийн загвар

```md
### [Lab нэр]
- Сэдэв / түвшин:
- Огноо / хугацаа:
- Эмзэг цэг (endpoint/parameter):
- Hypothesis:
- Test & evidence:
- Root cause:
- Impact:
- Remediation:
- Шийдсэн эсэх: Independent / Hint / Solution
- Дараа давтах огноо:
```

## Долоо хоногийн шалгуур

- [ ] 5–7 lab оролдсон (тоо бус, ойлголт чухал)
- [ ] 2 lab-ийг hint-гүй дахин хийсэн
- [ ] 1 mini bug report бичсэн
- [ ] Алдаа, сурсан зүйлээ нэгтгэсэн

**Дүрэм:** PortSwigger lab болон зөвшөөрөгдсөн bug bounty scope дотор л тест хий.

**Эх сурвалж:** [PortSwigger Web Security Academy](https://portswigger.net/web-security) · [Server-side Apprentice Path](https://portswigger.net/web-security/learning-paths/server-side-vulnerabilities-apprentice)
