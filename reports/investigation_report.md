# Phishing Investigation Report

| | |
|---|---|
| **Case ID** | PHISH-2026-001 |
| **Analyst** | Vijayalaxmi Kummari |
| **Date analysed** | 3 October 2026 |
| **Evidence** | `samples/invoice_overdue.eml` (SHA-256 `8ba6d9a78e393ee1d924389fb17ae8f17e251f6256723d1df0392b5d2a74ad74`) |
| **Verdict** | **MALICIOUS - credential phishing** |
| **Severity** | High |
| **Confidence** | High |

> This is a lab exercise. The email is a training sample written for this project. All domains use the reserved `.example` ending and all IP addresses come from documentation ranges, so no real organisation is involved.

## 1. Summary

A user at company.example received an email that claimed to come from IT Support. It said an invoice was overdue and the account would be suspended within 24 hours unless the user signed in to "verify" their password.

The email is a phishing attempt. It was sent from a lookalike domain, failed every email authentication check, sends replies to an unrelated domain, and contains a link whose visible text hides the real destination. An attached HTML file is disguised as a PDF. The aim is to steal the user's login details.

## 2. How the email was reported

The recipient (alex.morgan@company.example) forwarded the message to the security mailbox as an attachment because the sender address looked unusual. The original `.eml` file was saved so the headers stayed intact.

## 3. Analysis

### 3.1 Sender identity

| Header | Value | Observation |
|---|---|---|
| From | "IT Support" &lt;it@c0mpany-help[.]example&gt; | Display name looks official. The domain uses a zero in place of the letter o and adds "-help". The real domain is company.example. |
| Reply-To | pay@mail-drop[.]example | Any reply goes to a different domain from the sender. |
| Return-Path | bounce@mail-drop[.]example | Bounces also go to mail-drop[.]example. This is the domain that actually sent the email. |
| X-Mailer | PHPMailer 5.2.9 | A scripting library often used for bulk sending. Not what a corporate IT team would use. |
| Message-ID | ends in `@WIN-7K2PQ1` | A default Windows computer name rather than a mail server domain. |

### 3.2 Authentication

| Check | Result | Meaning |
|---|---|---|
| SPF | fail | The sending IP (198[.]51[.]100[.]77) is not authorised to send for the envelope domain. |
| DKIM | none | The message carries no digital signature. |
| DMARC | fail | Neither SPF nor DKIM backs up the From address. |

All three checks failed. A genuine internal IT email would pass them.

### 3.3 Delivery path

Read from the first hop to the last:

| Hop | From | IP | Received by | Time (UTC) |
|---|---|---|---|---|
| 1 | WIN-7K2PQ1 | 203[.]0[.]113[.]45 | relay7[.]mail-drop[.]example | 08:14:02 |
| 2 | relay7[.]mail-drop[.]example | 198[.]51[.]100[.]77 | mx[.]company[.]example | 08:14:07 |
| 3 | mx[.]company[.]example | 192[.]0[.]2[.]25 | inbox[.]company[.]example | 08:14:09 |

The message started on a machine named WIN-7K2PQ1 at 203[.]0[.]113[.]45 and was relayed through mail-drop[.]example. It never touched company.example's own outbound mail servers. Hop 3 is the organisation's own internal delivery and is not an indicator.

### 3.4 Message content

- **Subject:** "URGENT: Invoice overdue - account will be suspended today"
- **Greeting:** "Dear user" - the sender does not know the recipient's name.
- **Pressure:** a 24-hour deadline, a threat of suspension, "act now", "do not ignore".
- **Request:** sign in and verify a password. IT teams do not ask for this by email.
- **Mixed story:** an "overdue invoice" from IT Support that needs a password makes no business sense.

### 3.5 Links

| Text the user sees | Where it really goes |
|---|---|
| hxxps://portal[.]company[.]example/billing | hxxps://login-portal[.]example/verify?id=8841&user=alex[.]morgan |

The link text shows the real company portal, but the underlying address is on a different domain. The URL also carries the recipient's username, which lets the attacker pre-fill the fake login page and track who clicked.

The link was not opened during this investigation.

### 3.6 Attachment

| File name | Type | Size | SHA-256 |
|---|---|---|---|
| Invoice_8841.pdf.html | text/html | 96 bytes | `49644c131e7273bb7fa7d950b16155b1a3270c891e18f9b0ad4959d850402ded` |

The name ends in `.pdf.html`. On systems that hide known extensions it would show as "Invoice_8841.pdf", but it opens in a browser. HTML attachments are commonly used to show a fake login form. The file was hashed without being opened.

## 4. Indicators of compromise

| Type | Indicator |
|---|---|
| Domain | c0mpany-help[.]example |
| Domain | mail-drop[.]example |
| Domain | login-portal[.]example |
| URL | hxxps://login-portal[.]example/verify?id=8841&user=alex[.]morgan |
| IP | 203[.]0[.]113[.]45 (origin) |
| IP | 198[.]51[.]100[.]77 (sending relay) |
| Email | it@c0mpany-help[.]example |
| Email | pay@mail-drop[.]example |
| Email | bounce@mail-drop[.]example |
| SHA-256 | 49644c131e7273bb7fa7d950b16155b1a3270c891e18f9b0ad4959d850402ded |
| Subject | URGENT: Invoice overdue - account will be suspended today |

## 5. MITRE ATT&CK

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Phishing: Spearphishing Link | T1566.002 |
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 |
| Defense Evasion | Impersonation | T1656 |
| Defense Evasion | Masquerading: Double File Extension | T1036.007 |
| Execution | User Execution: Malicious Link / Malicious File | T1204.001 / T1204.002 |

## 6. Recommended actions

**Contain**
1. Block the three domains and the URL at the email gateway and web proxy.
2. Block the two external IP addresses at the email gateway.
3. Search all mailboxes for the same sender, subject or attachment hash and remove every copy.

**Check for impact**
4. Search proxy and DNS logs for any connection to login-portal[.]example.
5. Ask the recipient whether they clicked the link or opened the attachment.
6. If anyone did, reset their password, end their active sessions, and review their sign-in history for unfamiliar locations.

**Prevent**
7. Move the company.example DMARC policy to `p=reject` so mail that fails authentication is refused. This email arrived with `action=none`, which means it was delivered despite failing.
8. Add a mail rule that flags or quarantines HTML attachments from external senders.
9. Thank the reporting user and share a short awareness note showing this email's red flags.

## 7. Example detection (Splunk)

A search to find other recipients of the same campaign. Field names depend on the email log source, so they would need adjusting.

```spl
index=email (sender_domain="c0mpany-help.example" OR reply_to_domain="mail-drop.example"
  OR subject="URGENT: Invoice overdue*" OR attachment_name="*.pdf.html")
| stats count values(subject) as subject by recipient, sender, src_ip
```

## 8. Conclusion

The email is a credential phishing attempt that impersonates internal IT Support. The verdict rests on several independent pieces of evidence that agree with each other: a lookalike domain, failed SPF, DKIM and DMARC, mismatched reply addresses, a hidden link target and a disguised attachment. The indicators above should be blocked and the mail environment searched for further copies.
