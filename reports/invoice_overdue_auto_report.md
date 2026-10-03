# Phishing Triage Report (auto-generated)

**Verdict: MALICIOUS**  |  Risk score: 100/100

## Email details

| Field | Value |
|---|---|
| File | `samples/invoice_overdue.eml` |
| Subject | URGENT: Invoice overdue - account will be suspended today |
| From | IT Support &lt;it@c0mpany-help[.]example&gt; |
| Reply-To | pay@mail-drop[.]example |
| Return-Path | bounce@mail-drop[.]example |
| To | alex.morgan@company.example |
| Date | Mon, 28 Sep 2026 08:14:02 +0000 |
| Sent with | PHPMailer 5.2.9 |
| Email SHA-256 | `8ba6d9a78e393ee1d924389fb17ae8f17e251f6256723d1df0392b5d2a74ad74` |

## Authentication

| Check | Result |
|---|---|
| SPF | fail |
| DKIM | none |
| DMARC | fail |

## Delivery path (first hop at the top)

| Hop | From | IP | Received by |
|---|---|---|---|
| 1 | WIN-7K2PQ1 | 203[.]0[.]113[.]45 | relay7[.]mail-drop[.]example |
| 2 | relay7[.]mail-drop[.]example | 198[.]51[.]100[.]77 | mx[.]company[.]example |
| 3 | mx[.]company[.]example | 192[.]0[.]2[.]25 | inbox[.]company[.]example |

## Findings

| Points | Finding |
|---|---|
| +20 | Sender domain c0mpany-help.example imitates company.example but is not the same domain. |
| +20 | SPF result is 'fail': the sending server is not allowed to send for this domain. |
| +20 | DMARC result is 'fail': the From address is not backed by SPF or DKIM. |
| +20 | Link shows portal[.]company[.]example but really goes to login-portal[.]example. |
| +15 | Replies go to pay@mail-drop.example, a different domain from the sender (c0mpany-help.example). |
| +15 | Attachment 'Invoice_8841.pdf.html' is a risky file type (.html). |
| +10 | Return-Path is bounce@mail-drop.example, a different domain from the sender (c0mpany-help.example). |
| +10 | DKIM result is 'none': the message has no valid digital signature. |
| +10 | Attachment 'Invoice_8841.pdf.html' has two extensions, a trick to disguise the real file type. |
| +10 | Pressure language used: urgent, immediately, suspended, overdue, verify your password, within 24 hours, act now, loss of access, do not ignore. |
| +5 | Generic greeting instead of the recipient's name. |

## Attachments

| File name | Type | Size | SHA-256 |
|---|---|---|---|
| Invoice_8841.pdf.html | text/html | 96 bytes | `49644c131e7273bb7fa7d950b16155b1a3270c891e18f9b0ad4959d850402ded` |

## Indicators of compromise (defanged)

**Domains**
- `c0mpany-help[.]example`
- `login-portal[.]example`
- `mail-drop[.]example`

**URLs**
- `hxxps://login-portal[.]example/verify?id=8841&user=alex[.]morgan`

**IP addresses**
- `203[.]0[.]113[.]45`
- `198[.]51[.]100[.]77`

**Email addresses**
- `bounce@mail-drop[.]example`
- `it@c0mpany-help[.]example`
- `pay@mail-drop[.]example`

**File hashes (SHA-256)**
- `49644c131e7273bb7fa7d950b16155b1a3270c891e18f9b0ad4959d850402ded`
