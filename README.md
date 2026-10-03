# Phishing Email Investigation

A hands-on SOC analyst project: take one suspicious email, work out whether it is malicious, pull out the indicators, and write it up the way a security team would.

**Verdict on the sample email: MALICIOUS (risk score 100/100)**

| | |
|---|---|
| **Skills shown** | Email header analysis, SPF / DKIM / DMARC, IOC extraction, defanging, MITRE ATT&CK mapping, incident reporting, Python |
| **Tools** | Python 3 (standard library only), a text editor, the terminal |
| **Time to complete** | About 60 to 90 minutes for a beginner |
| **Safe to run?** | Yes. The email is a training sample created for this project. Every domain ends in `.example` and every IP is from a documentation range, so none of them exist on the internet. |

## What this project does

1. **Analyse a suspicious email** - read the raw `.eml` file by hand and understand each header.
2. **Identify indicators** - run a small Python tool that pulls out domains, URLs, IPs and file hashes and scores the email.
3. **Document the findings** - write an investigation report with a verdict, evidence and recommended actions.

## The email at a glance

```
From:      "IT Support" <it@c0mpany-help.example>
Reply-To:  pay@mail-drop.example
spf=fail   dkim=none   dmarc=fail
hxxps://login-portal[.]example
VERDICT: MALICIOUS
```

## What I found

| # | Red flag | Why it matters |
|---|---|---|
| 1 | Sender domain is `c0mpany-help` with a zero instead of the letter o | A lookalike domain built to pass a quick glance |
| 2 | SPF fail, DKIM none, DMARC fail | The sending server had no right to send as this domain and the message is unsigned |
| 3 | Reply-To and Return-Path point to `mail-drop.example` | Replies would go to the attacker, not to IT |
| 4 | The link shows `portal.company.example` but goes to `login-portal.example` | The visible text hides a credential-harvesting page |
| 5 | Attachment named `Invoice_8841.pdf.html` | Double extension: it looks like a PDF but opens as a web page |
| 6 | "URGENT", "within 24 hours", "act now", "Dear user" | Pressure and a generic greeting, both classic social engineering |
| 7 | First hop is `WIN-7K2PQ1`, sent with PHPMailer | Sent from a personal Windows machine using a mailing script, not a company mail server |

The full write-up is in [`reports/investigation_report.md`](reports/investigation_report.md).

## Project layout

```
phishing-email-investigation/
├── samples/invoice_overdue.eml        the suspicious email (safe training sample)
├── analyzer/phish_analyzer.py         the Python triage tool
├── reports/
│   ├── investigation_report.md        my written investigation report
│   ├── invoice_overdue_auto_report.md report produced by the tool
│   └── invoice_overdue_iocs.json      indicators in machine-readable form
├── docs/
│   ├── BEGINNER_GUIDE.md              full step-by-step walkthrough
│   └── UPLOAD_TO_GITHUB.md            how to publish this project
└── tests/test_analyzer.py             automated checks for the tool
```

## Quick start

You need Python 3.8 or newer. Nothing else has to be installed.

```bash
git clone https://github.com/VijayalaxmiKummari/phishing-email-investigation.git
cd phishing-email-investigation
python3 analyzer/phish_analyzer.py samples/invoice_overdue.eml --trusted-domain company.example
```

Expected output:

```
VERDICT: MALICIOUS  (risk score 100/100)

  [+20] Sender domain c0mpany-help.example imitates company.example but is not the same domain.
  [+20] SPF result is 'fail': the sending server is not allowed to send for this domain.
  [+20] DMARC result is 'fail': the From address is not backed by SPF or DKIM.
  [+20] Link shows portal[.]company[.]example but really goes to login-portal[.]example.
  ...
Report saved to  reports/invoice_overdue_auto_report.md
IOC data saved to reports/invoice_overdue_iocs.json
```

Run the tests:

```bash
python3 -m unittest discover tests -v
```

New to all of this? Start with the [beginner guide](docs/BEGINNER_GUIDE.md). It explains every term and every step from scratch.

## How the tool scores an email

Each red flag adds points. The total is capped at 100.

| Finding | Points |
|---|---|
| SPF fail | 20 |
| DMARC fail | 20 |
| Lookalike sender domain | 20 |
| Link text does not match its real target | 20 |
| Reply-To on a different domain | 15 |
| Risky attachment type | 15 |
| DKIM fail or missing | 10 |
| Return-Path on a different domain | 10 |
| Double file extension | 10 |
| Urgent or threatening language | 10 |
| Generic greeting | 5 |

**60 or more = MALICIOUS, 30 to 59 = SUSPICIOUS, under 30 = LIKELY BENIGN.**

The score is a triage aid. It tells an analyst where to look first; the analyst still makes the final call.

## MITRE ATT&CK mapping

| Technique | ID | Where it shows up |
|---|---|---|
| Phishing: Spearphishing Link | T1566.002 | Link to the fake login page |
| Phishing: Spearphishing Attachment | T1566.001 | The HTML "invoice" attachment |
| Impersonation | T1656 | Posing as IT Support |
| Masquerading: Double File Extension | T1036.007 | `Invoice_8841.pdf.html` |
| User Execution: Malicious Link / File | T1204.001 / T1204.002 | The email needs the user to click or open |

## Limitations

- The tool reads the `Authentication-Results` header that the receiving mail server wrote. It does not redo the SPF, DKIM or DMARC checks itself.
- Lookalike detection covers simple character swaps (0 for o, 1 for l, rn for m). It will not catch every trick, for example characters from other alphabets.
- It works fully offline, so it does not check domains or hashes against reputation services such as VirusTotal. In a real investigation that would be the next step.

## What I learned

- How to read email headers from the bottom up to trace where a message really came from.
- What SPF, DKIM and DMARC each prove, and why a failure on all three is a strong signal.
- Why indicators are defanged before they go into a report.
- How to turn raw findings into a short report that someone else can act on.

## Author

Vijayalaxmi Kummari - MSc Cybersecurity, University of Hertfordshire

## Licence

MIT. See [LICENSE](LICENSE).
