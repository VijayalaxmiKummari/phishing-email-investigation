# Beginner Guide: Phishing Email Investigation

This guide assumes you have never investigated an email before. Follow it from top to bottom. Commands are written for a Mac; they work the same on Linux, and on Windows if you type `python` instead of `python3`.

**Contents**

1. [What you are doing and why](#1-what-you-are-doing-and-why)
2. [Words you need to know](#2-words-you-need-to-know)
3. [Set up your computer](#3-set-up-your-computer)
4. [Stage 1 - Analyse the suspicious email by hand](#4-stage-1---analyse-the-suspicious-email-by-hand)
5. [Stage 2 - Identify indicators with the tool](#5-stage-2---identify-indicators-with-the-tool)
6. [Stage 3 - Document your findings](#6-stage-3---document-your-findings)
7. [Safety rules for real emails](#7-safety-rules-for-real-emails)
8. [Troubleshooting](#8-troubleshooting)
9. [How to talk about this project in an interview](#9-how-to-talk-about-this-project-in-an-interview)
10. [Ideas to extend the project](#10-ideas-to-extend-the-project)

---

## 1. What you are doing and why

Phishing is an email that pretends to be from someone trustworthy so the reader hands over a password, pays a fake invoice or opens a harmful file. It is the most common way attackers get into organisations, so checking reported emails is one of the most frequent jobs a junior SOC analyst does.

When a user reports an email, the analyst answers three questions:

1. **Is it malicious?** (the verdict)
2. **What is the evidence?** (the indicators)
3. **What should we do about it?** (the response)

This project walks through all three on one sample email.

## 2. Words you need to know

| Term | Plain meaning |
|---|---|
| **.eml file** | An email saved as a file. It holds everything: the hidden headers, the message and the attachments. |
| **Header** | Hidden lines at the top of every email recording who sent it, where it travelled and whether it passed security checks. |
| **From** | The sender the reader sees. It is easy to fake. |
| **Reply-To** | Where your reply goes if you press Reply. Attackers set this to their own address. |
| **Return-Path** | Where "could not deliver" messages go. It shows the domain that really sent the email. |
| **Received** | One line added by each mail server the email passed through. The newest is at the top, so you read them from the bottom up. |
| **SPF** | A check asking "is this server allowed to send email for this domain?" |
| **DKIM** | A digital signature proving the email was not changed and came from the signing domain. |
| **DMARC** | A check asking "does the From address match a domain that passed SPF or DKIM?" It also tells the receiver what to do on failure. |
| **Lookalike domain** | A fake domain made to resemble a real one, such as `c0mpany` with a zero. Also called typosquatting. |
| **IOC** | Indicator of compromise. A piece of evidence you can search for or block: a domain, URL, IP address, email address or file hash. |
| **Hash (SHA-256)** | A unique fingerprint of a file. The same file always gives the same hash, so you can identify a file without opening it. |
| **Defanging** | Rewriting a dangerous link so nobody can click it by accident: `https://bad.example` becomes `hxxps://bad[.]example`. |
| **MITRE ATT&CK** | A public catalogue of attacker techniques, each with an ID such as T1566 (Phishing). Analysts use it as a shared language. |

## 3. Set up your computer

### 3.1 Open the Terminal

On a Mac press `Cmd + Space`, type `Terminal` and press Enter. A window opens where you type commands.

### 3.2 Check Python is installed

```bash
python3 --version
```

You should see something like `Python 3.12.4`. Any version from 3.8 upwards is fine. If you see "command not found", install Python from https://www.python.org/downloads/ and open a new Terminal window.

### 3.3 Check Git is installed

```bash
git --version
```

On a Mac, if Git is missing a pop-up offers to install the "command line developer tools". Click Install and wait for it to finish.

### 3.4 Get the project

```bash
cd ~/Documents
git clone https://github.com/YOUR-USERNAME/phishing-email-investigation.git
cd phishing-email-investigation
```

`cd` means "change directory", which moves you into a folder. Replace `YOUR-USERNAME` with your GitHub username.

### 3.5 Look around

```bash
ls
```

`ls` lists what is in the folder. You should see `README.md`, `analyzer`, `samples`, `reports`, `docs` and `tests`.

## 4. Stage 1 - Analyse the suspicious email by hand

Do this by hand first. The tool in Stage 2 only automates what you learn here.

### 4.1 Open the raw email

```bash
cat samples/invoice_overdue.eml
```

`cat` prints a file to the screen. You can also open the file in TextEdit or VS Code. **Never double-click a real suspicious .eml file**, because that opens it in your mail app and may load its content. Reading it as text is safe.

### 4.2 Check who it claims to be from

Find these three lines:

```
Return-Path: <bounce@mail-drop.example>
From: "IT Support" <it@c0mpany-help.example>
Reply-To: pay@mail-drop.example
```

Ask yourself:

- **Is the From domain the real one?** Look closely at `c0mpany-help`. The second character is a zero, not the letter o. The real domain is `company.example`. This is a lookalike domain.
- **Do From, Reply-To and Return-Path share a domain?** No. From is `c0mpany-help.example`; the other two are `mail-drop.example`. In a genuine email they normally match. Here, a reply would go straight to the attacker.

### 4.3 Check the authentication results

Find this header:

```
Authentication-Results: mx.company.example; spf=fail (sender IP is 198.51.100.77)
 smtp.mailfrom=mail-drop.example; dkim=none; dmarc=fail action=none
 header.from=c0mpany-help.example
```

The receiving mail server wrote this when the email arrived. Read it piece by piece:

| Part | Meaning |
|---|---|
| `spf=fail` | The server at 198.51.100.77 is not on the list of servers allowed to send for that domain. |
| `dkim=none` | The email has no digital signature at all. |
| `dmarc=fail` | The From address is not backed by SPF or DKIM. |
| `action=none` | The receiver took no action, so the email was still delivered. |

Possible values are `pass`, `fail`, `softfail`, `neutral` and `none`. One failure alone can be a misconfiguration. Three together, on an email asking for a password, is strong evidence.

### 4.4 Trace the route

Find the `Received:` lines. There are three. **Read from the bottom one up**, because each server adds its line at the top.

```
(bottom) from WIN-7K2PQ1 (unknown [203.0.113.45]) by relay7.mail-drop.example
(middle) from relay7.mail-drop.example [198.51.100.77] by mx.company.example
(top)    from mx.company.example [192.0.2.25] by inbox.company.example
```

In plain English:

1. A computer called `WIN-7K2PQ1` at IP 203.0.113.45 handed the email to `mail-drop.example`. That name is the kind Windows gives a PC by default, so this is somebody's computer and not a company mail server.
2. `mail-drop.example` passed it to the company's mail server.
3. The company's mail server delivered it to the inbox. This hop is internal and is not suspicious.

So the email did not come from the company's own IT systems.

Two more small clues in the headers:

- `X-Mailer: PHPMailer 5.2.9` - sent by a script, not by Outlook or Gmail.
- `Message-ID: <...@WIN-7K2PQ1>` - the ID ends in the PC's name, not a real mail domain.

### 4.5 Read the message

Scroll down to the text of the email and look for social engineering, which means tricks that push people to act without thinking.

| What it says | Why it is a red flag |
|---|---|
| "URGENT", "within 24 hours", "act now" | Creates time pressure so the reader does not stop to check. |
| "Your account will be suspended" | A threat. |
| "Dear user" | The sender does not know the recipient's name. |
| "verify your password" | Real IT teams do not ask for your password by email. |
| An overdue invoice from IT Support | The story does not make sense. IT does not chase invoices. |

### 4.6 Inspect the link without clicking it

In the HTML part of the email, find this line:

```html
<a href="https://login-portal.example/verify?id=8841&amp;user=alex.morgan">https://portal.company.example/billing</a>
```

A link has two parts:

- The text between `>` and `</a>` is **what the reader sees**: `portal.company.example/billing`
- The `href="..."` value is **where it really goes**: `login-portal.example/verify...`

They are different domains. The reader sees their company's real portal and lands on the attacker's page. Notice too that the address contains `user=alex.morgan`, so the attacker knows exactly who clicked.

### 4.7 Look at the attachment

Find this line near the bottom:

```
Content-Disposition: attachment; filename="Invoice_8841.pdf.html"
```

The name has two extensions. Only the last one counts, so this is an HTML file (a web page), not a PDF. Many computers hide the last extension, so the user sees "Invoice_8841.pdf". HTML attachments are often fake login forms.

You do not open it. In Stage 2 the tool takes its hash instead.

### 4.8 Write down what you found

Before moving on, list your red flags on paper. You should have about seven. Compare your list with the table in the [README](../README.md#what-i-found).

## 5. Stage 2 - Identify indicators with the tool

### 5.1 Run it

Make sure you are in the project folder, then:

```bash
python3 analyzer/phish_analyzer.py samples/invoice_overdue.eml --trusted-domain company.example
```

What each part means:

| Part | Meaning |
|---|---|
| `python3` | Run a Python program |
| `analyzer/phish_analyzer.py` | The program to run |
| `samples/invoice_overdue.eml` | The email to check |
| `--trusted-domain company.example` | The organisation's real domain, so the tool can spot imitations |

### 5.2 Read the output

```
VERDICT: MALICIOUS  (risk score 100/100)

  [+20] Sender domain c0mpany-help.example imitates company.example but is not the same domain.
  [+20] SPF result is 'fail': the sending server is not allowed to send for this domain.
  [+20] DMARC result is 'fail': the From address is not backed by SPF or DKIM.
  [+20] Link shows portal[.]company[.]example but really goes to login-portal[.]example.
  [+15] Replies go to pay@mail-drop.example, a different domain from the sender (c0mpany-help.example).
  [+15] Attachment 'Invoice_8841.pdf.html' is a risky file type (.html).
  [+10] Return-Path is bounce@mail-drop.example, a different domain from the sender (c0mpany-help.example).
  [+10] DKIM result is 'none': the message has no valid digital signature.
  [+10] Attachment 'Invoice_8841.pdf.html' has two extensions, a trick to disguise the real file type.
  [+10] Pressure language used: urgent, immediately, suspended, overdue, ...
  [+ 5] Generic greeting instead of the recipient's name.
```

Each line is one finding and the points it added. The points add up to more than 100, so the score is capped at 100. Sixty or more gives a verdict of MALICIOUS.

Every finding matches something you found by hand in Stage 1. That is the point: the tool is quicker, but you can explain each line yourself.

### 5.3 Open the files it created

```bash
cat reports/invoice_overdue_auto_report.md
cat reports/invoice_overdue_iocs.json
```

- The `.md` file is a readable report with tables.
- The `.json` file holds the same data in a format other security tools can read.

Look at the "Indicators of compromise" section. Notice the indicators are defanged (`hxxps`, `[.]`). The company's own domain and its own mail server are left out because they belong to the victim, not the attacker.

### 5.4 Understand how the tool works

Open `analyzer/phish_analyzer.py` in a text editor. It is commented throughout. The main function, `analyse`, has five numbered steps that mirror Stage 1:

1. Who does the email claim to be from?
2. Did it pass the authentication checks?
3. Which servers did it travel through?
4. Read the body text, links and attachments.
5. Add up the score and decide.

You do not have to understand every line. Aim to be able to say what each of the five steps does.

### 5.5 Run the tests

```bash
python3 -m unittest discover tests -v
```

You should see nine lines ending in `ok` and then `OK`. Tests are small automatic checks that prove the tool still gives the right answers. Having them shows good practice.

### 5.6 Try it yourself

Make a copy of the sample and change it to see how the score reacts:

```bash
cp samples/invoice_overdue.eml samples/my_test.eml
```

Open `samples/my_test.eml` in a text editor, change `spf=fail` to `spf=pass`, save, and run the tool on `samples/my_test.eml`. One finding disappears. Experimenting like this is how you learn what each check does. Delete `my_test.eml` when you are done.

## 6. Stage 3 - Document your findings

An investigation is only useful if someone else can read it and act. Open [`reports/investigation_report.md`](../reports/investigation_report.md) and notice its structure:

| Section | What it answers |
|---|---|
| Header table | Who analysed what, when, and the verdict |
| Summary | The whole case in a few sentences for a busy reader |
| Analysis | The evidence, one area at a time |
| Indicators of compromise | Everything to block or search for, defanged |
| MITRE ATT&CK | Which known attacker techniques were used |
| Recommended actions | What to do: contain, check for impact, prevent |
| Conclusion | The verdict and the reasons, restated briefly |

Rules for a good report:

- **Lead with the verdict.** The reader should know the answer in the first few lines.
- **State facts and show the evidence.** "SPF failed for 198[.]51[.]100[.]77", not "the email seemed dodgy".
- **Defang everything.** No clickable links to bad sites.
- **Say what you did not do.** For example, "the link was not opened".
- **Make the actions specific.** Name the domain to block and the log to search.

To practise, close the report and write your own from your Stage 1 notes, then compare.

## 7. Safety rules for real emails

The sample here is harmless. Real phishing emails are not. When you work with real ones:

- Never click links or open attachments on your everyday computer. Use an isolated virtual machine or an online sandbox.
- Read `.eml` files as text. Do not open them in a mail app.
- Do not upload emails from your workplace or university to public websites such as VirusTotal. They may contain private information, and attackers watch those sites. Look up the hash or domain instead.
- Always defang indicators when you share them.
- Do not publish real phishing emails with real people's names or addresses on GitHub.

## 8. Troubleshooting

| Problem | Fix |
|---|---|
| `python3: command not found` | Install Python from python.org, then open a new Terminal window. On Windows use `python`. |
| `File not found: samples/invoice_overdue.eml` | You are in the wrong folder. Run `cd ~/Documents/phishing-email-investigation` and try again. |
| `No such file or directory` when running the tool | Same cause. Run `pwd` to see where you are and `ls` to see what is there. |
| `git: command not found` | Install Git (on a Mac, accept the developer tools pop-up). |
| Tests fail after you edited the sample | Restore the original with `git checkout samples/invoice_overdue.eml`. |

## 9. How to talk about this project in an interview

A short answer you can adapt:

> "I investigated a phishing email end to end. I started with the raw headers and found the sender was a lookalike domain, with the Reply-To and Return-Path pointing somewhere else. SPF, DKIM and DMARC all failed. I traced the Received headers back to the originating IP, found a link whose visible text did not match its real destination, and an HTML attachment disguised with a double extension. I wrote a small Python tool to automate those checks and extract defanged IOCs, mapped the activity to MITRE ATT&CK, and wrote a report with containment steps such as blocking the domains, searching mailboxes for other copies and checking proxy logs for clicks."

Questions you should be ready for:

- **What is the difference between SPF, DKIM and DMARC?** SPF checks the sending server, DKIM checks a signature on the message, and DMARC checks that one of them matches the From address and sets the policy on failure.
- **Why read Received headers from the bottom?** Each server adds its line at the top, so the first hop is at the bottom.
- **A user clicked the link. What do you do?** Reset the password, end active sessions, review sign-in logs, check for new mailbox rules, and search for other recipients.
- **Can headers be faked?** Yes. The sender controls From, Reply-To and any Received lines below the first trusted server. The lines added by your own mail servers can be trusted.
- **What are the limits of your tool?** It trusts the receiver's Authentication-Results header, catches only simple lookalikes and does no reputation lookups.

## 10. Ideas to extend the project

- Look up domains and hashes against VirusTotal or AbuseIPDB using their free APIs.
- Handle a whole folder of emails and produce one summary table.
- Detect more lookalike tricks, such as characters from other alphabets.
- Decode QR codes in image attachments, a growing phishing method.
- Write a Splunk or Elastic detection rule from the indicators and test it in a lab.
