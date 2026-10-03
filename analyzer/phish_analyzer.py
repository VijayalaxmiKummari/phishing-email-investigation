#!/usr/bin/env python3
"""
phish_analyzer.py - a small phishing email triage tool.

It reads a saved email (.eml file), pulls out the things a SOC analyst
looks at first, scores them, and writes a report.

It never opens links, never runs attachments and never connects to the
internet. Everything is done by reading the text of the file.

Usage:
    python3 analyzer/phish_analyzer.py samples/invoice_overdue.eml \
        --trusted-domain company.example

Only the Python standard library is used, so there is nothing to install.
"""

import argparse
import hashlib
import json
import re
import sys
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from pathlib import Path

# ---------------------------------------------------------------------------
# Reference lists (edit these to tune the tool)
# ---------------------------------------------------------------------------

# Words that phishing emails use to rush the reader.
URGENCY_WORDS = [
    "urgent", "immediately", "suspended", "overdue",
    "verify your password", "within 24 hours", "act now",
    "final notice", "loss of access", "do not ignore",
]

# Attachment types that can run code or open a fake login page.
RISKY_EXTENSIONS = {
    ".html", ".htm", ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd",
    ".iso", ".img", ".lnk", ".docm", ".xlsm", ".zip", ".rar", ".7z",
}

# Characters attackers swap in to make a fake domain look real.
LOOKALIKE_SWAPS = {"0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "rn": "m", "vv": "w"}

# How many points each finding adds to the risk score.
WEIGHTS = {
    "spf_fail": 20,
    "dkim_fail": 10,
    "dmarc_fail": 20,
    "reply_to_mismatch": 15,
    "return_path_mismatch": 10,
    "lookalike_domain": 20,
    "link_mismatch": 20,
    "urgency": 10,
    "risky_attachment": 15,
    "double_extension": 10,
    "generic_greeting": 5,
}


# ---------------------------------------------------------------------------
# Small helper functions
# ---------------------------------------------------------------------------

def domain_of(address):
    """Return the domain part of an email address, in lower case."""
    address = parseaddr(address or "")[1]
    return address.rsplit("@", 1)[1].lower() if "@" in address else ""


def host_of(url):
    """Return the host name inside a URL."""
    match = re.match(r"https?://([^/:?#\s]+)", url, re.I)
    return match.group(1).lower() if match else ""


def defang(value):
    """Make a URL, domain or IP safe to paste into a report.

    'Defanging' changes the text so nobody can click it by accident:
    https://bad.example  ->  hxxps://bad[.]example
    """
    value = re.sub(r"^http", "hxxp", value, flags=re.I)
    return value.replace(".", "[.]")


def normalise_lookalike(label):
    """Undo common character swaps: c0mpany -> company."""
    for fake, real in LOOKALIKE_SWAPS.items():
        label = label.replace(fake, real)
    return label


def looks_like(candidate, trusted):
    """True if 'candidate' is a different domain that imitates 'trusted'."""
    if not candidate or not trusted or candidate == trusted:
        return False
    if candidate.endswith("." + trusted):
        return False  # a real subdomain of the trusted domain
    brand = trusted.split(".")[0]            # company.example -> company
    cleaned = normalise_lookalike(candidate)  # c0mpany-help.example -> company-help.example
    return brand in cleaned


class LinkCollector(HTMLParser):
    """Collects every link in an HTML email as (visible text, real target)."""

    def __init__(self):
        super().__init__()
        self.links = []
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href", "")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append(("".join(self._text).strip(), self._href))
            self._href = None


# ---------------------------------------------------------------------------
# The analysis itself
# ---------------------------------------------------------------------------

def analyse(path, trusted_domain=None):
    """Read one .eml file and return a dictionary of everything we found."""
    raw = Path(path).read_bytes()
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    findings = []   # each one is {"id", "points", "detail"}

    def flag(finding_id, detail):
        findings.append({"id": finding_id, "points": WEIGHTS[finding_id], "detail": detail})

    # --- 1. Who does the email claim to be from? -------------------------
    from_name, from_addr = parseaddr(msg.get("From", ""))
    from_domain = domain_of(from_addr)
    reply_to = parseaddr(msg.get("Reply-To", ""))[1]
    return_path = parseaddr(msg.get("Return-Path", ""))[1]

    if reply_to and domain_of(reply_to) != from_domain:
        flag("reply_to_mismatch",
             f"Replies go to {reply_to}, a different domain from the sender ({from_domain}).")
    if return_path and domain_of(return_path) != from_domain:
        flag("return_path_mismatch",
             f"Return-Path is {return_path}, a different domain from the sender ({from_domain}).")
    if trusted_domain and looks_like(from_domain, trusted_domain.lower()):
        flag("lookalike_domain",
             f"Sender domain {from_domain} imitates {trusted_domain} but is not the same domain.")

    # --- 2. Did the email pass the authentication checks? ----------------
    auth_header = " ".join(msg.get_all("Authentication-Results", []))
    auth = {}
    for check in ("spf", "dkim", "dmarc"):
        match = re.search(rf"\b{check}=(\w+)", auth_header, re.I)
        auth[check] = match.group(1).lower() if match else "not present"
    if auth["spf"] in ("fail", "softfail"):
        flag("spf_fail", f"SPF result is '{auth['spf']}': the sending server is not allowed to send for this domain.")
    if auth["dkim"] in ("fail", "none"):
        flag("dkim_fail", f"DKIM result is '{auth['dkim']}': the message has no valid digital signature.")
    if auth["dmarc"] == "fail":
        flag("dmarc_fail", "DMARC result is 'fail': the From address is not backed by SPF or DKIM.")

    # --- 3. Which servers did the email travel through? ------------------
    # Received headers are added top-down, so the LAST one is the first hop.
    hops = []
    for header in reversed(msg.get_all("Received", [])):
        text = " ".join(str(header).split())
        ip = re.search(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", text)
        sender = re.search(r"from\s+(\S+)", text)
        receiver = re.search(r"\bby\s+(\S+)", text)
        hops.append({
            "from": sender.group(1) if sender else "",
            "by": receiver.group(1) if receiver else "",
            "ip": ip.group(1) if ip else "",
        })
    origin_ip = hops[0]["ip"] if hops else ""

    # --- 4. Read the body text and the links -----------------------------
    plain, html = "", ""
    attachments = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename:
            data = part.get_payload(decode=True) or b""
            suffixes = [s.lower() for s in Path(filename).suffixes]
            attachments.append({
                "filename": filename,
                "content_type": part.get_content_type(),
                "size_bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            })
            if suffixes and suffixes[-1] in RISKY_EXTENSIONS:
                flag("risky_attachment", f"Attachment '{filename}' is a risky file type ({suffixes[-1]}).")
            if len(suffixes) >= 2:
                flag("double_extension",
                     f"Attachment '{filename}' has two extensions, a trick to disguise the real file type.")
        elif part.get_content_type() == "text/plain":
            plain += part.get_content()
        elif part.get_content_type() == "text/html":
            html += part.get_content()

    collector = LinkCollector()
    collector.feed(html)
    urls = set(re.findall(r"https?://[^\s\"'<>]+", plain))
    for shown, target in collector.links:
        if target.lower().startswith("http"):
            urls.add(target)
        shown_host, target_host = host_of(shown), host_of(target)
        if shown_host and target_host and shown_host != target_host:
            flag("link_mismatch",
                 f"Link shows {defang(shown_host)} but really goes to {defang(target_host)}.")
    urls = sorted(urls)

    body_lower = (plain + " " + msg.get("Subject", "")).lower()
    hits = [word for word in URGENCY_WORDS if word in body_lower]
    if len(hits) >= 2:
        flag("urgency", "Pressure language used: " + ", ".join(hits) + ".")
    if re.search(r"dear (user|customer|client|member)", body_lower):
        flag("generic_greeting", "Generic greeting instead of the recipient's name.")

    # --- 5. Add up the score and decide ----------------------------------
    score = min(100, sum(f["points"] for f in findings))
    if score >= 60:
        verdict = "MALICIOUS"
    elif score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LIKELY BENIGN"

    domains = {from_domain, domain_of(reply_to), domain_of(return_path)} | {host_of(u) for u in urls}
    trusted = (trusted_domain or "").lower()
    domains = sorted(d for d in domains if d and d != trusted and not d.endswith("." + trusted))

    return {
        "file": str(path),
        "email_sha256": hashlib.sha256(raw).hexdigest(),
        "headers": {
            "from_name": from_name,
            "from_address": from_addr,
            "reply_to": reply_to,
            "return_path": return_path,
            "to": [a for _, a in getaddresses(msg.get_all("To", []))],
            "subject": msg.get("Subject", ""),
            "date": msg.get("Date", ""),
            "message_id": msg.get("Message-ID", ""),
            "x_mailer": msg.get("X-Mailer", ""),
        },
        "authentication": auth,
        "hops": hops,
        "origin_ip": origin_ip,
        "urls": urls,
        "attachments": attachments,
        "findings": findings,
        "score": score,
        "verdict": verdict,
        "iocs": {
            "domains": [defang(d) for d in domains],
            "urls": [defang(u) for u in urls],
            "ips": [defang(h["ip"]) for h in hops if h["ip"] and not h["from"].endswith(trusted or "\0")],
            "email_addresses": sorted({defang(a) for a in (from_addr, reply_to, return_path) if a}),
            "file_hashes_sha256": [a["sha256"] for a in attachments],
        },
    }


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def to_markdown(result):
    """Turn the result dictionary into a readable Markdown report."""
    h, a = result["headers"], result["authentication"]
    lines = [
        "# Phishing Triage Report (auto-generated)",
        "",
        f"**Verdict: {result['verdict']}**  |  Risk score: {result['score']}/100",
        "",
        "## Email details",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| File | `{result['file']}` |",
        f"| Subject | {h['subject']} |",
        f"| From | {h['from_name']} &lt;{defang(h['from_address'])}&gt; |",
        f"| Reply-To | {defang(h['reply_to']) or '-'} |",
        f"| Return-Path | {defang(h['return_path']) or '-'} |",
        f"| To | {', '.join(h['to'])} |",
        f"| Date | {h['date']} |",
        f"| Sent with | {h['x_mailer'] or '-'} |",
        f"| Email SHA-256 | `{result['email_sha256']}` |",
        "",
        "## Authentication",
        "",
        "| Check | Result |",
        "|---|---|",
        f"| SPF | {a['spf']} |",
        f"| DKIM | {a['dkim']} |",
        f"| DMARC | {a['dmarc']} |",
        "",
        "## Delivery path (first hop at the top)",
        "",
        "| Hop | From | IP | Received by |",
        "|---|---|---|---|",
    ]
    for number, hop in enumerate(result["hops"], 1):
        lines.append(f"| {number} | {defang(hop['from'])} | {defang(hop['ip'])} | {defang(hop['by'])} |")
    lines += ["", "## Findings", "", "| Points | Finding |", "|---|---|"]
    for f in sorted(result["findings"], key=lambda item: -item["points"]):
        lines.append(f"| +{f['points']} | {f['detail']} |")
    lines += ["", "## Attachments", ""]
    if result["attachments"]:
        lines += ["| File name | Type | Size | SHA-256 |", "|---|---|---|---|"]
        for att in result["attachments"]:
            lines.append(f"| {att['filename']} | {att['content_type']} | {att['size_bytes']} bytes | `{att['sha256']}` |")
    else:
        lines.append("None.")
    lines += ["", "## Indicators of compromise (defanged)", ""]
    for label, key in (("Domains", "domains"), ("URLs", "urls"), ("IP addresses", "ips"),
                       ("Email addresses", "email_addresses"), ("File hashes (SHA-256)", "file_hashes_sha256")):
        lines.append(f"**{label}**")
        lines += [f"- `{item}`" for item in result["iocs"][key]] or ["- none"]
        lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Triage a saved phishing email (.eml).")
    parser.add_argument("eml", help="path to the .eml file")
    parser.add_argument("--trusted-domain", help="your organisation's real domain, e.g. company.example")
    parser.add_argument("--out", default="reports", help="folder to write the report files into")
    args = parser.parse_args()

    if not Path(args.eml).is_file():
        sys.exit(f"File not found: {args.eml}")

    result = analyse(args.eml, args.trusted_domain)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = Path(args.eml).stem
    md_path = out_dir / f"{stem}_auto_report.md"
    json_path = out_dir / f"{stem}_iocs.json"
    md_path.write_text(to_markdown(result), encoding="utf-8")
    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print(f"\nVERDICT: {result['verdict']}  (risk score {result['score']}/100)\n")
    for f in sorted(result["findings"], key=lambda item: -item["points"]):
        print(f"  [+{f['points']:>2}] {f['detail']}")
    print(f"\nReport saved to  {md_path}")
    print(f"IOC data saved to {json_path}\n")


if __name__ == "__main__":
    main()
