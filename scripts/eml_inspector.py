#!/usr/bin/env python3
"""Parse a phishing email sample and print suspicious indicators."""

import argparse
import json
import re
from email import policy
from email.parser import BytesParser
from html import unescape


def extract_authentication_results(message):
    values = {}
    auth = message.get("Authentication-Results", "")
    if not auth:
        return values

    patterns = {
        "spf": r"spf\s*=\s*([^;\s]+)",
        "dkim": r"dkim\s*=\s*([^;\s]+)",
        "dmarc": r"dmarc\s*=\s*([^;\s]+)",
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, auth, flags=re.IGNORECASE)
        if match:
            values[key] = match.group(1).strip()

    return values


def extract_links(message):
    links = set()
    for part in message.walk():
        if part.get_content_maintype() != "multipart" and part.get_content_type() in {
            "text/plain",
            "text/html",
        }:
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            text = payload.decode(errors="replace")
            for match in re.findall(r"https?://[^\s\"'<>]+", text):
                links.add(unescape(match.rstrip(").,>")))
    return sorted(links)


def extract_suspicious_indicators(message):
    suspicious = []
    subject = message.get("Subject", "")
    sender = message.get("From", "")
    body_text = "\n".join(
        part.get_payload(decode=True).decode(errors="replace", charset="utf-8", errors="replace")
        if part.get_content_maintype() != "multipart"
        else ""
        for part in message.walk()
    )

    if re.search(r"expir(ing|e|es)|urgent|immediate|today", subject, flags=re.IGNORECASE):
        suspicious.append("Urgent action language in the subject line")

    if sender and ("@atendimento.com.br" in sender.lower() or "@bradesco" not in sender.lower()):
        suspicious.append("Sender address does not match an official Bradesco mailbox")

    if re.search(r"points?\s+.*\s+expir|\bpoints\b.*\bexpire\b", body_text, flags=re.IGNORECASE):
        suspicious.append("Threat/urgency messaging about expiring rewards or points")

    links = extract_links(message)
    for link in links:
        domain = link.split("//")[-1].split("/")[0].lower()
        if any(token in domain for token in ["bradesco", "livelo"]) is False and domain:
            suspicious.append(f"External link not aligned with official brand domains: {link}")
            break

    return suspicious


def load_message(path):
    with open(path, "rb") as raw_email:
        return BytesParser(policy=policy.default).parse(raw_email)


def build_summary(path):
    message = load_message(path)
    auth = extract_authentication_results(message)
    links = extract_links(message)
    summary = {
        "file": path,
        "subject": message.get("Subject", ""),
        "from": message.get("From", ""),
        "reply_to": message.get("Reply-To", ""),
        "return_path": message.get("Return-Path", ""),
        "message_id": message.get("Message-ID", ""),
        "authentication_results": auth,
        "links": links,
        "suspicious_indicators": extract_suspicious_indicators(message),
    }
    return summary


def main():
    parser = argparse.ArgumentParser(description="Inspect phishing EML files for suspicious indicators.")
    parser.add_argument("email_file", help="Path to the .eml file to inspect")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of plain text")
    args = parser.parse_args()

    summary = build_summary(args.email_file)

    if args.json:
        print(json.dumps(summary, indent=2))
        return

    print(f"Subject: {summary['subject']}")
    print(f"From: {summary['from']}")
    print(f"Return-Path: {summary['return_path']}")
    print(f"Message-ID: {summary['message_id']}")
    print()
    print("Authentication Results:")
    for key, value in summary["authentication_results"].items():
        print(f"  - {key.upper()}: {value}")
    if not summary["authentication_results"]:
        print("  - None found in headers")

    print()
    print(f"Links ({len(summary['links'])}):")
    if summary["links"]:
        for link in summary["links"]:
            print(f"  - {link}")
    else:
        print("  - No URLs detected")

    print()
    print("Suspicious Indicators:")
    if summary["suspicious_indicators"]:
        for item in summary["suspicious_indicators"]:
            print(f"  - {item}")
    else:
        print("  - No obvious indicators detected")


if __name__ == "__main__":
    main()
