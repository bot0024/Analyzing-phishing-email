# Bradesco Livelo Phishing Email Analysis

This repository contains a phishing email sample impersonating Bradesco and Livelo, along with a structured analysis and a small Python utility for extracting email indicators.

## Overview

The sample email uses common phishing tactics:

- Urgent language claiming reward points are expiring today
- Brand impersonation of Bradesco and Livelo
- A suspicious sender address not aligned with official Bradesco infrastructure
- A malicious or non-official external link
- Authentication failures suggesting spoofing or invalid origin

## Repository Structure

- `email/BRADESCO_LIVELO.eml` — original phishing email sample
- `analysis/email_analysis.md` — written investigation notes
- `screenshots/email_rendered.png` — rendered email preview
- `scripts/eml_inspector.py` — Python script to inspect headers, links, and phishing indicators

## Quick Start

Run the parser against the sample email:

```bash
python3 scripts/eml_inspector.py email/BRADESCO_LIVELO.eml
```

To output the result as JSON:

```bash
python3 scripts/eml_inspector.py email/BRADESCO_LIVELO.eml --json
```

## Key Findings

- Subject: `CLIENTE PRIME - BRADESCO LIVELO`
- Sender: `banco.bradesco@atendimento.com.br`
- Suspicious return-path / infrastructure indicators
- Sender IP: `137.184.34.4`
- SPF/DKIM/DMARC checks are not valid or are inconclusive
- Malicious URL observed: `https://blog1seguimentmydomaine2bra.me/`

## Why This Repo Matters

This repository is useful for:

- security awareness and phishing education,
- practical email analysis exercises,
- testing automated email threat-detection logic,
- documenting how a fraudulent financial email can be identified.

## Suggested Next Improvements

- Add multiple sample emails to compare phishing patterns
- Add a CSV/JSON export for extracted indicators
- Add rule-based checks for suspicious domains, headers, and urgent messaging
- Add a notebook or dashboard to visualize common phishing patterns

## Contributing

Contributions are welcome. If you improve the analysis or add automation, open a pull request with a clear explanation of the changes.
