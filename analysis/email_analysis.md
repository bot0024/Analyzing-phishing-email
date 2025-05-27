# Email Analysis

This is a phishing email spoofing Banco do Bradesco and Livelo.

## Key Observations:
- Urgency: Claims points expire today.
- Fake sender: banco.bradesco@atendimento.com.br
- Suspicious IP: 137.184.34.4 (likely attacker-controlled VPS)
- No SPF/DKIM/DMARC validation
- HTML layout mimics official Bradesco promotions

The email uses visual tricks and urgency to lure victims into clicking a malicious link.
