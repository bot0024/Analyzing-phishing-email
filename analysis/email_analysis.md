# Email-Analysis:

## 1. Sender Analysis

### From:

```banco.bradesco@atendimento.com.br```

- This is not an official Bradesco domain.


### Return Path: 

```root@ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06```

- Shows the email was sent from a Linux VPS on DigitalOcean, not from a legitimate banking server.

### Sender IP: ```137.184.34.4```

- Belongs to DigitalOcean, a cloud provider commonly misused for spam or phishing if not secured.

---

## 2. Authentication Failures
```
SPF: temperror

DKIM: none

DMARC: temperror 
```

These indicate the email failed all major authentication checks, suggesting spoofing or malicious origin.

---

## 3. Red Flags in Content

### Urgent Message:
 The subject urges the user to act quickly, a typical phishing trick.

```"Seu cartão tem 92.990 pontos LIVELO expirando hoje!" -  Your card has 92,990 LIVELO points expiring today!```

### Brand Impersonation: 
Uses Bradesco and Livelo logos and formatting to create false credibility.

### Malicious Link: 
The main CTA button redirects to:

```https://blog1seguimentmydomaine2bra.me/```

This is a fraudulent, non-Bradesco domain.

---

## 4. Technical Indicators

### Content-Type: 
HTML with embedded base64 encoded content.

### Message-ID: 
Does not align with Bradesco email infrastructure.

### Authentication Results: 
Compromised or unverifiable.

---

## 📍 Server Details (the attacker’s machine)

### Hostname: 

```ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06```

### IP Address: 
```137.184.34.4```

### Provider: 
```DigitalOcean (San Francisco region)```

This VPS was almost certainly created and configured manually to send spam/phishing emails.

---

## Conclusion

- This email is a phishing attempt. It leverages urgency, spoofed branding, and fraudulent links to compromise user data.

---

## Recommendations

- Do NOT click any links.

- Mark the email as phishing/spam.

- Report the incident to Bradesco.

- Run a malware scan if any interaction occurred.

- Reset passwords if suspicious activity is noticed.

