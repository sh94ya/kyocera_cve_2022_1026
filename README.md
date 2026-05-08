# Kyocera CVE-2022-1026
Metasploit module for obtaining passwords for Kyocera printer address books in cleartext
# Overview
CVE-2022-1026 is a critical vulnerability in Kyocera multifunction printers (MFPs) that allows a remote attacker to extract sensitive data without authentication.
## Key Features
- Type: Insufficient Credential Protection (CWE-522).
- Severity Score (CVSS 3.1): 8.6 (High) — high severity.
- Nature of the Issue: The vulnerability relates to the address book export function via the SOAP protocol (port 9091/TCP). A device can respond to a specially crafted request and provide address book data even if mandatory user authentication is enabled in the settings.

# Reference
[Original POC](https://github.com/ac3lives/kyocera-cve-2022-1026)
