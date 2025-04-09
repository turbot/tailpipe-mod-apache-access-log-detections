## Overview

Detect when clients connect using deprecated or weak SSL/TLS protocol versions that are vulnerable to known attacks. Older SSL/TLS versions (SSLv3, TLS 1.0, TLS 1.1) have known security vulnerabilities such as POODLE, BEAST, and CRIME that can be exploited to intercept and decrypt supposedly secure communications. This detection identifies clients attempting to connect with these insecure protocols, which could indicate outdated software, deliberate downgrade attacks, or misconfigured clients that pose a security risk to sensitive data in transit.

**References**:
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [OWASP: Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [NIST: Guidelines for TLS Implementations](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf)
- [MITRE ATT&CK T1557: Man-in-the-Middle](https://attack.mitre.org/techniques/T1557/) 