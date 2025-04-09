## Overview

Detect when credentials are transmitted in cleartext over unencrypted HTTP connections. Sensitive authentication credentials should always be transmitted over secure, encrypted connections (HTTPS). When credentials are sent over unencrypted HTTP, they can be intercepted by attackers through network sniffing, man-in-the-middle attacks, or compromised network infrastructure. This detection identifies instances where login credentials are transmitted via HTTP rather than HTTPS, exposing them to potential interception which could lead to unauthorized account access, identity theft, or further system compromise.

**References**:
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [OWASP: Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [MITRE ATT&CK T1040: Network Sniffing](https://attack.mitre.org/techniques/T1040/) 