## Overview

Detect when a web server received requests from unauthorized IP ranges or geographic locations. Many organizations implement network segmentation and access control based on IP address ranges to enforce the principle of least privilege and reduce the attack surface. Connections from unexpected IP addresses, particularly those outside of known corporate networks or from unexpected geographic regions, may indicate unauthorized access attempts, potential breaches, or misconfigured access controls.

**References**:
- [OWASP: Authentication Cheat Sheet - IP-Based Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#ip-based-authentication)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- [Apache HTTP Server: Access Control](https://httpd.apache.org/docs/2.4/howto/access.html) 