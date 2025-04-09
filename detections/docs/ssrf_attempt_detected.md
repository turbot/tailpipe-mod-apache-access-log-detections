## Overview

Detect when a web server received requests that attempt to exploit server-side request forgery (SSRF) vulnerabilities. SSRF vulnerabilities allow attackers to make the server perform requests to internal or external systems that should not be accessible. These attacks can bypass network security controls by leveraging the trust given to the vulnerable server. This detection identifies common SSRF patterns in web requests, including suspicious URL parameters, attempts to access internal resources, and the use of potentially dangerous URL schemes. Successful SSRF attacks can lead to internal network scanning, data exfiltration, or remote code execution through access to internal services.

**References**:
- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
- [OWASP: A10:2021-Server-Side Request Forgery](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
- [OWASP: SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [MITRE ATT&CK T1219: Remote Access Software](https://attack.mitre.org/techniques/T1219/) 