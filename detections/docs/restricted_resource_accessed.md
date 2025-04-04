## Overview

Detect when a web server processed requests to restricted resources or administrative areas. Administrative interfaces, management consoles, and other sensitive areas of web applications should be protected from unauthorized access. Attempts to access these resources may indicate reconnaissance activities or active exploitation attempts targeting privileged functionality, which could lead to unauthorized administrative actions, privilege escalation, or complete system compromise.

**References**:
- [OWASP Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- [Apache HTTP Server: Securing Admin Interfaces](https://httpd.apache.org/docs/2.4/howto/auth.html) 