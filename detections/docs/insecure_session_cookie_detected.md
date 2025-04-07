## Overview

Detect when a web server processes requests that may expose session cookies over insecure channels. This detection focuses on identifying potential session cookie exposure vulnerabilities, particularly the Joomla! vulnerability (CVE-2008-4122) where session cookies were not set with the secure flag during HTTPS sessions. When session cookies are transmitted over non-HTTPS connections or lack proper security flags, they can be intercepted by attackers, leading to session hijacking and unauthorized access to user accounts.

**References**:
- [CVE-2008-4122](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4122)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html)
- [CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)
