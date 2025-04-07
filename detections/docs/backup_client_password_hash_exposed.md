## Overview

Detect when a backup client exposes password hashes in cleartext. This detection focuses on identifying potential password hash exposure vulnerabilities, particularly the EMC Dantz Retrospect Backup Client vulnerability (CVE-2008-3289) where password hashes were transmitted without encryption. When password hashes are transmitted in cleartext, they can be intercepted by attackers and used for offline password cracking attempts, potentially leading to unauthorized access to backup systems and protected data.

**References**:
- [CVE-2008-3289](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-3289)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [CWE-256: Unprotected Storage of Credentials](https://cwe.mitre.org/data/definitions/256.html)
