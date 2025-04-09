## Overview

Detect when a web server received requests attempting to access log files, which could indicate reconnaissance for sensitive information or attempts to cover tracks. Log files often contain sensitive information including authentication attempts, user activities, system behaviors, and in some cases, sensitive data like session tokens or credentials. Unauthorized access to logs can expose this information and help attackers plan further attacks by revealing system architecture, user accounts, or security controls. Additionally, attackers may attempt to access logs to determine if their activities have been recorded or to gather intelligence for more targeted attacks.

**References**:
- [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)
- [CWE-552: Files or Directories Accessible to External Parties](https://cwe.mitre.org/data/definitions/552.html)
- [OWASP: Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [MITRE ATT&CK T1005: Data from Local System](https://attack.mitre.org/techniques/T1005/) 