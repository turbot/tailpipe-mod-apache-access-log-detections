## Overview

Detect when a web server was targeted by SQL injection attempts. SQL injection is a code injection technique that exploits vulnerabilities in applications that process SQL queries, allowing attackers to manipulate database queries to access, modify, or delete data without proper authorization. These attacks can lead to unauthorized access to sensitive data, data breaches, and potentially complete compromise of affected databases and systems.

The detection identifies SQL-like syntax and patterns in URL requests that may indicate SQL injection attempts, such as:
- SELECT FROM patterns
- UNION SELECT patterns
- INSERT INTO patterns
- DELETE FROM patterns
- Common SQL injection test conditions like `OR 1=1`

**References**:
- [OWASP SQL Injection Guide](https://owasp.org/www-community/attacks/SQL_Injection)
- [MITRE ATT&CK: Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/)
- [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [Apache Web Server Security Best Practices](https://httpd.apache.org/docs/2.4/misc/security_tips.html) 