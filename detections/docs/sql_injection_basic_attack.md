## Overview

Detect basic SQL injection attempts targeting common SQL keywords and syntax patterns. Basic SQL injection exploits insufficient input validation to inject malicious SQL statements by inserting SQL keywords and operators. These attacks target fundamental SQL syntax elements like SELECT, INSERT, UPDATE, DELETE statements to manipulate database queries, potentially leading to unauthorized data access, data theft, or complete database compromise.

This detection identifies common SQL command patterns (SELECT, INSERT, DELETE, UPDATE), basic SQL injection techniques (OR 1=1), and SQL comment markers used to bypass security controls.

**References**:
- [OWASP SQL Injection Guide](https://owasp.org/www-community/attacks/SQL_Injection)
- [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [MITRE ATT&CK: Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/)