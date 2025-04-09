## Overview

Detect potentially malicious automation combined with SQL injection patterns in requests. This detection identifies a key attack signature: requests containing SQL injection patterns in the URL that are also made using suspicious or automated user agents. This correlation of factors significantly increases the likelihood that the request represents a deliberate attack rather than a false positive.

By combining both SQL injection patterns and suspicious user agents, this detection reduces false positives while focusing on requests with strong indicators of malicious intent. The combination of automation tools and SQL injection patterns is a hallmark of reconnaissance and targeted attacks - attackers frequently use specialized tools or scripts to automate SQL injection attempts, the presence of both factors significantly increases confidence in attack identification, and automated SQL injection attempts often precede more targeted manual exploitation.

This detection identifies multiple patterns that suggest automated SQL injection attempts, including SQL injection patterns (URL patterns containing SQL attack signatures like `UNION SELECT`, `SELECT FROM`, `1=1`, and metadata queries), known SQL injection tools (user agents from specialized SQL attack tools like SQLMap, Havij, and SQLNinja), generic automation tools (user agents from command-line tools and programming libraries commonly used for automation like Python, curl, wget), and suspicious user agent patterns (missing, empty, or highly generic user agents that deviate from legitimate browser patterns). Public-facing web applications with database backends, legacy applications that may not properly validate input, and applications with extensive query parameter functionality are particularly at risk from these types of attacks.

**References**:
- [OWASP Automated Threats to Web Applications](https://owasp.org/www-project-automated-threats-to-web-applications/)
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [MITRE ATT&CK: Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK: Gather Victim Host Information (T1592)](https://attack.mitre.org/techniques/T1592/) 