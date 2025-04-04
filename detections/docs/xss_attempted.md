## Overview

Detect when a web server was targeted by cross-site scripting (XSS) attacks. Cross-Site Scripting is a type of security vulnerability typically found in web applications that allows attackers to inject client-side scripts into web pages viewed by other users. XSS enables attackers to bypass same-origin policy, allowing them to steal sensitive information like session tokens and cookies, or to perform actions impersonating the victim, potentially leading to account takeover or data theft.

**References**:
- [OWASP Cross Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)
- [MITRE ATT&CK: Command and Scripting Interpreter: JavaScript (T1059.007)](https://attack.mitre.org/techniques/T1059/007/)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [XSS Filter Evasion Cheat Sheet](https://owasp.org/www-community/xss-filter-evasion-cheatsheet) 