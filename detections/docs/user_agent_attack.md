## Overview

Detect when a web server received requests with attack patterns in the User-Agent header. The User-Agent header is normally used to identify the client application, operating system, and browser version. However, attackers can manipulate this header to carry various attack payloads, including SQL injection, local file inclusion (LFI), cross-site scripting (XSS), and command injection patterns.

This detection identifies a broad range of attack signatures in User-Agent headers, spanning multiple attack vectors in a single comprehensive rule. The User-Agent header represents an often-overlooked attack vector - many applications log User-Agent values but don't properly sanitize them before processing, backend systems may perform operations on User-Agent data without adequate input validation, and User-Agent manipulation is a common technique to bypass security controls focused on standard parameters.

The detection monitors for multiple attack categories in User-Agent headers, including SQL Injection attempts to exploit database vulnerabilities through SQL commands, Local File Inclusion (LFI) attempts to access files outside the web root using path traversal, Cross-Site Scripting (XSS) attempts to inject client-side code through script tags and event handlers, and OS Command Injection attempts to execute system commands via shell metacharacters. Web applications that log and display User-Agent data without proper sanitization, analytics systems that process User-Agent strings in database operations, and logging systems that don't properly escape User-Agent values are particularly vulnerable to these attacks.

**References**:
- [OWASP HTTP Header Manipulation](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution)
- [OWASP User Agent Attack Surface](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [MITRE ATT&CK: Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/) 