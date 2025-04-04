## Overview

Detect when a web server was targeted by directory traversal attempts. Directory traversal (also known as path traversal) is an attack that aims to access files and directories stored outside the web root folder by manipulating variables that reference files with "dot-dot-slash (../)" sequences and variations. By using this technique, attackers can access arbitrary files and directories stored on the file system, including application source code, configuration files, and critical system files.

The detection identifies various directory traversal patterns in URL requests, including:
- Plain traversal sequences (`../`, `/../`, `/./`)
- URL-encoded variants (`%2e%2e%2f`, `%2E%2E%2F`)
- Double-encoded traversal attempts
- Other path manipulation techniques

These patterns are strong indicators of reconnaissance activities or active exploitation attempts to gain unauthorized access to sensitive resources.

**References**:
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [Apache Security Tips: Directory Protection](https://httpd.apache.org/docs/2.4/misc/security_tips.html#directoryprotection)