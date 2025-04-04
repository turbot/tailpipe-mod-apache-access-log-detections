## Overview

Detect when a web server received requests for sensitive files or directories. Attackers often probe web servers for configuration files, backup files, or other sensitive resources that might have been inadvertently exposed. These files can contain valuable information such as database credentials, API keys, internal network details, or application source code that could be leveraged for deeper compromises.

The detection identifies requests for several categories of potentially sensitive files and directories:
- Configuration files (`.conf`, `.config`, `web.xml`)
- System files (`/etc/`)
- Environment files (`.env`)
- Source code repositories (`.git/`)
- Database files (`.sql`)
- Backup files (`backup`, `dump`)
- Web server specific files (`httpd.conf`, `.htpasswd`, `.htaccess`)
- Server status and information pages (`/server-status`, `/server-info`)

Unauthorized access to these resources can lead to information disclosure, credential theft, privilege escalation, and further exploitation of the system.

**References**:
- [MITRE ATT&CK: File and Directory Discovery (T1083)](https://attack.mitre.org/techniques/T1083/)
- [OWASP Sensitive Data Exposure](https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure)
- [CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)
- [Apache Security: Securing Files](https://httpd.apache.org/docs/2.4/misc/security_tips.html#protectserverfiles)
- [Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) 