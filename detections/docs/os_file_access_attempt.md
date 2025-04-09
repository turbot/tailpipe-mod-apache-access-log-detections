## Overview

Detect when a web server received requests attempting to access common operating system files. This detection focuses on identifying attempts to access sensitive system files that should never be accessible through a web application, which may indicate Local File Inclusion (LFI) vulnerabilities or other file disclosure attacks.

Attackers target operating system files including Unix/Linux system files (such as `/etc/passwd`, `/etc/shadow`, `/etc/hosts`, `/etc/issue`, `/proc/self/`, `/proc/version`, `/var/log/`), Windows system files (such as `win.ini`, `system32`, `boot.ini`, `windows/system.ini`, `autoexec.bat`, `config.sys`), and common web server configuration files (such as `/usr/local/apache`, `/usr/local/etc/httpd`, `/var/www/`, `/var/apache`). 

Successful exploitation can lead to disclosure of sensitive system information, including usernames, system configuration, and potentially even password hashes. Attackers use this information for reconnaissance and to plan further attacks. When this detection triggers, security teams should verify if the access attempt was successful (checking for 200 OK responses rather than 404 errors), analyze which system files were targeted, implement proper web server configuration to block access to system directories, configure web application firewalls to block common LFI patterns, validate and sanitize all file path inputs in the application, and review the application for file inclusion vulnerabilities. Some legitimate scenarios that may trigger this detection include system administration tools operating through web interfaces, monitoring and logging applications that need access to system files, and authorized system information display pages.

**References**:
- [OWASP: Testing for Local File Inclusion](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [Path Traversal Prevention](https://cheatsheetseries.owasp.org/cheatsheets/File_System_Security_Cheat_Sheet.html)
- [MITRE ATT&CK: File and Directory Discovery (T1083)](https://attack.mitre.org/techniques/T1083/) 