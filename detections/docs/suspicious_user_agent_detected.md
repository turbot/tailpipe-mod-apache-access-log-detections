## Overview

Detect when a web server received requests with known malicious user agents. The User-Agent HTTP header identifies the client application, operating system, vendor, or version of the requesting user agent. Many penetration testing tools, vulnerability scanners, and malicious bots use distinctive user-agent strings that can be identified. These tools are often used for reconnaissance activities prior to more targeted attacks or as part of active exploitation attempts.

**References**:
- [OWASP Automated Threat Handbook](https://owasp.org/www-project-automated-threats-to-web-applications/)
- [User Agent Strings - Web Application Security Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)