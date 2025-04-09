## Overview

Detect when a web server received requests with known malicious user agents. The User-Agent HTTP header identifies the client application, operating system, vendor, or version of the requesting user agent. Many penetration testing tools, vulnerability scanners, and malicious bots use distinctive user-agent strings that can be identified. These tools are often used for reconnaissance activities prior to more targeted attacks or as part of active exploitation attempts.

User-Agent analysis provides valuable early warning of potential attacks - specialized security tools leave distinctive fingerprints in their user agent strings, reconnaissance typically precedes targeted attacks (providing an opportunity for early detection), and identifying scanning activities allows security teams to preemptively strengthen defenses.

This detection identifies multiple categories of potentially malicious tools, including vulnerability scanners (tools like Nikto, Nessus, and Acunetix designed to identify security weaknesses), penetration testing tools (frameworks like SQLMap, Metasploit, and BurpSuite used for security testing), network scanning tools (port scanners and network mappers like Nmap and Masscan), directory enumeration tools (tools like Dirbuster and Gobuster that attempt to find hidden resources), password cracking tools (authentication attack tools like Hydra), and missing user-agents (null or empty user agents that may indicate deliberate header manipulation). Public-facing web applications and APIs, administrative interfaces accessible from public networks, and legacy applications that may contain undiscovered vulnerabilities are particularly at risk from these types of reconnaissance activities.

**References**:
- [OWASP Automated Threat Handbook](https://owasp.org/www-project-automated-threats-to-web-applications/)
- [User Agent Strings - Web Application Security Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [MITRE ATT&CK: Gather Victim Host Information (T1592)](https://attack.mitre.org/techniques/T1592/)