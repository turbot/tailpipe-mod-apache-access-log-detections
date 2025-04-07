## Overview

Detect when a web server processed requests that may expose network device configuration data. This detection focuses on identifying potential configuration data exposure vulnerabilities, particularly the Cisco IOS vulnerability (CVE-2001-1546) where SNMP community strings could be obtained through TFTP configuration files. When network device configurations are exposed, attackers can obtain sensitive information such as SNMP community strings, passwords, access control lists, and routing information that could be used to compromise network security.

**References**:
- [CVE-2001-1546](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2001-1546)
- [OWASP Network Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration)
- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)