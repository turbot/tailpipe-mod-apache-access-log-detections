## Overview

Detect attempts to access known vulnerable components or exploit specific CVEs through web requests. Attackers often target known vulnerabilities in web components such as frameworks, libraries, and applications. This detection identifies requests that attempt to exploit specific known vulnerabilities in common web frameworks and applications, including Log4j/Log4Shell, Spring4Shell, Apache Struts, and content management systems like WordPress and Drupal. Early detection of these exploitation attempts is crucial as these vulnerabilities can lead to remote code execution, data breaches, and complete system compromise.

**References**:
- [CWE-1104: Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html)
- [OWASP: A06:2021-Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)
- [NIST: Vulnerability Management](https://csrc.nist.gov/Projects/vulnerability-management)
- [MITRE ATT&CK T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) 