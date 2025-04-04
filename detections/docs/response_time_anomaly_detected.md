## Overview

Detect when a web server experienced sudden increases in response time compared to historical patterns. This detection focuses on identifying temporal anomalies in performance metrics by comparing current response times to a rolling historical average. Unlike the previous performance detections that examine absolute thresholds, this approach identifies relative degradations in performance that might otherwise go unnoticed.

**References**:
- [OWASP: Application Performance Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/07-Test_Defenses_Against_Application_Misuse)
- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)