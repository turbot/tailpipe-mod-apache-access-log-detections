## Overview

Detect when a web server processed requests to endpoints with consistently high response times. Unlike the "Very Slow Request Detected" detection that identifies individual slow requests, this detection analyzes endpoint performance more holistically by examining the average and maximum response times for specific URIs over multiple requests. This approach helps identify chronically problematic endpoints that may need optimization, even if individual requests don't exceed extreme thresholds.

**References**:
- [OWASP: Security Performance Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/07-Test_Defenses_Against_Application_Misuse)
- [CWE-1005: Input Validation for Unexpected Parameter](https://cwe.mitre.org/data/definitions/1005.html)
- [Web Performance Optimization](https://web.dev/fast/) 