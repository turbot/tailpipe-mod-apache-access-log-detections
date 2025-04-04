## Overview

Detect when a web server experienced a high rate of HTTP errors within a time window. A sudden or sustained spike in error responses (HTTP 4xx and 5xx status codes) can indicate application problems, configuration issues, or potentially malicious activities such as scanning or attacks. This detection analyzes error rates over 5-minute windows to identify periods where error rates exceed normal thresholds.

The detection identifies time periods where:
- The total request volume exceeds a minimum threshold (10 requests)
- The error rate exceeds a significant threshold (10% of all requests)
- HTTP status codes in the 400-599 range occur at an abnormal frequency

High error rates may indicate:
- Application failures or bugs
- Server resource constraints
- Misconfiguration of services
- Ongoing scanning or probing attacks
- Active exploitation attempts against vulnerabilities
- Denial of service conditions

Monitoring error rates helps detect both operational issues and potential security incidents in progress, allowing for more rapid investigation and response.

**References**:
- [MITRE ATT&CK: Service Exhaustion Flood (T1499.002)](https://attack.mitre.org/techniques/T1499/002/)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
- [HTTP Status Codes](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status)
- [Apache HTTP Server: Logging Configuration](https://httpd.apache.org/docs/2.4/logs.html) 