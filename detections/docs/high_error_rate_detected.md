## Overview

Detect when a web server experienced a high rate of HTTP errors within a time window. A sudden or sustained spike in error responses (HTTP 4xx and 5xx status codes) can indicate application problems, configuration issues, or potentially malicious activities such as scanning or attacks. This detection analyzes error rates over 5-minute windows to identify periods where error rates exceed normal thresholds.

**References**:
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
- [HTTP Status Codes](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status)
- [Apache HTTP Server: Logging Configuration](https://httpd.apache.org/docs/2.4/logs.html) 