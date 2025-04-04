## Overview

Detect when a web server processed HTTP requests with abnormally high response times. Excessively slow response times can indicate various issues including performance bottlenecks, resource contention, database problems, or potentially denial of service conditions. This detection identifies individual requests that exceed reasonable performance thresholds, which can help pinpoint specific problematic endpoints or transactions.

The detection focuses on identifying HTTP requests where:
- The response time exceeds a significant threshold (5 seconds)
- Individual requests show extreme latency, regardless of the overall system performance
- Specific transactions are experiencing performance degradation

Very slow requests may indicate:
- Inefficient code or database queries
- Resource contention issues (CPU, memory, disk I/O)
- External service dependencies that are slow or unresponsive
- DoS conditions targeting specific application functionality
- Misconfiguration in specific application components
- Network latency or connectivity issues

Identifying these outlier requests helps teams address performance bottlenecks and potential availability issues before they impact larger portions of the application.

**References**:
- [MITRE ATT&CK: Application Exhaustion Flood (T1499.003)](https://attack.mitre.org/techniques/T1499/003/)
- [OWASP: Denial of Service](https://owasp.org/www-community/attacks/Denial_of_Service)
- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
- [Web Performance Best Practices](https://web.dev/performance-get-started/)
- [Apache mod_reqtimeout: Request Timeout Configuration](https://httpd.apache.org/docs/2.4/mod/mod_reqtimeout.html) 