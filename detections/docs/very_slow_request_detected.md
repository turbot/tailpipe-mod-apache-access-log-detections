## Overview

Detect when a web server processed HTTP requests with abnormally high response times. Excessively slow response times can indicate various issues including performance bottlenecks, resource contention, database problems, or potentially denial of service conditions. This detection identifies individual requests that exceed reasonable performance thresholds, which can help pinpoint specific problematic endpoints or transactions.

**References**:
- [OWASP: Denial of Service](https://owasp.org/www-community/attacks/Denial_of_Service)
- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
- [Web Performance Best Practices](https://web.dev/performance-get-started/)
- [Apache mod_reqtimeout: Request Timeout Configuration](https://httpd.apache.org/docs/2.4/mod/mod_reqtimeout.html) 