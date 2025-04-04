## Overview

Detect when a web server showed signs of connection pool exhaustion based on concurrent connections. Web servers typically maintain connection pools with maximum limits on concurrent connections. As these pools approach capacity, the server may start to reject new connections, leading to degraded performance and potential service outages. This detection identifies periods of high connection volume or abnormal rejection rates that may indicate impending resource exhaustion.

**References**:
- [OWASP: Denial of Service](https://owasp.org/www-community/attacks/Denial_of_Service)
- [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html)
- [HTTP Status Code 503: Service Unavailable](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/503)
- [Apache HTTP Server: Connection Handling](https://httpd.apache.org/docs/2.4/mod/core.html#maxconnectionsperchild) 