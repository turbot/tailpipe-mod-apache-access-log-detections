## Overview

Detect when a web server returned HTTP 408 Request Timeout or 504 Gateway Timeout errors. Timeout errors occur when a request takes too long to complete, either due to client delays in sending the complete request (408) or when a gateway or proxy server does not receive a timely response from an upstream server (504). These errors can indicate resource constraints, server overload, network issues, or problems with dependent services.

The detection identifies HTTP requests where:
- HTTP status code 408 (Request Timeout) is returned, indicating client-side delays
- HTTP status code 504 (Gateway Timeout) is returned, indicating upstream server delays
- Either timeout condition indicates potential service disruption

Request timeout errors may indicate:
- Server resource constraints (CPU, memory, connections)
- Network latency or connectivity issues
- Overloaded upstream services or dependencies
- Database query timeouts
- Long-running processes consuming server resources
- Partial denial of service conditions
- Misconfigured timeout settings

Identifying timeout patterns helps diagnose performance bottlenecks, infrastructure issues, and potential security concerns before they escalate to complete service outages.

**References**:
- [HTTP Status Code 408: Request Timeout](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/408)
- [HTTP Status Code 504: Gateway Timeout](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/504)
- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
- [Apache mod_reqtimeout: Request Timeout Configuration](https://httpd.apache.org/docs/2.4/mod/mod_reqtimeout.html)
- [Apache mod_proxy: Timeout Configuration](https://httpd.apache.org/docs/2.4/mod/mod_proxy.html) 