## Overview

Detect when a web server logged patterns in server-side errors (5xx). HTTP 5xx status codes indicate server-side problems that prevented the fulfillment of otherwise valid client requests. These errors often point to more serious underlying issues such as application crashes, resource constraints, or configuration problems. Analyzing the distribution and patterns of server errors can reveal important information about system health, potential vulnerabilities, and possible exploitation attempts.

The detection analyzes server-side error patterns by:
- Aggregating HTTP status codes in the 500-599 range
- Identifying the most frequent server error codes
- Determining the relative percentage of each error type
- Finding the most common URIs associated with each error type

Server error patterns may indicate:
- Application code failures (500 Internal Server Error)
- Gateway or proxy issues (502 Bad Gateway, 504 Gateway Timeout)
- Server overload conditions (503 Service Unavailable)
- Potential exploitation attempts triggering application crashes
- Infrastructure or configuration problems
- Deployment issues with new code

Understanding server error patterns is critical for maintaining application availability, performance, and security.

**References**:
- [OWASP: Improper Error Handling](https://owasp.org/www-community/Improper_Error_Handling)
- [HTTP Status Code Definitions: 5xx Server Error](https://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html)
- [Apache HTTP Server: Handling Server Errors](https://httpd.apache.org/docs/2.4/misc/security_tips.html#serversidedata) 