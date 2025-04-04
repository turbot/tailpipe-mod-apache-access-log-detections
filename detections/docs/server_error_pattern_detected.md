## Overview

Detect when a web server logged patterns in server-side errors (5xx). HTTP 5xx status codes indicate server-side problems that prevented the fulfillment of otherwise valid client requests. These errors often point to more serious underlying issues such as application crashes, resource constraints, or configuration problems. Analyzing the distribution and patterns of server errors can reveal important information about system health, potential vulnerabilities, and possible exploitation attempts.

**References**:
- [OWASP: Improper Error Handling](https://owasp.org/www-community/Improper_Error_Handling)
- [HTTP Status Code Definitions: 5xx Server Error](https://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html)
- [Apache HTTP Server: Handling Server Errors](https://httpd.apache.org/docs/2.4/misc/security_tips.html#serversidedata) 