## Overview

Detect when a web server returned HTTP 500 Internal Server Error responses. A 500 Internal Server Error is a generic error message indicating that the server encountered an unexpected condition that prevented it from fulfilling the request. These errors typically indicate server-side problems such as application crashes, unhandled exceptions, misconfiguration, or resource constraints. Monitoring for 500 errors is critical for maintaining application reliability and identifying potential security issues.

**References**:
- [OWASP: Improper Error Handling](https://owasp.org/www-community/Improper_Error_Handling)
- [CWE-388: Error Handling](https://cwe.mitre.org/data/definitions/388.html)
- [HTTP Status Code 500: Internal Server Error](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/500)
- [Apache HTTP Server: Debugging Server Errors](https://httpd.apache.org/docs/2.4/misc/security_tips.html#serversidedata) 