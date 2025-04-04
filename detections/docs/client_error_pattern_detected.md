## Overview

Detect when a web server logged patterns in client-side errors (4xx). HTTP 4xx status codes indicate that the client's request contains errors or cannot be fulfilled for client-specific reasons, such as authentication failures, resource not found, or invalid data. Analyzing the distribution and patterns of these client errors can reveal important information about potential client issues, scanning activities, or targeted attacks against the web application.

The detection analyzes client-side error patterns by:
- Aggregating HTTP status codes in the 400-499 range
- Identifying the most frequent client error codes
- Determining the relative percentage of each error type
- Finding the most common URIs associated with each error type

Client error patterns may indicate:
- Authentication problems (401, 403 errors)
- Scanning or enumeration activities (many 404 errors)
- Deprecated or changed API endpoints (410 errors)
- Clients submitting malformed requests (400 errors)
- Reconnaissance prior to targeted attacks
- Broken links or outdated documentation

Understanding client error patterns helps identify both operational issues and potential security threats, allowing for proactive mitigation.

**References**:

- [OWASP: Failure to Restrict URL Access](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema)
- [CWE-352: Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html) 