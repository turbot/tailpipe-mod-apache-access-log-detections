## Overview

Detect when a web server processed requests for large static files. While serving static content is a normal function of web servers, unusually large static file transfers can impact server performance, consume significant bandwidth, and potentially indicate content distribution issues or attempts to cause resource exhaustion. This detection identifies requests for large static files such as images, videos, documents, and archives that exceed typical size thresholds.

**References**:
- [OWASP Performance Testing Guidance](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/07-Test_Defenses_Against_Application_Misuse)
- [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html)
- [Web Content Optimization Best Practices](https://developers.google.com/speed/docs/insights/OptimizeImages)
- [Apache HTTP Server: Content Negotiation](https://httpd.apache.org/docs/2.4/content-negotiation.html) 