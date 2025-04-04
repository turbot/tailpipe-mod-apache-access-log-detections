## Overview

Detect when a web server handled unusually high traffic volumes to specific endpoints. Some endpoints naturally receive more traffic than others, but identifying the highest-traffic URIs helps pinpoint resource consumption patterns, application hot spots, and potential areas for optimization. This detection ranks endpoints by request volume to help identify where traffic is concentrated within the application.

The detection identifies high traffic patterns by:
- Analyzing request counts for each unique URI path
- Calculating what percentage of overall traffic each endpoint receives
- Identifying endpoints that exceed a minimum request threshold (10 requests)
- Ranking endpoints based on traffic volume

High traffic endpoints may indicate:
- Popular application features that may need additional optimization
- Potential candidates for caching or CDN delivery
- Resource-intensive operations that could benefit from scaling
- Endpoints that might be targets for rate limiting
- Traffic patterns that could inform architectural decisions
- Potential scanning or enumeration activities if traffic is unexpected

Understanding traffic distribution helps prioritize performance optimization efforts and can highlight unexpected usage patterns that warrant investigation.

**References**:
- [MITRE ATT&CK: Service Exhaustion Flood (T1499.002)](https://attack.mitre.org/techniques/T1499/002/)
- [MITRE ATT&CK: Direct Network Flood (T1498.001)](https://attack.mitre.org/techniques/T1498/001/)
- [OWASP: Denial of Service](https://owasp.org/www-community/attacks/Denial_of_Service)
- [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html)
- [Web Application Scalability Best Practices](https://aws.amazon.com/blogs/architecture/web-application-scaling-best-practices/) 