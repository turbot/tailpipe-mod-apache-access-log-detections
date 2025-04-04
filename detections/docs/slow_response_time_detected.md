## Overview

Detect when a web server processed requests to endpoints with consistently high response times. Unlike the "Very Slow Request Detected" detection that identifies individual slow requests, this detection analyzes endpoint performance more holistically by examining the average and maximum response times for specific URIs over multiple requests. This approach helps identify chronically problematic endpoints that may need optimization, even if individual requests don't exceed extreme thresholds.

The detection identifies endpoints where:
- Multiple requests have been processed (minimum of 5 requests)
- The average response time exceeds a significant threshold (1 second)
- OR the maximum response time exceeds a higher threshold (3 seconds)
- Performance issues appear to be endpoint-specific rather than system-wide

Consistently slow response times may indicate:
- Inefficient database queries associated with specific endpoints
- N+1 query problems or other code inefficiencies
- Resource-intensive operations that may need optimization
- Missing indexes or caching opportunities
- Endpoints that handle larger data volumes
- Backend service dependencies that are consistently slow

Identifying chronically slow endpoints helps prioritize performance optimization efforts and avoid gradual service degradation over time.

**References**:
- [OWASP: Security Performance Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/07-Test_Defenses_Against_Application_Misuse)
- [CWE-1005: Input Validation for Unexpected Parameter](https://cwe.mitre.org/data/definitions/1005.html)
- [Web Performance Optimization](https://web.dev/fast/) 