## Overview

Detect when a web server processed requests to specific endpoints with unusually high error rates. While the previous "High Error Rate" detection focuses on overall server error patterns, this detection examines error rates at the individual endpoint level. This allows for the identification of specific problematic URLs, API endpoints, or resources that may be experiencing issues even when the overall system appears healthy.

The detection identifies endpoints where:
- The total request volume exceeds a minimum threshold (5 requests)
- The error rate exceeds a significant threshold (10% of all requests to that endpoint)
- HTTP status codes in the 400-599 range occur at an abnormal frequency for specific URIs

High error rates on specific endpoints may indicate:
- Broken functionality or bugs in specific application components
- Targeted attacks against vulnerable endpoints
- API versioning or compatibility issues
- Permission/authorization problems for specific resources
- Configuration issues affecting particular application areas

This granular approach helps identify localized issues that might be missed when looking at overall system metrics, enabling more targeted troubleshooting and security response.

**References**:
- [MITRE ATT&CK: Service Exhaustion Flood (T1499.002)](https://attack.mitre.org/techniques/T1499/002/)
- [MITRE ATT&CK: Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/)
- [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2019/en/0xa9-improper-assets-management/)
- [CWE-754: Improper Check for Unusual or Exceptional Conditions](https://cwe.mitre.org/data/definitions/754.html)
- [Microservice Architecture and Security](https://www.nginx.com/blog/microservices-security-challenge/) 