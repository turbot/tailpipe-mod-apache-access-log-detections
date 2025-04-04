## Overview

Detect when a web server processed requests to specific endpoints with unusually high error rates. While the previous "High Error Rate" detection focuses on overall server error patterns, this detection examines error rates at the individual endpoint level. This allows for the identification of specific problematic URLs, API endpoints, or resources that may be experiencing issues even when the overall system appears healthy.

**References**:
- [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2019/en/0xa9-improper-assets-management/)
- [CWE-754: Improper Check for Unusual or Exceptional Conditions](https://cwe.mitre.org/data/definitions/754.html)