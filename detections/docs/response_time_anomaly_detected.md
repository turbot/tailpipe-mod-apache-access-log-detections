## Overview

Detect when a web server experienced sudden increases in response time compared to historical patterns. This detection focuses on identifying temporal anomalies in performance metrics by comparing current response times to a rolling historical average. Unlike the previous performance detections that examine absolute thresholds, this approach identifies relative degradations in performance that might otherwise go unnoticed.

The detection identifies performance anomalies by:
- Analyzing average response times across 5-minute intervals
- Comparing current performance to a rolling historical average from previous time periods
- Identifying periods where response times increase significantly (50% or more) from baseline
- Filtering out normal fluctuations by requiring a minimum historical baseline

Response time anomalies may indicate:
- Gradual service degradation that hasn't yet reached critical levels
- Infrastructure changes impacting performance
- Database slowdowns or growing query complexity
- Memory leaks or resource consumption issues
- New code deployments with unexpected performance impacts
- Periodic batch processes affecting overall system performance
- Early indicators of denial of service conditions

Detecting these relative changes in performance helps identify issues before they reach critical thresholds and impact user experience.

**References**:
- [MITRE ATT&CK: Application Exhaustion Flood (T1499.003)](https://attack.mitre.org/techniques/T1499/003/)
- [MITRE ATT&CK: Compute Hijacking (T1496.001)](https://attack.mitre.org/techniques/T1496/001/)
- [OWASP: Application Performance Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/07-Test_Defenses_Against_Application_Misuse)
- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
- [Time Series Anomaly Detection](https://medium.com/towards-artificial-intelligence/time-series-anomaly-detection-using-lstm-encoder-decoder-models-a1c4bd8d97e1) 