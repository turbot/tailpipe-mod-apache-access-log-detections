## Overview

Detect attempts to access cloud provider metadata services, which are common targets in SSRF attacks. Cloud metadata endpoints provide sensitive information about cloud instances including credentials, network configurations, and user data. These services are often targeted in SSRF attacks to gain access to cloud credentials and escalate privileges. This detection identifies requests attempting to access these sensitive endpoints for major cloud providers including AWS, GCP, Azure, and DigitalOcean. Unauthorized access to cloud metadata can lead to lateral movement within cloud environments, data breaches, and complete compromise of cloud infrastructure.

**References**:
- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
- [OWASP: A10:2021-Server-Side Request Forgery](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
- [AWS: Protecting the Instance Metadata Service](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [MITRE ATT&CK T1557: Man-in-the-Middle](https://attack.mitre.org/techniques/T1557/) 