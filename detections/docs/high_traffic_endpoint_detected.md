## Overview

Detect when a web server handled unusually high traffic volumes to specific endpoints. Some endpoints naturally receive more traffic than others, but identifying the highest-traffic URIs helps pinpoint resource consumption patterns, application hot spots, and potential areas for optimization. This detection ranks endpoints by request volume to help identify where traffic is concentrated within the application.

**References**:
- [OWASP: Denial of Service](https://owasp.org/www-community/attacks/Denial_of_Service)
- [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html)