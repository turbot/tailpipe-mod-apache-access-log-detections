## Overview

Detect when a web server received potential web shell upload or access attempts. Web shells are malicious scripts uploaded to a web server that provide an attacker with a convenient interface to remotely access and control the compromised server. Once uploaded, web shells can be used for a variety of malicious activities including file manipulation, credential theft, lateral movement, and launching additional attacks from the compromised server.

**References**:
- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [Apache Security: Preventing Unauthorized Access](https://httpd.apache.org/docs/2.4/misc/security_tips.html#serverroot) 