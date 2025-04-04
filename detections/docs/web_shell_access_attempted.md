## Overview

Detect when a web server received potential web shell upload or access attempts. Web shells are malicious scripts uploaded to a web server that provide an attacker with a convenient interface to remotely access and control the compromised server. Once uploaded, web shells can be used for a variety of malicious activities including file manipulation, credential theft, lateral movement, and launching additional attacks from the compromised server.

The detection identifies patterns associated with web shell access and uploads, including:
- Requests to common web shell file extensions (.php, .jsp, .asp, .aspx, .cfm)
- Requests containing known web shell indicators in the URL (shell, cmd, command)
- Access to known web shell variants (c99, r57)
- Suspicious combinations of methods (POST/PUT) and URL patterns
- Successful responses to potentially malicious requests

Web shells represent a significant security risk as they provide attackers with persistent access to compromised systems and can be used as a staging point for further attacks within the network.

**References**:
- [MITRE ATT&CK: Web Shell (T1505.003)](https://attack.mitre.org/techniques/T1505/003/)
- [CISA Web Shell Malware Alert](https://www.cisa.gov/news-events/alerts/2021/04/15/nsa-cisa-joint-advisory-detecting-and-preventing-web-shell-malware)
- [Understanding Web Shells](https://owasp.org/www-community/attacks/Web_Shell)
- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [Apache Security: Preventing Unauthorized Access](https://httpd.apache.org/docs/2.4/misc/security_tips.html#serverroot) 