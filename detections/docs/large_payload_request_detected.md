## Overview

Detect when a web server processed requests with unusually large body sizes. While legitimate applications may sometimes transfer large files, an unusually large HTTP payload can indicate potential file uploads, data exfiltration attempts, or attempts to consume server resources. This detection helps identify abnormal data transfer patterns that could represent security risks or operational issues.

The detection identifies HTTP requests where the body size exceeds a significant threshold (10MB), which may indicate:
- Unauthorized file uploads (particularly executables or malicious content)
- Data exfiltration attempts where sensitive information is being extracted
- Denial of service attempts aimed at consuming server bandwidth or storage
- Misconfigured applications sending excessive data
- Potential abuse of file upload functionality

Monitoring large payload transfers is important for preventing unauthorized data transfers, protecting server resources, and identifying potential security incidents.

**References**:
- [MITRE ATT&CK: Data from Cloud Storage Object (T1530)](https://attack.mitre.org/techniques/T1530/)
- [MITRE ATT&CK: Exfiltration Over Alternative Protocol (T1048)](https://attack.mitre.org/techniques/T1048/)
- [OWASP Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [Apache HTTP Server: Limiting Request Body](https://httpd.apache.org/docs/2.4/mod/core.html#limitrequestbody) 