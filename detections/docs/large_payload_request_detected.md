## Overview

Detect when a web server processed requests with unusually large body sizes. While legitimate applications may sometimes transfer large files, an unusually large HTTP payload can indicate potential file uploads, data exfiltration attempts, or attempts to consume server resources. This detection helps identify abnormal data transfer patterns that could represent security risks or operational issues.

**References**:
- [OWASP Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [Apache HTTP Server: Limiting Request Body](https://httpd.apache.org/docs/2.4/mod/core.html#limitrequestbody) 