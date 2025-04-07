## Overview

Detect attempts to exploit the ILIAS SCORM debugger local file inclusion vulnerability (CVE-2022-45918). This vulnerability affects ILIAS eLearning platform versions before 7.16 and occurs due to insufficient validation of file paths in the SCORM debugger component.

The vulnerability specifically relates to how the SCORM debugger handles log file access. The debugger allows authors to view logs of previous SCORM player sessions, but fails to validate the requested file path specified in the `logFile` parameter. By manipulating this parameter with directory traversal sequences such as `../`, attackers can access arbitrary files on the server's filesystem, potentially revealing sensitive configuration files, credentials, or other private information.

**References**:
- [CVE-2022-45918](https://www.cve.org/CVERecord?id=CVE-2022-45918)
- [SEC Consult Advisory](https://seclists.org/fulldisclosure/2022/Dec/7)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html) 