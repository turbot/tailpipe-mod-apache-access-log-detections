## Overview

Detect attempts to exploit the Apache mod_status vulnerability (CVE-2014-3852) where server-status pages could expose sensitive information through cross-site scripting. This vulnerability affects Apache HTTP Server versions before 2.4.10 and occurs due to insufficient output escaping in the mod_status module's server-status pages. When exploited, attackers can inject malicious scripts into the status page output, potentially leading to information disclosure and session hijacking.

The vulnerability specifically relates to how mod_status handles certain HTML-special characters in URLs shown in the server-status output. By crafting specific URLs containing script tags or other malicious content, attackers can inject JavaScript code that executes in the context of the server-status page. This could allow attackers to steal sensitive information displayed in the status page, including server configuration details, active connections, and potentially internal network information.

**References**:
- [CVE-2014-3852](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3852)
- [Apache HTTP Server Security Advisory](https://httpd.apache.org/security/vulnerabilities_24.html)
- [OWASP Cross Site Scripting Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [MITRE ATT&CK - Collection: Data from Web Application](https://attack.mitre.org/techniques/T1213/) 