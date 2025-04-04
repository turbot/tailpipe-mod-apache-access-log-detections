## Overview

Detect when a web server received requests with missing user agent headers. The User-Agent HTTP header field normally contains information about the client application, operating system, vendor, or version making the request. When this header is missing, empty, or explicitly nullified, it often indicates automated tools, scripts, or potential security scanning activities rather than legitimate user browser traffic.

The detection identifies requests where the user agent header is:
- Completely absent (null)
- Empty strings ('')
- Placeholder values ('-')

Missing user agent headers may indicate:
- Automated scanning tools or scripts
- Custom attack tools that don't properly emulate browsers
- Deliberate attempts to avoid detection by not presenting identifying information
- Reconnaissance activities prior to targeted attacks

While some legitimate scripts and API clients might not include user agent headers, a pattern of requests without this information can be a signal of potentially suspicious activity that warrants investigation.

**References**:
- [OWASP Web Security Testing Guide: Fingerprint Web Server](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Discovery_Reconnaissance_for_Information_Leakage)
- [RFC 7231: User-Agent](https://tools.ietf.org/html/rfc7231#section-5.5.3)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [Apache ModSecurity: User Agent Filtering](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-(v2.x)#useragent) 