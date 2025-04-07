## Overview

Detect attempts to exploit the Cisco IOS HTTP Server vulnerability (CVE-2005-1205) where malformed HTTP requests could trigger a denial of service condition. This vulnerability affects various versions of Cisco IOS and occurs due to improper handling of malformed HTTP requests by the HTTP server component, allowing attackers to cause a device reload. When exploited, attackers can send specially crafted HTTP requests that cause the affected device to crash and reload, resulting in a denial of service condition.

The vulnerability specifically relates to how the Cisco IOS HTTP Server processes malformed HTTP requests. By sending requests containing null bytes, non-printable characters, invalid UTF-8 sequences, or unusually long URIs, attackers can trigger a buffer overflow condition that causes the device to reload. This could lead to service disruption, loss of network connectivity, and potential exposure of sensitive information in crash dumps.

**References**:
- [CVE-2005-1205](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-1205)
- [Cisco Security Advisory](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20050411-http)
- [OWASP Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
- [CWE-730: OWASP Top Ten 2004 Category A9 - Denial of Service](https://cwe.mitre.org/data/definitions/730.html)
- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
- [MITRE ATT&CK - Impact: Endpoint Denial of Service](https://attack.mitre.org/techniques/T1499/) 