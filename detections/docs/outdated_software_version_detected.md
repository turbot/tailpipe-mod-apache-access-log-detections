## Overview

Detect requests to or from outdated software versions that may contain known security vulnerabilities. Outdated software versions often contain known security vulnerabilities that have been patched in newer releases. This detection identifies requests that appear to be using or targeting deprecated versions of common web technologies, including browsers, content management systems, and libraries. Monitoring for outdated software usage helps identify potential security gaps in an organization's technology ecosystem and can help prioritize upgrades or additional security controls to mitigate risks posed by legacy systems that cannot be immediately updated.

**References**:
- [CWE-1104: Use of Unmaintained Third Party Components](https://cwe.mitre.org/data/definitions/1104.html)
- [OWASP: A06:2021-Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)
- [CISA: Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [MITRE ATT&CK T1592: Gather Victim Host Information](https://attack.mitre.org/techniques/T1592/) 