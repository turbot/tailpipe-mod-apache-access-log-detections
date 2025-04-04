## Overview

Detect when a web server logged Personally Identifiable Information (PII) in URLs. PII is any data that could potentially identify a specific individual, such as Social Security numbers, credit card numbers, email addresses, phone numbers, and passwords. Including this sensitive information in URLs is a significant privacy and security risk as URLs are commonly logged in server logs, browser history, and proxy servers, and can be exposed in referrer headers when users navigate between sites.

**References**:
- [OWASP: Information Exposure Through Query Strings in URL](https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url)
- [CWE-598: Use of GET Request Method With Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html)
- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [GDPR: Personal Data Protection](https://gdpr-info.eu/issues/personal-data/)
- [PCI DSS: Requirements for Protecting Cardholder Data](https://www.pcisecuritystandards.org/) 