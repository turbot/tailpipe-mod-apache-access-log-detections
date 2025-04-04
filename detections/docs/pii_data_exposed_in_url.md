## Overview

Detect when a web server logged Personally Identifiable Information (PII) in URLs. PII is any data that could potentially identify a specific individual, such as Social Security numbers, credit card numbers, email addresses, phone numbers, and passwords. Including this sensitive information in URLs is a significant privacy and security risk as URLs are commonly logged in server logs, browser history, and proxy servers, and can be exposed in referrer headers when users navigate between sites.

The detection identifies several types of PII that may be exposed in URL requests:
- Social Security Numbers (SSN) with pattern 123-45-6789
- Credit card numbers (16-digit sequences)
- Email addresses
- Passwords or password parameters
- Phone numbers (10-digit sequences)

Exposing PII in URLs violates data privacy best practices and potentially regulatory requirements such as GDPR, CCPA, and PCI-DSS. This exposure creates risk of identity theft, financial fraud, and privacy violations for users whose information is compromised.

**References**:
- [OWASP: Information Exposure Through Query Strings in URL](https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url)
- [CWE-598: Use of GET Request Method With Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html)
- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [GDPR: Personal Data Protection](https://gdpr-info.eu/issues/personal-data/)
- [PCI DSS: Requirements for Protecting Cardholder Data](https://www.pcisecuritystandards.org/) 