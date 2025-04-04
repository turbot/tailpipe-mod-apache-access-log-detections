## Overview

Detect when a web server logged potential API keys or tokens in URLs. API keys, tokens, and other credentials should never be included in URLs as they can be exposed in various ways including server logs, browser history, referrer headers, and bookmarks. When these sensitive credentials are exposed, attackers can use them to gain unauthorized access to external services or systems, potentially leading to data breaches, service abuse, or unauthorized actions on behalf of the compromised account.

The detection identifies several types of exposed credentials in URL requests:
- Long alphanumeric strings that resemble API keys
- Bearer tokens in URLs
- Explicitly named API keys (key=, token=)
- Client secrets and other authentication credentials

Exposed credentials in URLs represent a significant security risk as they can lead to unauthorized access to third-party services, data leaks, and financial impacts through service abuse or account takeover.

**References**:

- [CWE-598: Use of GET Request Method With Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html)
- [CWE-259: Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)