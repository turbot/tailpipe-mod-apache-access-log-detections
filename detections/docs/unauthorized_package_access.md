## Overview

Detect attempts to access or download untrusted packages or dependencies which could introduce supply chain risks. Software supply chain attacks often involve compromising package repositories or tricking users into downloading malicious packages. These attacks have become increasingly common, with attackers targeting package registries like NPM, PyPI, and Maven to distribute malicious code. This detection identifies suspicious package access patterns that could indicate an attempt to introduce compromised dependencies into the software supply chain, potentially leading to unauthorized access, data exfiltration, or system compromise.

**References**:
- [CWE-1352: Misuse of Secure Design Principles](https://cwe.mitre.org/data/definitions/1352.html)
- [OWASP: A08:2021-Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
- [CNCF: Software Supply Chain Best Practices](https://github.com/cncf/tag-security/blob/main/supply-chain-security/supply-chain-security-paper/CNCF_SSCP_v1.pdf)
- [MITRE ATT&CK T1195: Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/) 