## Overview

Detect when a web server received requests attempting to delete, modify, or tamper with security logs, which could indicate an attempt to cover tracks of malicious activity. Attackers often try to delete or modify log files to hide evidence of their activities after gaining access to a system. This anti-forensic technique is commonly used in sophisticated attacks to evade detection and complicate incident response. By identifying attempts to manipulate log storage locations or configuration files related to logging, security teams can detect potential intrusions even when attackers are actively trying to cover their tracks, which is a critical capability for security monitoring.

**References**:
- [CWE-778: Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)
- [OWASP: A09:2021-Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)
- [OWASP: Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [MITRE ATT&CK T1070: Indicator Removal on Host](https://attack.mitre.org/techniques/T1070/) 