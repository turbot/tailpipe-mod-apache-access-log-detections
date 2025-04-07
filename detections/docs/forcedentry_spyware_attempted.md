## Overview

Detect attempts to exploit the FORCEDENTRY vulnerability (CVE-2021-30860) where malformed GIF files could lead to remote code execution through CoreGraphics. This vulnerability affects iOS devices before version 14.8 and occurs due to integer overflow issues in the CoreGraphics component when processing maliciously crafted GIF files. When exploited, attackers can achieve zero-click remote code execution through iMessage, potentially leading to device compromise and spyware installation.

The vulnerability specifically relates to how CoreGraphics processes GIF files, particularly in the handling of image metadata and buffer management. By crafting specially formatted GIF files with specific characteristics, attackers can trigger memory corruption and achieve arbitrary code execution. This vulnerability was actively exploited by NSO Group's Pegasus spyware for zero-click attacks against iOS devices, allowing complete device compromise without any user interaction.

**References**:
- [CVE-2021-30860](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-30860)
- [Apple Security Advisory](https://support.apple.com/en-us/HT212807)
- [Citizen Lab FORCEDENTRY Analysis](https://citizenlab.ca/2021/09/forcedentry-nso-group-imessage-zero-click-exploit-captured-in-the-wild/)
- [CWE-190: Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html)
- [CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer](https://cwe.mitre.org/data/definitions/119.html)
- [MITRE ATT&CK - Initial Access: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK - Execution: Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/)
