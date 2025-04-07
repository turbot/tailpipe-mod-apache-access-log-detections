## Overview

Detect attempts to exploit the Ollama path traversal vulnerability (CVE-2024-37032). This vulnerability affects Ollama versions prior to 0.1.34 and occurs because Ollama does not properly validate the format of sha256 digests when getting model paths. This vulnerability could allow an attacker to access files outside the intended directory or execute unauthorized code by manipulating the digest format in API requests.

The vulnerability specifically relates to how Ollama handles digest validation, where it fails to properly validate that a digest follows the correct format (sha256 with exactly 64 hex digits). By manipulating the digest format, attackers can potentially access sensitive files or directories outside the intended scope.

**References**:
- [CVE-2024-37032](https://www.cve.org/CVERecord?id=CVE-2024-37032)
- [Ollama GitHub Fix Commit](https://github.com/ollama/ollama/compare/v0.1.33...v0.1.34)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html) 