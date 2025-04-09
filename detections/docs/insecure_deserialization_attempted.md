## Overview

Detect attempts to exploit insecure deserialization vulnerabilities which could lead to remote code execution or privilege escalation. Insecure deserialization occurs when applications deserialize data from untrusted sources without proper validation, potentially allowing attackers to manipulate serialized objects to achieve code execution. This detection identifies suspicious requests targeting known deserialization endpoints in popular frameworks like Java, PHP, Node.js, Ruby, and .NET. Successful exploitation of these vulnerabilities can give attackers complete control over affected systems, making it one of the most severe web application vulnerabilities.

**References**:
- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [OWASP: A8:2017-Insecure Deserialization](https://owasp.org/www-project-top-ten/2017/A8_2017-Insecure_Deserialization)
- [Java Deserialization Cheat Sheet](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet)
- [MITRE ATT&CK T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) 