## Overview

Detect when a web server received requests using unusual or potentially dangerous HTTP methods. While common HTTP methods like GET, POST, and HEAD are expected in normal web traffic, other methods such as PUT, DELETE, CONNECT, and TRACE can sometimes indicate reconnaissance, vulnerability scanning, or active exploitation attempts. Many of these less common methods have legitimate uses in REST APIs and WebDAV services, but they can also be misused to upload malicious content, delete resources, or gather information about the web server.

**References**:
- [OWASP HTTP Methods](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods)
- [CWE-650: Trusting HTTP Permission Methods on the Server Side](https://cwe.mitre.org/data/definitions/650.html)
- [RFC 7231: Hypertext Transfer Protocol (HTTP/1.1): Semantics and Content](https://tools.ietf.org/html/rfc7231)
- [Apache HTTP Server: Method Limiting Configuration](https://httpd.apache.org/docs/2.4/mod/mod_allowmethods.html) 