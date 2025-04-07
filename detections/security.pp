locals {
  security_common_tags = merge(local.apache_access_log_detections_common_tags, {
    category = "Security"
  })
}

benchmark "security_detections" {
  title       = "Security Detections"
  description = "This benchmark contains security-focused detections when scanning access logs."
  type        = "detection"
  children = [
    detection.api_key_exposed,
    detection.brute_force_auth_attempted,
    detection.data_privacy_requirement_violated,
    detection.directory_traversal_attempted,
    detection.ilias_lfi_attempted,
    detection.lollms_path_traversal_attempted,
    detection.ollama_path_traversal_attempted,
    detection.pip_directory_traversal_attempted,
    detection.pii_data_exposed_in_url,
    detection.restricted_resource_accessed,
    detection.sensitive_file_access_attempted,
    detection.sql_injection_attempted,
    detection.suspicious_user_agent_detected,
    detection.unauthorized_ip_access_detected,
    detection.unusual_http_method_used,
    detection.web_shell_access_attempted,
    detection.xss_attempted,
    detection.forcedentry_spyware_attempted,
    detection.webkit_integer_overflow_attempted,
    detection.cisco_snmp_community_exposure_attempted,
    detection.cisco_snmp_rw_access_attempted,
    detection.cisco_http_auth_bypass_attempted,
    detection.cisco_ios_http_dos_attempted,
    detection.apache_mod_status_info_disclosure_attempted
  ]

  tags = merge(local.security_common_tags, {
    type = "Benchmark"
  })
}

detection "sql_injection_attempted" {
  title           = "SQL Injection Attempted"
  description     = "Detect when a web server was targeted by SQL injection attempts to check for potential database compromise, data theft, or unauthorized system access."
  documentation   = file("./detections/docs/sql_injection_attempted.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.sql_injection_attempted

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0009:T1190"
  })
}

query "sql_injection_attempted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        lower(request_uri) like '%select%from%'
        or lower(request_uri) like '%union%select%'
        or lower(request_uri) like '%insert%into%'
        or lower(request_uri) like '%delete%from%'
        or lower(request_uri) like '%update%set%'
        or lower(request_uri) like '%drop%table%'
        or lower(request_uri) like '%or%1=1%'
        or lower(request_uri) like '%or%1%=%1%'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "directory_traversal_attempted" {
  title           = "Directory Traversal Attempted"
  description     = "Detect when a web server was targeted by directory traversal attempts to check for unauthorized access to sensitive files outside the web root directory."
  documentation   = file("./detections/docs/directory_traversal_attempted.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.directory_traversal_attempted

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0009:T1083"
  })
}

query "directory_traversal_attempted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- Plain directory traversal attempts
        request_uri like '%../%'
        or request_uri like '%/../%'
        or request_uri like '%/./%'
        -- URL-encoded variants (both cases)
        or request_uri like '%..%2f%'
        or request_uri like '%..%2F%'
        or request_uri like '%%%2e%%2e%%2f%'
        or request_uri like '%%%2E%%2E%%2F%'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "brute_force_auth_attempted" {
  title           = "Brute Force Authentication Attempted"
  description     = "Detect when a web server was targeted by brute force authentication attempts to check for potential credential compromise and unauthorized access."
  documentation   = file("./detections/docs/brute_force_auth_attempted.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.brute_force_auth_attempted

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0009:T1110"
  })
}

query "brute_force_auth_attempted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- Common brute force patterns
        lower(request_uri) like '%login%'
        or lower(request_uri) like '%auth%'
        or lower(request_uri) like '%pass%'
        or lower(request_uri) like '%password%'
        or lower(request_uri) like '%user%'
        or lower(request_uri) like '%username%'
        or lower(request_uri) like '%credentials%'
        or lower(request_uri) like '%attempt%'
        or lower(request_uri) like '%failed%'
        or lower(request_uri) like '%error%'
      )
      and (
        -- Successful response increases suspicion
        status = 200
        -- POST to these URLs is suspicious
        or request_method = 'POST'
        -- PUT to these URLs is very suspicious
        or request_method = 'PUT'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "suspicious_user_agent_detected" {
  title           = "Suspicious User Agent Detected"
  description     = "Detect when a web server received requests with known malicious user agents to check for reconnaissance activities and potential targeted attacks."
  documentation   = file("./detections/docs/suspicious_user_agent_detected.md")
  severity        = "medium"
  display_columns = local.detection_display_columns

  query = query.suspicious_user_agent_detected

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0043:T1592"
  })
}

query "suspicious_user_agent_detected" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      http_user_agent is not null
      and (
        lower(http_user_agent) like '%sqlmap%'
        or lower(http_user_agent) like '%nikto%'
        or lower(http_user_agent) like '%nmap%'
        or lower(http_user_agent) like '%masscan%'
        or lower(http_user_agent) like '%gobuster%'
        or lower(http_user_agent) like '%dirbuster%'
        or lower(http_user_agent) like '%hydra%'
        or lower(http_user_agent) like '%burpsuite%'
        or lower(http_user_agent) like '%nessus%'
        or lower(http_user_agent) like '%metasploit%'
        or http_user_agent is null
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "xss_attempted" {
  title           = "Cross-Site Scripting Attempted"
  description     = "Detect when a web server was targeted by cross-site scripting (XSS) attacks to check for potential client-side code injection that could lead to session hijacking or credential theft."
  documentation   = file("./detections/docs/xss_attempted.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.xss_attempted

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0009:T1059.007"
  })
}

query "xss_attempted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- Plain XSS patterns
        lower(request_uri) like '%<script%'
        or lower(request_uri) like '%javascript:%'
        or lower(request_uri) like '%onerror=%'
        or lower(request_uri) like '%onload=%'
        or lower(request_uri) like '%onclick=%'
        or lower(request_uri) like '%alert(%'
        or lower(request_uri) like '%eval(%'
        -- URL-encoded variants
        or lower(request_uri) like '%%%3cscript%'
        or lower(request_uri) like '%%%3e%'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "sensitive_file_access_attempted" {
  title           = "Sensitive File Access Attempted"
  description     = "Detect when a web server received requests for sensitive files or directories to check for potential information disclosure, configuration leaks, or access to restricted resources."
  documentation   = file("./detections/docs/sensitive_file_access_attempted.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.sensitive_file_access_attempted

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0009:T1083"
  })
}

query "sensitive_file_access_attempted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- Configuration files
        lower(request_uri) like '%.conf%'
        or lower(request_uri) like '%.config%'
        or lower(request_uri) like '%/etc/%'
        or lower(request_uri) like '%web.xml%'
        or lower(request_uri) like '%/config%'
        
        -- Common sensitive files
        or lower(request_uri) like '%/.env%'
        or lower(request_uri) like '%/.git/%'
        or lower(request_uri) like '%.sql%'
        or lower(request_uri) like '%backup%'
        or lower(request_uri) like '%dump%'

        -- Apache specific files
        or lower(request_uri) like '%/server-status%'
        or lower(request_uri) like '%/server-info%'
        or lower(request_uri) like '%httpd.conf%'
        or lower(request_uri) like '%/htpasswd%'
        or lower(request_uri) like '%/htaccess%'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "unusual_http_method_used" {
  title           = "Unusual HTTP Method Used"
  description     = "Detect when a web server received requests using unusual or potentially dangerous HTTP methods to check for exploitation attempts, information disclosure, or unauthorized modifications."
  documentation   = file("./detections/docs/unusual_http_method_used.md")
  severity        = "medium"
  display_columns = local.detection_display_columns

  query = query.unusual_http_method_used

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0009:T1213"
  })
}

query "unusual_http_method_used" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_method is not null
      and request_method not in ('GET', 'POST', 'HEAD')
      and (
        -- Potentially dangerous methods
        request_method in ('OPTIONS', 'PUT', 'DELETE', 'CONNECT', 'TRACE', 'PATCH', 'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK')
        -- WebDAV methods
        or request_method in ('PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK')
        -- Sometimes used in attacks
        or request_method in ('DEBUG', 'TRACK', 'SEARCH')
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "web_shell_access_attempted" {
  title           = "Web Shell Access Attempted"
  description     = "Detect when a web server received potential web shell upload or access attempts to check for backdoor installation, persistent access, or remote code execution."
  documentation   = file("./detections/docs/web_shell_access_attempted.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.web_shell_access_attempted

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0003:T1505.003"
  })
}

query "web_shell_access_attempted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- Common web shell names/extensions
        lower(request_uri) like '%.php%'
        or lower(request_uri) like '%.jsp%'
        or lower(request_uri) like '%.asp%'
        or lower(request_uri) like '%.aspx%'
        or lower(request_uri) like '%.cfm%'
        
        -- Common shell names
        or lower(request_uri) like '%shell%'
        or lower(request_uri) like '%cmd%'
        or lower(request_uri) like '%command%'
        or lower(request_uri) like '%c99%'
        or lower(request_uri) like '%r57%'
        or lower(request_uri) like '%webshell%'
        or lower(request_uri) like '%backdoor%'
      )
      and (
        -- Successful response increases suspicion
        status = 200
        -- POST to these URLs is suspicious
        or request_method = 'POST'
        -- PUT to these URLs is very suspicious
        or request_method = 'PUT'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "api_key_exposed" {
  title           = "API Key Exposed"
  description     = "Detect when a web server logged potential API keys or tokens in URLs to check for credential exposure, which could lead to unauthorized access to external services or systems."
  documentation   = file("./detections/docs/api_key_exposed.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.api_key_exposed

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0006:T1552"
  })
}

query "api_key_exposed" {
  sql = <<-EOQ
    select
      case
        when request_uri ~ '(?i)[a-z0-9]{32,}' then 'Potential API Key'
        when request_uri ~ '(?i)bearer\s+[a-zA-Z0-9-._~+/]+=*' then 'Bearer Token'
        when request_uri ~ '(?i)key=[a-zA-Z0-9-]{20,}' then 'API Key Parameter'
        when request_uri ~ '(?i)token=[a-zA-Z0-9-]{20,}' then 'Token Parameter'
        when request_uri ~ '(?i)client_secret=[a-zA-Z0-9-]{20,}' then 'Client Secret'
      end as token_type,
      status as status_code,
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        request_uri ~ '(?i)[a-z0-9]{32,}'
        or request_uri ~ '(?i)bearer\s+[a-zA-Z0-9-._~+/]+=*'
        or request_uri ~ '(?i)key=[a-zA-Z0-9-]{20,}'
        or request_uri ~ '(?i)token=[a-zA-Z0-9-]{20,}'
        or request_uri ~ '(?i)client_secret=[a-zA-Z0-9-]{20,}'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "pii_data_exposed_in_url" {
  title           = "PII Data Exposed In URL"
  description     = "Detect when a web server logged Personally Identifiable Information (PII) in URLs to check for potential data privacy violations, regulatory non-compliance, and sensitive information disclosure."
  documentation   = file("./detections/docs/pii_data_exposed_in_url.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.pii_data_exposed_in_url

  tags = merge(local.security_common_tags, {
    mitre_attack_id = "TA0006:T1552.001" # Credential Access:Credentials In Files
  })
}

query "pii_data_exposed_in_url" {
  sql = <<-EOQ
    with pii_patterns as (
      select
        case
          when request_uri ~ '[0-9]{3}-[0-9]{2}-[0-9]{4}' then 'SSN'
          when request_uri ~ '[0-9]{16}' then 'Credit Card'
          when request_uri ~ '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' then 'Email'
          when request_uri ~ '(?:password|passwd|pwd)=[^&]+' then 'Password'
          when request_uri ~ '[0-9]{10}' then 'Phone Number'
        end as pii_type,
        ${local.detection_sql_columns}
      from
        apache_access_log
      where
        request_uri is not null
        and (
          request_uri ~ '[0-9]{3}-[0-9]{2}-[0-9]{4}'  -- SSN pattern
          or request_uri ~ '[0-9]{16}'  -- Credit card pattern
          or request_uri ~ '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'  -- Email pattern
          or request_uri ~ '(?:password|passwd|pwd)=[^&]+'  -- Password in URL
          or request_uri ~ '[0-9]{10}'  -- Phone number pattern
        )
    )
    select
      *
    from
      pii_patterns
    order by
      timestamp desc;
  EOQ
}

detection "restricted_resource_accessed" {
  title           = "Restricted Resource Accessed"
  description     = "Detect when a web server processed requests to restricted resources or administrative areas to check for unauthorized access attempts, privilege escalation, or security policy violations."
  documentation   = file("./detections/docs/restricted_resource_accessed.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.restricted_resource_accessed

  tags = merge(local.security_common_tags, {
    mitre_attack_id = "TA0001:T1190,TA0008:T1133" # Initial Access:Exploit Public-Facing Application, Lateral Movement:External Remote Services
  })
}

query "restricted_resource_accessed" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        lower(request_uri) like '%/admin%'
        or lower(request_uri) like '%/manager%'
        or lower(request_uri) like '%/console%'
        or lower(request_uri) like '%/dashboard%'
        or lower(request_uri) like '%/management%'
        or lower(request_uri) like '%/phpmyadmin%'
        or lower(request_uri) like '%/wp-admin%'
        or lower(request_uri) like '%/administrator%'
        
        -- Apache-specific sensitive paths
        or lower(request_uri) like '%/server-status%'
        or lower(request_uri) like '%/server-info%'
        or lower(request_uri) like '%/status%'
        or lower(request_uri) like '%/balancer-manager%'
      )
      and status != 404  -- Exclude 404s to reduce noise
    order by
      timestamp desc;
  EOQ
}

detection "unauthorized_ip_access_detected" {
  title           = "Unauthorized IP Access Detected"
  description     = "Detect when a web server received requests from unauthorized IP ranges or geographic locations to check for potential security policy violations, access control bypasses, or geofencing compliance issues."
  documentation   = file("./detections/docs/unauthorized_ip_access_detected.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.unauthorized_ip_access_detected

  tags = merge(local.security_common_tags, {
    mitre_attack_id = "TA0008:T1133,TA0003:T1078.004" # Lateral Movement:External Remote Services, Persistence:Cloud Accounts
  })
}

query "unauthorized_ip_access_detected" {
  sql = <<-EOQ
    with unauthorized_access as (
      select
        remote_addr as request_ip,
        count(*) as request_count,
        min(tp_timestamp) as first_access,
        max(tp_timestamp) as last_access
      from
        apache_access_log
      where
        remote_addr not like '10.%'
        and remote_addr not like '172.%'
        and remote_addr not like '192.168.%'
        and remote_addr not like '127.%'
      group by
        remote_addr
    )
    select
      *
    from
      unauthorized_access
    order by
      request_count desc;
  EOQ
}

detection "data_privacy_requirement_violated" {
  title           = "Data Privacy Requirement Violated"
  description     = "Detect when a web server processed requests that potentially violate data privacy requirements to check for regulatory compliance issues, sensitive data handling violations, or privacy policy infractions."
  documentation   = file("./detections/docs/data_privacy_requirement_violated.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.data_privacy_requirement_violated

  tags = merge(local.security_common_tags, {
    mitre_attack_id = "TA0009:T1530,TA0006:T1552.001" # Collection:Data from Cloud Storage, Credential Access:Credentials In Files
  })
}

query "data_privacy_requirement_violated" {
  sql = <<-EOQ
    with privacy_endpoints as (
      select
        request_uri as endpoint,
        count(*) as total_requests,
        count(*) filter (
          where request_uri ~ '(?i)(ssn|email|password|credit|card|phone|address|dob|birth)'
        ) as sensitive_data_count,
        count(distinct remote_addr) as unique_ips
      from
        apache_access_log
      where
        request_uri is not null
        -- Focus on API endpoints and form submissions
        and (request_uri like '/api/%' or request_method = 'POST')
      group by
        request_uri
      having
        count(*) filter (
          where request_uri ~ '(?i)(ssn|email|password|credit|card|phone|address|dob|birth)'
        ) > 0
    )
    select
      endpoint,
      total_requests,
      sensitive_data_count,
      unique_ips,
      round((sensitive_data_count::float / total_requests * 100)::numeric, 2) as sensitive_data_percentage
    from
      privacy_endpoints
    order by
      sensitive_data_count desc;
  EOQ
}

detection "ilias_lfi_attempted" {
  title           = "ILIAS LFI Attempted (CVE-2022-45918)"
  description     = "Detect attempts to exploit the ILIAS SCORM debugger local file inclusion vulnerability (CVE-2022-45918) affecting versions before 7.16, which could allow unauthorized access to sensitive files outside the intended directory."
  documentation   = file("./detections/docs/ilias_lfi_attempted.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.ilias_lfi_attempted

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0009:T1083",
    cve_id           = "CVE-2022-45918"
  })
}

query "ilias_lfi_attempted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- Detect requests to ILIAS SCORM debugger endpoints with potential LFI
        request_uri like '%/scorm/%'
        and (
          -- Look for log file parameter with path traversal
          request_uri like '%logFile=%../%'
          or request_uri like '%logFile=../%'
          -- Encoded variants
          or request_uri like '%logFile=%252e%252e%2f%'
          or request_uri like '%logFile=%2e%2e%2f%'
          -- Paths to common sensitive files
          or request_uri like '%logFile=%/etc/passwd%'
          or request_uri like '%logFile=%/etc/shadow%'
          or request_uri like '%logFile=%/etc/hosts%'
          or request_uri like '%logFile=%wp-config.php%'
          or request_uri like '%logFile=%config.php%'
          or request_uri like '%logFile=%/.env%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "lollms_path_traversal_attempted" {
  title           = "LollMS Path Traversal Attempted (CVE-2024-4315)"
  description     = "Detect attempts to exploit the LollMS Local File Inclusion vulnerability (CVE-2024-4315) affecting version 9.5, which could allow attackers to access or delete any file on Windows systems due to insufficient path sanitization."
  documentation   = file("./detections/docs/lollms_path_traversal_attempted.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.lollms_path_traversal_attempted

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0009:T1083",
    cve_id           = "CVE-2024-4315"
  })
}

query "lollms_path_traversal_attempted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- Detect requests to LollMS endpoints with potential path traversal
        (request_uri like '%/personalities%' or request_uri like '%/del_preset%')
        and (
          -- Look for Windows-style path traversal attempts with backslashes
          request_uri like '%\\%'
          or request_uri like '%\\..\\%'
          or request_uri like '%\..\%'
          -- Also check for URL-encoded backslashes
          or request_uri like '%%%5C%'
          or request_uri like '%%%5c%'
          or request_uri like '%%%5C..%%%5C%'
          or request_uri like '%%%5c..%%%5c%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "ollama_path_traversal_attempted" {
  title           = "Ollama Path Traversal Attempted (CVE-2024-37032)"
  description     = "Detect attempts to exploit the Ollama path traversal vulnerability (CVE-2024-37032) affecting versions before 0.1.34, which could allow unauthorized access to sensitive files outside the intended directory."
  documentation   = file("./detections/docs/ollama_path_traversal_attempted.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.ollama_path_traversal_attempted

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0009:T1083",
    cve_id           = "CVE-2024-37032"
  })
}

query "ollama_path_traversal_attempted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- Detect requests to Ollama API endpoints with potential path traversal
        (request_uri like '%/api/blobs/%' or request_uri like '%/ollama/blobs/%')
        and (
          -- Paths with potential traversal sequences
          request_uri like '%/../%'
          or request_uri like '%/..%'
          -- Look for invalid sha256 digest format (not exactly 64 hex chars)
          or request_uri ~ '/blobs/sha256:[^a-f0-9]'  -- Invalid characters
          or request_uri ~ '/blobs/sha256:[a-f0-9]{0,63}$'  -- Too short
          or request_uri ~ '/blobs/sha256:[a-f0-9]{65,}'    -- Too long
          -- Additional check for malformed sha256 prefix
          or request_uri ~ '/blobs/sha[^2]'
          or request_uri ~ '/blobs/sha2[^5]'
          or request_uri ~ '/blobs/sha25[^6]'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "pip_directory_traversal_attempted" {
  title           = "Python pip Directory Traversal Attempted (CVE-2019-20916)"
  description     = "Detect attempts to exploit the Python pip directory traversal vulnerability (CVE-2019-20916) affecting versions before 19.2, which could allow attackers to write files to arbitrary locations on the filesystem."
  documentation   = file("./detections/docs/pip_directory_traversal_attempted.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.pip_directory_traversal_attempted

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0009:T1083",
    cve_id           = "CVE-2019-20916"
  })
}

query "pip_directory_traversal_attempted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- Detect potential Python pip package repository or installation URLs
        (request_uri like '%/simple/%' or request_uri like '%/packages/%' or request_uri like '%/pip/%')
        and (
          -- Look for Content-Disposition header manipulation attempts
          request_uri like '%../%.whl'
          or request_uri like '%/%2e%2e/%'
          or request_uri like '%/%2E%2E/%'
          or request_uri like '%/.ssh/%'
          or request_uri like '%/authorized_keys%'
          -- Encoded variants
          or request_uri like '%/%252e%252e/%'
          or request_uri like '%/%252E%252E/%'
          or request_uri like '%/%252e%252e/ssh%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "insecure_session_cookie_detected" {
  title           = "Insecure Session Cookie Detected (CVE-2008-4122)"
  description     = "Detect when a web server processes requests that may expose session cookies over insecure channels, particularly focusing on the Joomla! vulnerability (CVE-2008-4122) where session cookies were not set with the secure flag in HTTPS sessions."
  documentation   = file("./detections/docs/insecure_session_cookie_detected.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.insecure_session_cookie_detected

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0006:T1539", # Credential Access:Steal Web Session Cookie
    cve_id           = "CVE-2008-4122"
  })
}

query "insecure_session_cookie_detected" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- Detect potential Joomla session-related requests
        (
          request_uri like '%/administrator/%'
          or request_uri like '%/components/%'
          or request_uri like '%/modules/%'
          or request_uri like '%/templates/%'
          or request_uri like '%/includes/%'
          or request_uri like '%/installation/%'
          or request_uri like '%/libraries/%'
          or request_uri like '%/plugins/%'
        )
        and (
          -- Look for session-related parameters or cookies
          request_uri like '%jsessionid=%'
          or request_uri like '%phpsessid=%'
          or request_uri like '%sessionid=%'
          or request_uri like '%session_id=%'
          -- Specific Joomla session parameters
          or request_uri like '%JOOMLA_SESSION=%'
          or request_uri like '%JSESSIONID=%'
        )
        -- Focus on potential insecure transmissions
        and (
          -- Non-HTTPS requests with session information
          request_uri not like 'https://%'
          -- Requests switching between HTTP and HTTPS
          or request_uri like '%http://%'
          or request_uri like '%://localhost%'
          or request_uri like '%://127.0.0.1%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "backup_client_password_hash_exposed" {
  title           = "Backup Client Password Hash Exposed (CVE-2008-3289)"
  description     = "Detect when a backup client exposes password hashes in cleartext, particularly focusing on the EMC Dantz Retrospect vulnerability (CVE-2008-3289) where password hashes were transmitted without encryption."
  documentation   = file("./detections/docs/backup_client_password_hash_exposed.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.backup_client_password_hash_exposed

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0006:T1552", # Credential Access:Unsecured Credentials
    cve_id           = "CVE-2008-3289"
  })
}

query "backup_client_password_hash_exposed" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- Detect potential backup client communications
        (
          request_uri like '%/backup/%'
          or request_uri like '%/restore/%'
          or request_uri like '%/retrospect/%'
          or request_uri like '%/client/%'
          or request_uri like '%/agent/%'
        )
        and (
          -- Look for potential password hash patterns
          request_uri ~ '[a-fA-F0-9]{32,}'  -- MD5 or longer hashes
          or request_uri ~ 'hash=[a-fA-F0-9]+'
          or request_uri ~ 'password=[a-fA-F0-9]+'
          or request_uri ~ 'pwd=[a-fA-F0-9]+'
          -- Specific Retrospect client parameters
          or request_uri like '%/auth%'
          or request_uri like '%/login%'
          or request_uri like '%/connect%'
        )
        -- Focus on unencrypted transmissions
        and (
          request_uri not like 'https://%'
          or request_uri like '%http://%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "camera_config_exposure_attempted" {
  title           = "Camera Configuration Data Exposure Attempted (CVE-2008-4390)"
  description     = "Detect when a web server processed requests that may expose camera configuration data, particularly focusing on the Cisco Linksys WVC54GC vulnerability (CVE-2008-4390) where configuration data including passwords was transmitted in cleartext."
  documentation   = file("./detections/docs/camera_config_exposure_attempted.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.camera_config_exposure_attempted

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0006:T1552", # Credential Access:Unsecured Credentials
    cve_id           = "CVE-2008-4390"
  })
}

query "camera_config_exposure_attempted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- Detect potential camera configuration access attempts
        (
          request_uri like '%/setup%'
          or request_uri like '%/config%'
          or request_uri like '%/admin%'
          or request_uri like '%/wizard%'
          -- Specific to Linksys WVC54GC
          or request_uri like '%/wvc54gc%'
          or request_uri like '%/camera%'
        )
        and (
          -- Look for configuration data patterns
          request_uri like '%setup_wizard%'
          or request_uri like '%remote_management%'
          or request_uri like '%settings%'
          or request_uri like '%password%'
          or request_uri like '%credentials%'
          -- Specific Linksys camera parameters
          or request_uri like '%/setup.cgi%'
          or request_uri like '%/config.cgi%'
        )
        -- Focus on unencrypted transmissions
        and (
          request_uri not like 'https://%'
          or request_uri like '%http://%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "network_config_exposure_attempted" {
  title           = "Network Configuration Data Exposure Attempted (CVE-2001-1546)"
  description     = "Detect when a web server processed requests that may expose network device configuration data, particularly focusing on the Cisco IOS vulnerability (CVE-2001-1546) where SNMP community strings could be obtained through TFTP configuration files."
  documentation   = file("./detections/docs/network_config_exposure_attempted.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.network_config_exposure_attempted

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0006:T1552", # Credential Access:Unsecured Credentials
    cve_id           = "CVE-2001-1546"
  })
}

query "network_config_exposure_attempted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- Detect potential network config access attempts
        (
          request_uri like '%/tftp/%'
          or request_uri like '%/config/%'
          or request_uri like '%/cisco/%'
          or request_uri like '%/network/%'
          or request_uri like '%/router/%'
          or request_uri like '%/switch/%'
        )
        and (
          -- Look for configuration file patterns
          request_uri like '%.conf%'
          or request_uri like '%.cfg%'
          or request_uri like '%.config%'
          or request_uri like '%startup-config%'
          or request_uri like '%running-config%'
          -- SNMP related patterns
          or request_uri like '%snmp%'
          or request_uri like '%community%'
          -- Network config backup patterns
          or request_uri like '%backup%'
          or request_uri like '%restore%'
          -- Common config file extensions
          or request_uri like '%.ios%'
          or request_uri like '%.txt%'
        )
        -- Focus on unencrypted transmissions
        and (
          request_uri not like 'https://%'
          or request_uri like '%http://%'
          -- TFTP specific patterns
          or request_uri like '%tftp://%'
          or request_uri like '%udp%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "forcedentry_spyware_attempted" {
  title           = "FORCEDENTRY Spyware Attempted (CVE-2021-30860)"
  description     = "Detect attempts to exploit the FORCEDENTRY vulnerability (CVE-2021-30860) affecting iOS devices before 14.8, which could allow attackers to achieve remote code execution through malformed GIF files targeting CoreGraphics."
  documentation   = file("./detections/docs/forcedentry_spyware_attempted.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.forcedentry_spyware_attempted

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0001:T1190,TA0002:T1203", # Initial Access:Exploit Public-Facing Application, Execution:Exploitation for Client Execution
    cve_id           = "CVE-2021-30860"
  })
}

query "forcedentry_spyware_attempted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- Detect potential FORCEDENTRY/Pegasus exploitation attempts
        (
          -- Look for malformed GIF file patterns
          (
            lower(request_uri) like '%.gif'
            or lower(request_uri) like '%image/gif%'
            or lower(request_uri) like '%/gif/%'
          )
          and (
            -- Suspicious GIF patterns
            request_uri ~ '(?i)gif8[^7]'  -- Invalid GIF87a/GIF89a header
            or request_uri like '%\x00%'  -- Null bytes
            or request_uri ~ '[^\x20-\x7E]'  -- Non-printable characters
            or body_bytes_sent > 1048576  -- Unusually large GIF (>1MB)
          )
        )
        or
        -- CoreGraphics related patterns
        (
          lower(request_uri) like '%/CoreGraphics%'
          or lower(request_uri) like '%/ImageIO%'
          or lower(request_uri) like '%/CoreImage%'
          -- Common iOS image processing paths
          or lower(request_uri) like '%/Library/Graphics%'
          or lower(request_uri) like '%/System/Library/Frameworks/ImageIO%'
        )
        -- Focus on potential malicious sources
        and (
          -- Non-standard ports
          request_uri ~ ':\d{4,5}'
          -- Suspicious domains/paths
          or lower(request_uri) like '%cdn%'
          or lower(request_uri) like '%static%'
          or lower(request_uri) like '%media%'
          or lower(request_uri) like '%download%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "webkit_integer_overflow_attempted" {
  title           = "WebKit Integer Overflow Attempted (CVE-2021-30663)"
  description     = "Detect attempts to exploit the WebKit integer overflow vulnerability (CVE-2021-30663) affecting iOS versions before 14.5.1, which could allow attackers to achieve arbitrary code execution through maliciously crafted web content."
  documentation   = file("./detections/docs/webkit_integer_overflow_attempted.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.webkit_integer_overflow_attempted

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0002:T1203", # Execution:Exploitation for Client Execution
    cve_id           = "CVE-2021-30663"
  })
}

query "webkit_integer_overflow_attempted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- Detect potential WebKit exploitation attempts
        (
          -- Look for suspicious web content patterns
          (
            lower(request_uri) like '%.html'
            or lower(request_uri) like '%.htm'
            or lower(request_uri) like '%.js'
            or lower(request_uri) like '%.css'
            or lower(request_uri) like '%text/html%'
            or lower(request_uri) like '%application/javascript%'
            or lower(request_uri) like '%application/x-javascript%'
          )
          and (
            -- Integer overflow patterns
            request_uri ~ '[0-9]{10,}'  -- Very large numbers
            or request_uri ~ '0x[0-9a-f]{8,}'  -- Large hex values
            -- Memory manipulation indicators
            or lower(request_uri) like '%heap%'
            or lower(request_uri) like '%spray%'
            or lower(request_uri) like '%overflow%'
            or lower(request_uri) like '%buffer%'
            -- Suspicious JavaScript patterns
            or lower(request_uri) like '%arraybuffer%'
            or lower(request_uri) like '%typedarray%'
            or lower(request_uri) like '%dataview%'
          )
        )
        or
        -- WebKit related patterns
        (
          lower(request_uri) like '%webkit%'
          or lower(request_uri) like '%safari%'
          or lower(request_uri) like '%ios%'
          -- Common WebKit paths
          or lower(request_uri) like '%/WebKit%'
          or lower(request_uri) like '%/WebCore%'
          or lower(request_uri) like '%/JavaScriptCore%'
        )
        -- Focus on potential malicious sources
        and (
          -- Suspicious patterns
          lower(request_uri) like '%exploit%'
          or lower(request_uri) like '%payload%'
          or lower(request_uri) like '%poc%'
          or lower(request_uri) like '%0day%'
          -- Common malicious file indicators
          or lower(request_uri) like '%.min.js%'
          or lower(request_uri) like '%.obf.js%'
          or lower(request_uri) like '%.enc.js%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "cisco_snmp_community_exposure_attempted" {
  title           = "Cisco SNMP Community String Exposure Attempted (CVE-2008-2049)"
  description     = "Detect attempts to exploit the Cisco IOS vulnerability (CVE-2008-2049) where SNMP community strings could be obtained through TFTP configuration files due to improper access controls."
  documentation   = file("./detections/docs/cisco_snmp_community_exposure_attempted.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.cisco_snmp_community_exposure_attempted

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0006:T1552", # Credential Access:Unsecured Credentials
    cve_id           = "CVE-2008-2049"
  })
}

query "cisco_snmp_community_exposure_attempted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- Detect potential Cisco IOS config access attempts
        (
          request_uri like '%/ios/%'
          or request_uri like '%/cisco/%'
          or request_uri like '%/router/%'
          or request_uri like '%/switch/%'
          -- TFTP specific paths
          or request_uri like '%/tftp/%'
          or request_uri like '%/tftpboot/%'
        )
        and (
          -- Look for SNMP configuration patterns
          request_uri like '%snmp%'
          or request_uri like '%community%'
          or request_uri like '%public%'
          or request_uri like '%private%'
          -- IOS config file patterns
          or request_uri like '%startup-config%'
          or request_uri like '%running-config%'
          or request_uri like '%config.text%'
          or request_uri like '%ios.cfg%'
          or request_uri like '%ios.conf%'
          -- TFTP file patterns
          or request_uri like '%.cfg%'
          or request_uri like '%.conf%'
          or request_uri like '%.txt%'
        )
        -- Focus on unencrypted transmissions and TFTP
        and (
          request_uri not like 'https://%'
          or request_uri like '%http://%'
          or request_uri like '%tftp://%'
          or request_uri like '%udp%'
          -- Common TFTP ports
          or request_uri like '%:69%'
          or request_uri like '%:10069%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "cisco_snmp_rw_access_attempted" {
  title           = "Cisco SNMP Read-Write Access Attempted (CVE-2007-5172)"
  description     = "Detect attempts to exploit the Cisco IOS vulnerability (CVE-2007-5172) where improper access controls could allow unauthorized SNMP read-write access, potentially leading to device configuration changes and network compromise."
  documentation   = file("./detections/docs/cisco_snmp_rw_access_attempted.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.cisco_snmp_rw_access_attempted

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0040:T1489", # Impact:Service Stop
    cve_id           = "CVE-2007-5172"
  })
}

query "cisco_snmp_rw_access_attempted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- Detect potential SNMP read-write access attempts
        (
          request_uri like '%/snmp/%'
          or request_uri like '%/cisco/%'
          or request_uri like '%/router/%'
          or request_uri like '%/switch/%'
          -- SNMP specific paths
          or request_uri like '%/private/%'
          or request_uri like '%/rw/%'
          or request_uri like '%/write/%'
        )
        and (
          -- Look for SNMP write operation patterns
          request_uri like '%set%'
          or request_uri like '%write%'
          or request_uri like '%modify%'
          or request_uri like '%config%'
          -- SNMP version indicators
          or request_uri like '%v2c%'
          or request_uri like '%v3%'
          -- Common SNMP write operations
          or request_uri like '%reload%'
          or request_uri like '%reset%'
          or request_uri like '%shutdown%'
          or request_uri like '%enable%'
          or request_uri like '%disable%'
        )
        -- Focus on SNMP protocols and ports
        and (
          request_uri like '%snmp://%'
          or request_uri like '%udp%'
          -- Common SNMP ports
          or request_uri like '%:161%'
          or request_uri like '%:162%'
          -- Non-standard SNMP ports
          or request_uri like '%:1161%'
          or request_uri like '%:1162%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "cisco_http_auth_bypass_attempted" {
  title           = "Cisco HTTP Authentication Bypass Attempted (CVE-2003-1038)"
  description     = "Detect attempts to exploit the Cisco IOS HTTP Server vulnerability (CVE-2003-1038) where authentication could be bypassed through crafted URLs, potentially allowing unauthorized access to the device configuration interface."
  documentation   = file("./detections/docs/cisco_http_auth_bypass_attempted.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.cisco_http_auth_bypass_attempted

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0001:T1190", # Initial Access:Exploit Public-Facing Application
    cve_id           = "CVE-2003-1038"
  })
}

query "cisco_http_auth_bypass_attempted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- Detect potential Cisco IOS HTTP Server access attempts
        (
          request_uri like '%/ios/%'
          or request_uri like '%/cisco/%'
          or request_uri like '%/level/%'
          or request_uri like '%/exec/%'
          -- HTTP server specific paths
          or request_uri like '%/admin/%'
          or request_uri like '%/config/%'
          or request_uri like '%/setup/%'
        )
        and (
          -- Look for authentication bypass patterns
          request_uri like '%/auth%'
          or request_uri like '%/login%'
          or request_uri like '%/bypass%'
          -- Common HTTP auth parameters
          or request_uri like '%username=%'
          or request_uri like '%password=%'
          or request_uri like '%level=%'
          -- URL manipulation patterns
          or request_uri like '%..%'
          or request_uri like '%//%'
          or request_uri like '%\\%'
          -- Encoded variants
          or request_uri like '%2e%2e%'
          or request_uri like '%252e%'
          or request_uri like '%2f%2f%'
        )
        -- Focus on HTTP protocol and ports
        and (
          request_uri like '%http://%'
          -- Common HTTP server ports
          or request_uri like '%:80%'
          or request_uri like '%:8080%'
          -- Non-standard HTTP ports
          or request_uri like '%:180%'
          or request_uri like '%:280%'
          or request_uri like '%:8000%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "cisco_ios_http_dos_attempted" {
  title           = "Cisco IOS HTTP DoS Attempted (CVE-2005-1205)"
  description     = "Detect attempts to exploit the Cisco IOS HTTP Server vulnerability (CVE-2005-1205) where malformed HTTP requests could cause a denial of service condition through a device reload."
  documentation   = file("./detections/docs/cisco_ios_http_dos_attempted.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.cisco_ios_http_dos_attempted

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0040:T1499", # Impact:Endpoint Denial of Service
    cve_id           = "CVE-2005-1205"
  })
}

query "cisco_ios_http_dos_attempted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- Detect potential Cisco IOS HTTP Server DoS attempts
        (
          request_uri like '%/ios/%'
          or request_uri like '%/cisco/%'
          or request_uri like '%/level/%'
          or request_uri like '%/exec/%'
          -- HTTP server specific paths
          or request_uri like '%/admin/%'
          or request_uri like '%/config/%'
          or request_uri like '%/setup/%'
        )
        and (
          -- Look for malformed HTTP request patterns
          request_uri like '%\x00%'  -- Null bytes
          or request_uri ~ '[^\x20-\x7E]'  -- Non-printable characters
          or request_uri like '%\xff%'  -- Invalid UTF-8 sequences
          -- Unusually long requests
          or length(request_uri) > 2048
          -- Invalid HTTP version strings
          or request_uri like '%HTTP/1.%'
          or request_uri like '%HTTP/%'
        )
        -- Focus on HTTP protocol and ports
        and (
          request_uri like '%http://%'
          -- Common HTTP server ports
          or request_uri like '%:80%'
          or request_uri like '%:8080%'
          -- Non-standard HTTP ports
          or request_uri like '%:180%'
          or request_uri like '%:280%'
          or request_uri like '%:8000%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "apache_mod_status_info_disclosure_attempted" {
  title           = "Apache mod_status Information Disclosure Attempted (CVE-2014-3852)"
  description     = "Detect attempts to exploit the Apache mod_status vulnerability (CVE-2014-3852) where server-status pages could expose sensitive information through cross-site scripting."
  documentation   = file("./detections/docs/apache_mod_status_info_disclosure_attempted.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.apache_mod_status_info_disclosure_attempted

  tags = merge(local.security_common_tags, {
    mitre_attack_ids = "TA0009:T1213", # Collection:Data from Web Application
    cve_id           = "CVE-2014-3852"
  })
}

query "apache_mod_status_info_disclosure_attempted" {
  sql = <<EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- Detect potential mod_status information disclosure attempts
        (
          -- Look for server-status access attempts
          lower(request_uri) like '%/server-status%'
          or lower(request_uri) like '%/status%'
          or lower(request_uri) like '%/mod_status%'
          -- Common status page variations
          or lower(request_uri) like '%/apache-status%'
          or lower(request_uri) like '%/apache_status%'
        )
        and (
          -- XSS patterns in query parameters
          request_uri like '%<script%'
          or request_uri like '%javascript:%'
          or request_uri like '%onerror=%'
          or request_uri like '%onload=%'
          -- URL-encoded variants
          or request_uri like '%3Cscript%'
          or request_uri like '%253Cscript%'
          or request_uri like '%26lt%3Bscript%'
          -- Status page parameters
          or request_uri like '%?refresh=%'
          or request_uri like '%?auto=%'
          or request_uri like '%?notable=%'
        )
      )
    order by
      tp_timestamp desc
EOQ
}
