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
    detection.data_privacy_requirement_violated,
    detection.directory_traversal_attempted,
    detection.pii_data_exposed_in_url,
    detection.restricted_resource_accessed,
    detection.sensitive_file_access_attempted,
    detection.sql_injection_attempted,
    detection.suspicious_user_agent_detected,
    detection.unauthorized_ip_access_detected,
    detection.unusual_http_method_used,
    detection.web_shell_access_attempted,
    detection.xss_attempted,
    ######
    detection.cleartext_credentials_transmitted,
    detection.weak_ssl_tls_detected,
    detection.insecure_deserialization_attempted,
    detection.unauthorized_package_access,
    detection.log_file_access_attempted,
    detection.security_log_manipulation_attempted,
    detection.ssrf_attempt_detected,
    detection.cloud_metadata_access_attempted,
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

#############

detection "cleartext_credentials_transmitted" {
  title           = "Cleartext Credentials Transmitted"
  description     = "Detect when credentials are transmitted in cleartext over unencrypted HTTP connections, which could lead to credential theft through network sniffing."
  documentation   = file("./detections/docs/cleartext_credentials_transmitted.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.cleartext_credentials_transmitted

  tags = merge(local.owasp_top_10_a02_2021_common_tags, {
    mitre_attack_ids = "TA0006:T1040"
  })
}

query "cleartext_credentials_transmitted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and remote_addr is not null
      and scheme = 'http' 
      and (
        lower(request_uri) like '%/login%' 
        or lower(request_uri) like '%/signin%'
        or lower(request_uri) like '%/auth%'
      )
      and request_method = 'POST'
    order by
      tp_timestamp desc;
  EOQ
}

detection "weak_ssl_tls_detected" {
  title           = "Weak SSL/TLS Protocol Detected"
  description     = "Detect when clients connect using deprecated or weak SSL/TLS protocol versions that are vulnerable to known attacks."
  documentation   = file("./detections/docs/weak_ssl_tls_detected.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.weak_ssl_tls_detected

  tags = merge(local.owasp_top_10_a02_2021_common_tags, {
    mitre_attack_ids = "TA0009:T1557"
  })
}

query "weak_ssl_tls_detected" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      http_user_agent is not null
      and (
        lower(http_user_agent) like '%sslv3%'
        or lower(http_user_agent) like '%tls1.0%'
        or lower(http_user_agent) like '%tls1.1%'
        or lower(request_uri) like '%downgrade_protocol%'
      )
      and scheme = 'https'
    order by
      tp_timestamp desc;
  EOQ
}

detection "insecure_deserialization_attempted" {
  title           = "Insecure Deserialization Attempted"
  description     = "Detect attempts to exploit insecure deserialization vulnerabilities which could lead to remote code execution or privilege escalation."
  documentation   = file("./detections/docs/insecure_deserialization_attempted.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.insecure_deserialization_attempted

  tags = merge(local.owasp_top_10_a08_2021_common_tags, {
    mitre_attack_ids = "TA0004:T1190"
  })
}

query "insecure_deserialization_attempted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- Java serialized objects
        lower(request_uri) like '%/invoke/%' 
        or lower(request_uri) like '%/readObject%'
        -- PHP specific
        or lower(request_uri) like '%/unserialize%'
        or lower(request_uri) like '%/deserialize%'
        -- Node.js specific
        or lower(request_uri) like '%/node-serialize%'
        -- Ruby/Rails specific
        or lower(request_uri) like '%/yaml/load%'
        -- .NET specific
        or lower(request_uri) like '%/viewstate%'
        or lower(request_uri) like '%/binary-formatter%'
      )
      and request_method = 'POST'
    order by
      tp_timestamp desc;
  EOQ
}

detection "unauthorized_package_access" {
  title           = "Unauthorized Package Access"
  description     = "Detect attempts to access or download untrusted packages or dependencies which could introduce supply chain risks."
  documentation   = file("./detections/docs/unauthorized_package_access.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.unauthorized_package_access

  tags = merge(local.owasp_top_10_a08_2021_common_tags, {
    mitre_attack_ids = "TA0001:T1195"
  })
}

query "unauthorized_package_access" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- NPM packages
        lower(request_uri) like '%/npm/registry/%' 
        -- PyPI packages
        or lower(request_uri) like '%/pypi/simple/%'
        -- Maven packages
        or lower(request_uri) like '%/maven2/%'
        -- Ruby gems
        or lower(request_uri) like '%/gems/%'
        -- NuGet packages
        or lower(request_uri) like '%/nuget/v3/%'
        -- Docker images
        or lower(request_uri) like '%/v2/library/%'
      )
      and remote_addr not in (
        '127.0.0.1',
        '::1'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "log_file_access_attempted" {
  title           = "Log File Access Attempted"
  description     = "Detect when a web server received requests attempting to access log files, which could indicate reconnaissance for sensitive information or attempts to cover tracks."
  documentation   = file("./detections/docs/log_file_access_attempted.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.log_file_access_attempted

  tags = merge(local.owasp_top_10_a09_2021_common_tags, {
    mitre_attack_ids = "TA0006:T1005"
  })
}

query "log_file_access_attempted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- Web server logs
        lower(request_uri) like '%/logs/%' 
        or lower(request_uri) like '%/log/%'
        or lower(request_uri) like '%.log'
        -- Apache specific logs
        or lower(request_uri) like '%/apache/logs/%'
        or lower(request_uri) like '%/apache2/logs/%'
        or lower(request_uri) like '%/httpd/logs/%'
        -- Application logs
        or lower(request_uri) like '%/var/log/%'
        or lower(request_uri) like '%/system32/logfiles/%'
        -- AWS/Cloud logs
        or lower(request_uri) like '%/cloudwatch/%'
        or lower(request_uri) like '%/cloudtrail/%'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "security_log_manipulation_attempted" {
  title           = "Security Log Manipulation Attempted"
  description     = "Detect when a web server received requests attempting to delete, modify, or tamper with security logs, which could indicate an attempt to cover tracks of malicious activity."
  documentation   = file("./detections/docs/security_log_manipulation_attempted.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.security_log_manipulation_attempted

  tags = merge(local.owasp_top_10_a09_2021_common_tags, {
    mitre_attack_ids = "TA0005:T1070"
  })
}

query "security_log_manipulation_attempted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and request_method in ('DELETE', 'PUT', 'POST')
      and (
        -- Log configuration files
        lower(request_uri) like '%/logging.conf%' 
        or lower(request_uri) like '%/log4j%'
        or lower(request_uri) like '%/logback%'
        or lower(request_uri) like '%/auditd.conf%'
        -- Log management endpoints
        or lower(request_uri) like '%/api/logs/delete%'
        or lower(request_uri) like '%/api/logs/clear%'
        or lower(request_uri) like '%/api/audit/delete%'
        or lower(request_uri) like '%/admin/logs/purge%'
        -- Common log files
        or lower(request_uri) like '%/var/log/audit%'
        or lower(request_uri) like '%/var/log/apache%'
        or lower(request_uri) like '%/var/log/messages%'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "vulnerable_component_access_attempted" {
  title           = "Vulnerable Component Access Attempted"
  description     = "Detect attempts to access known vulnerable components or exploit specific CVEs through web requests."
  documentation   = file("./detections/docs/vulnerable_component_access_attempted.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.vulnerable_component_access_attempted

  tags = merge(local.owasp_top_10_a06_2021_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

query "vulnerable_component_access_attempted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- Log4j/Log4Shell vulnerability
        lower(request_uri) like '%$${jndi:ldap://%'
        or lower(request_uri) like '%$${jndi:rmi://%'
        -- Spring4Shell vulnerability
        or lower(request_uri) like '%class.module.classLoader%'
        or lower(request_uri) like '%class.module.classLoader.resources%'
        -- Struts vulnerabilities
        or lower(request_uri) like '%?action=%24%7B%'
        or lower(request_uri) like '%multipart/form-data%'
        -- Apache OFBiz vulnerabilities
        or lower(request_uri) like '%/webtools/control/xmlrpc%'
        -- Drupal vulnerabilities
        or lower(request_uri) like '%/?q=node/add%'
        or lower(request_uri) like '%/user/register%'
        -- WordPress specific vulnerabilities
        or lower(request_uri) like '%/wp-content/plugins/wp-file-manager%'
        or lower(request_uri) like '%/wp-content/plugins/elementor%'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "outdated_software_version_detected" {
  title           = "Outdated Software Version Detected"
  description     = "Detect requests to or from outdated software versions that may contain known security vulnerabilities."
  documentation   = file("./detections/docs/outdated_software_version_detected.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.outdated_software_version_detected

  tags = merge(local.owasp_top_10_a06_2021_common_tags, {
    mitre_attack_ids = "TA0043:T1592"
  })
}

query "outdated_software_version_detected" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      http_user_agent is not null
      and (
        -- Outdated browsers
        lower(http_user_agent) like '%msie 6%'
        or lower(http_user_agent) like '%msie 7%'
        or lower(http_user_agent) like '%msie 8%'
        or lower(http_user_agent) like '%firefox/3.%'
        or lower(http_user_agent) like '%chrome/4%'
        -- Outdated frameworks in user agent
        or lower(http_user_agent) like '%wordpress/4.%' 
        or lower(http_user_agent) like '%drupal/7.%'
        or lower(http_user_agent) like '%joomla/3.%'
        -- Outdated libraries/tools
        or lower(http_user_agent) like '%openssl/1.0.%'
        or lower(http_user_agent) like '%curl/7.1%'
        or lower(http_user_agent) like '%jquery/1.%'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "ssrf_attempt_detected" {
  title           = "Server-Side Request Forgery Attempt Detected"
  description     = "Detect when a web server received requests that attempt to exploit server-side request forgery vulnerabilities."
  documentation   = file("./detections/docs/ssrf_attempt_detected.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.ssrf_attempt_detected

  tags = merge(local.owasp_top_10_a10_2021_common_tags, {
    mitre_attack_ids = "TA0009:T1219"
  })
}

query "ssrf_attempt_detected" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- Common SSRF patterns in URL parameters
        lower(request_uri) like '%url=http%'
        or lower(request_uri) like '%path=http%'
        or lower(request_uri) like '%uri=http%'
        or lower(request_uri) like '%src=http%'
        or lower(request_uri) like '%dest=http%'
        or lower(request_uri) like '%redirect=http%'
        or lower(request_uri) like '%return_to=http%'
        or lower(request_uri) like '%callback=http%'
        -- Non-standard port access attempts
        or lower(request_uri) like '%localhost%'
        or lower(request_uri) like '%127.0.0.1%'
        or lower(request_uri) like '%[0:0:0:0:0:0:0:1]%'
        -- Protocols that can be used in SSRF
        or lower(request_uri) like '%file://%'
        or lower(request_uri) like '%dict://%'
        or lower(request_uri) like '%gopher://%'
        or lower(request_uri) like '%ldap://%'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "cloud_metadata_access_attempted" {
  title           = "Cloud Metadata Service Access Attempted"
  description     = "Detect attempts to access cloud provider metadata services, which are common targets in SSRF attacks."
  documentation   = file("./detections/docs/cloud_metadata_access_attempted.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.cloud_metadata_access_attempted

  tags = merge(local.owasp_top_10_a10_2021_common_tags, {
    mitre_attack_ids = "TA0009:T1557"
  })
}

query "cloud_metadata_access_attempted" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- AWS metadata endpoints
        lower(request_uri) like '%169.254.169.254%'
        or lower(request_uri) like '%/latest/meta-data%'
        or lower(request_uri) like '%/latest/user-data%'
        or lower(request_uri) like '%/latest/dynamic%'
        -- GCP metadata endpoints
        or lower(request_uri) like '%metadata.google.internal%'
        or lower(request_uri) like '%/computeMetadata/v1%'
        -- Azure metadata endpoints
        or lower(request_uri) like '%169.254.169.254%'
        or lower(request_uri) like '%/metadata/instance%'
        -- DigitalOcean metadata endpoints
        or lower(request_uri) like '%169.254.169.254%'
        or lower(request_uri) like '%/metadata/v1%'
        -- Other common cloud metadata URLs
        or lower(request_uri) like '%/latest/api/token%'
        or lower(request_uri) like '%/iam/security-credentials/%'
      )
    order by
      tp_timestamp desc;
  EOQ
}
