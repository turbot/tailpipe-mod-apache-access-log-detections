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
    detection.pii_data_exposed_in_url,
    detection.restricted_resource_accessed,
    detection.sensitive_file_access_attempted,
    detection.sql_injection_attempted,
    detection.suspicious_user_agent_detected,
    detection.unauthorized_ip_access_detected,
    detection.unusual_http_method_used,
    detection.web_shell_access_attempted,
    detection.xss_attempted
  ]

  tags = merge(local.security_common_tags, {
    type = "Benchmark"
  })
}

detection "sql_injection_attempted" {
  title           = "SQL Injection Attempted"
  description     = "Detect when a web server was targeted by SQL injection attempts to check for potential database compromise, data theft, or unauthorized system access."
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
      remote_addr as request_ip,
      request_uri as request_path,
      request_method,
      status as status_code,
      tp_timestamp as timestamp
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
      remote_addr as request_ip,
      request_uri as request_path,
      request_method,
      status as status_code,
      tp_timestamp as timestamp
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
      remote_addr as request_ip,
      request_uri as request_path,
      request_method,
      status as status_code,
      tp_timestamp as timestamp
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
      remote_addr as request_ip,
      http_user_agent as user_agent,
      request_uri as request_path,
      status as status_code,
      tp_timestamp as timestamp
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
      remote_addr as request_ip,
      request_uri as request_path,
      request_method,
      status as status_code,
      tp_timestamp as timestamp
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
      remote_addr as request_ip,
      request_uri as request_path,
      request_method,
      status as status_code,
      tp_timestamp as timestamp
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
      remote_addr as request_ip,
      request_method,
      request_uri as request_path,
      status as status_code,
      tp_timestamp as timestamp
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
      remote_addr as request_ip,
      request_uri as request_path,
      request_method,
      status as status_code,
      tp_timestamp as timestamp
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
      remote_addr as request_ip,
      request_uri as request_path,
      case
        when request_uri ~ '(?i)[a-z0-9]{32,}' then 'Potential API Key'
        when request_uri ~ '(?i)bearer\s+[a-zA-Z0-9-._~+/]+=*' then 'Bearer Token'
        when request_uri ~ '(?i)key=[a-zA-Z0-9-]{20,}' then 'API Key Parameter'
        when request_uri ~ '(?i)token=[a-zA-Z0-9-]{20,}' then 'Token Parameter'
        when request_uri ~ '(?i)client_secret=[a-zA-Z0-9-]{20,}' then 'Client Secret'
      end as token_type,
      status as status_code,
      tp_timestamp as timestamp
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
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.pii_data_exposed_in_url

  tags = merge(local.compliance_common_tags, {
    mitre_attack_id = "TA0006:T1552.001" # Credential Access:Credentials In Files
  })
}

query "pii_data_exposed_in_url" {
  sql = <<-EOQ
    with pii_patterns as (
      select 
        request_uri as request_path,
        remote_addr as request_ip,
        status as status_code,
        tp_timestamp as timestamp,
        case
          when request_uri ~ '[0-9]{3}-[0-9]{2}-[0-9]{4}' then 'SSN'
          when request_uri ~ '[0-9]{16}' then 'Credit Card'
          when request_uri ~ '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' then 'Email'
          when request_uri ~ '(?:password|passwd|pwd)=[^&]+' then 'Password'
          when request_uri ~ '[0-9]{10}' then 'Phone Number'
        end as pii_type
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
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.restricted_resource_accessed

  tags = merge(local.compliance_common_tags, {
    mitre_attack_id = "TA0001:T1190,TA0008:T1133" # Initial Access:Exploit Public-Facing Application, Lateral Movement:External Remote Services
  })
}

query "restricted_resource_accessed" {
  sql = <<-EOQ
    select
      remote_addr as request_ip,
      request_uri as request_path,
      request_method,
      status as status_code,
      tp_timestamp as timestamp
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
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.unauthorized_ip_access_detected

  tags = merge(local.compliance_common_tags, {
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
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.data_privacy_requirement_violated

  tags = merge(local.compliance_common_tags, {
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