locals {
  apache_security_common_tags = merge(local.apache_access_log_detections_common_tags, {
    category = "Security"
  })
}

benchmark "apache_security_detections" {
  title       = "Apache Security Detections"
  description = "This benchmark contains security-focused detections when scanning Apache access logs."
  type        = "detection"
  children = [
    detection.apache_sql_injection_attempts,
    detection.apache_directory_traversal_attempts,
    detection.apache_brute_force_auth_attempts,
    detection.apache_suspicious_user_agents,
    detection.apache_xss_attempts,
    detection.apache_sensitive_file_access,
    detection.apache_unusual_http_methods,
    detection.apache_web_shell_detection,
    # detection.apache_log4j_exploitation_attempts,
    detection.apache_api_key_exposure
  ]

  tags = merge(local.apache_security_common_tags, {
    type = "Benchmark"
  })
}

detection "apache_sql_injection_attempts" {
  title           = "SQL Injection Attempts Detected"
  description     = "Detect potential SQL injection attempts in URL parameters and request paths."
  severity        = "critical"
  display_columns = ["request_ip", "request_path", "request_method", "status_code", "timestamp"]

  query = query.apache_sql_injection_attempts

  tags = merge(local.apache_security_common_tags, {
    mitre_attack_ids = "TA0009:T1190"
  })
}

query "apache_sql_injection_attempts" {
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

detection "apache_directory_traversal_attempts" {
  title           = "Directory Traversal Attempts Detected"
  description     = "Detect attempts to traverse directories using ../ patterns in URLs."
  severity        = "high"
  display_columns = ["request_ip", "request_path", "request_method", "status_code", "timestamp"]

  query = query.apache_directory_traversal_attempts

  tags = merge(local.apache_security_common_tags, {
    mitre_attack_ids = "TA0009:T1083"
  })
}

query "apache_directory_traversal_attempts" {
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

detection "apache_brute_force_auth_attempts" {
  title           = "Authentication Brute Force Attempts"
  description     = "Detect potential brute force authentication attempts based on high frequency of 401/403 errors from the same IP."
  severity        = "high"
  display_columns = ["request_ip", "target_path", "failed_attempts", "first_attempt", "last_attempt"]

  query = query.apache_brute_force_auth_attempts

  tags = merge(local.apache_security_common_tags, {
    mitre_attack_ids = "TA0006:T1110"
  })
}

query "apache_brute_force_auth_attempts" {
  sql = <<-EOQ
    with failed_auths as (
      select
        remote_addr as request_ip,
        request_uri as target_path,
        count(*) as failed_attempts,
        min(tp_timestamp) as first_attempt,
        max(tp_timestamp) as last_attempt
      from
        apache_access_log
      where
        status in (401, 403)
        and request_uri is not null
      group by
        remote_addr, request_uri
      having
        count(*) >= 5
        and (max(tp_timestamp) - min(tp_timestamp)) <= interval '5 minutes'
    )
    select
      *
    from
      failed_auths
    order by
      failed_attempts desc;
  EOQ
}

detection "apache_suspicious_user_agents" {
  title           = "Suspicious User Agents Detected"
  description     = "Detect requests from known malicious or suspicious user agents."
  severity        = "medium"
  display_columns = ["request_ip", "user_agent", "request_path", "status_code", "timestamp"]

  query = query.apache_suspicious_user_agents

  tags = merge(local.apache_security_common_tags, {
    mitre_attack_ids = "TA0043:T1592"
  })
}

query "apache_suspicious_user_agents" {
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

detection "apache_xss_attempts" {
  title           = "Cross-Site Scripting (XSS) Attempts"
  description     = "Detect potential XSS attacks in request parameters and paths."
  severity        = "critical"
  display_columns = ["request_ip", "request_path", "request_method", "status_code", "timestamp"]

  query = query.apache_xss_attempts

  tags = merge(local.apache_security_common_tags, {
    mitre_attack_ids = "TA0009:T1059.007"
  })
}

query "apache_xss_attempts" {
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

detection "apache_sensitive_file_access" {
  title           = "Sensitive File Access Attempts"
  description     = "Detect attempts to access sensitive files or directories."
  severity        = "high"
  display_columns = ["request_ip", "request_path", "request_method", "status_code", "timestamp"]

  query = query.apache_sensitive_file_access

  tags = merge(local.apache_security_common_tags, {
    mitre_attack_ids = "TA0009:T1083"
  })
}

query "apache_sensitive_file_access" {
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

detection "apache_unusual_http_methods" {
  title           = "Unusual HTTP Methods Detected"
  description     = "Detect requests using unusual or potentially dangerous HTTP methods."
  severity        = "medium"
  display_columns = ["request_ip", "request_method", "request_path", "status_code", "timestamp"]

  query = query.apache_unusual_http_methods

  tags = merge(local.apache_security_common_tags, {
    mitre_attack_ids = "TA0009:T1213"
  })
}

query "apache_unusual_http_methods" {
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

detection "apache_web_shell_detection" {
  title           = "Web Shell Upload or Access Attempts"
  description     = "Detect potential web shell uploads or access attempts."
  severity        = "critical"
  display_columns = ["request_ip", "request_path", "request_method", "status_code", "timestamp"]

  query = query.apache_web_shell_detection

  tags = merge(local.apache_security_common_tags, {
    mitre_attack_ids = "TA0003:T1505.003"
  })
}

query "apache_web_shell_detection" {
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

# detection "apache_log4j_exploitation_attempts" {
#   title           = "Log4j Exploitation Attempts"
#   description     = "Detect potential Log4j/Log4Shell exploitation attempts in request parameters."
#   severity        = "critical"
#   display_columns = ["request_ip", "request_path", "request_method", "status_code", "timestamp"]

#   query = query.apache_log4j_exploitation_attempts

#   tags = merge(local.apache_security_common_tags, {
#     mitre_attack_ids = "TA0002:T1190"
#   })
# }

# query "apache_log4j_exploitation_attempts" {
#   sql = <<-EOQ
#     select
#       remote_addr as request_ip,
#       request_uri as request_path,
#       request_method,
#       status as status_code,
#       tp_timestamp as timestamp
#     from
#       apache_access_log
#     where
#       (
#         request_uri is not null
#         and (
#           lower(request_uri) like '%${jndi : % '
#   or lower(request_uri) like ' % $ % 7 bjndi : % '
#   or lower(request_uri) like ' % $ { % '
#     or lower(request_uri) like ' % $ % 7 b % '
#   )
# )
# or(
#   http_user_agent is not null
#   and(
#     lower(http_user_agent) like ' % $ { jndi : % '
#       or lower(http_user_agent) like ' % $ % 7 bjndi : % '
#     )
#   )
#   order by
#   tp_timestamp desc;
#   EOQ
# }

detection "apache_api_key_exposure" {
  title           = "API Key or Token Exposure"
  description     = "Detect potential exposure of API keys or tokens in URLs."
  severity        = "critical"
  display_columns = ["request_ip", "request_path", "token_type", "status_code", "timestamp"]

  query = query.apache_api_key_exposure

  tags = merge(local.apache_security_common_tags, {
    mitre_attack_ids = "TA0006:T1552"
  })
}

query "apache_api_key_exposure" {
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