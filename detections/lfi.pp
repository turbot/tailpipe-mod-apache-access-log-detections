locals {
  local_file_inclusion_common_tags = merge(local.apache_access_log_detections_common_tags, {
    category = "Security"
    attack_type = "Local File Inclusion"
  })
}

benchmark "local_file_inclusion_detections" {
  title       = "Local File Inclusion (LFI) Detections"
  description = "This benchmark contains detections for Local File Inclusion (LFI) attacks which could expose sensitive system or application files."
  type        = "detection"
  children = [
    detection.encoded_path_traversal_attack,
    detection.header_based_lfi_attempt,
    detection.hidden_file_access_attempt,
    detection.malicious_scanner,
    detection.os_file_access_attempt,
    detection.path_traversal_attack,
    detection.restricted_file_access_attempt,
    detection.user_agent_attack,
  ]

  tags = merge(local.local_file_inclusion_common_tags, {
    type = "Benchmark"
  })
}

detection "path_traversal_attack" {
  title           = "Path Traversal Attack"
  description     = "Detect when a web server received requests with path traversal patterns like '../' to check for attempts to access files outside the web root directory."
  documentation   = file("./detections/docs/path_traversal_attack.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.path_traversal_attack

  tags = merge(local.local_file_inclusion_common_tags, {
    mitre_attack_ids = "TA0001:T1083"
  })
}

query "path_traversal_attack" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      (
        request_uri is not null
        and (
          -- Basic path traversal patterns
          request_uri ilike '%../%'
          or request_uri ilike '%/../%'
          or request_uri ilike '%/./%'
          or request_uri ilike '%/.%'
          or request_uri ilike '%\\..\\%'
          or request_uri ilike '%\\.\\%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "encoded_path_traversal_attack" {
  title           = "Encoded Path Traversal Attack"
  description     = "Detect when a web server received requests with URL-encoded or otherwise obfuscated path traversal patterns to evade basic security controls."
  documentation   = file("./detections/docs/encoded_path_traversal_attack.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.encoded_path_traversal_attack

  tags = merge(local.local_file_inclusion_common_tags, {
    mitre_attack_ids = "TA0001:T1083"
  })
}

query "encoded_path_traversal_attack" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- URL-encoded variants (percent encoding)
        request_uri ilike '%..%2f%'
        or request_uri ilike '%..%2F%'
        or request_uri ilike '%%2e%2e%2f%'
        or request_uri ilike '%%2E%2E%2F%'
        -- Double-encoded variants
        or request_uri ilike '%..%252f%'
        or request_uri ilike '%..%252F%'
        or request_uri ilike '%%252e%252e%252f%'
        or request_uri ilike '%%252E%252E%252F%'
        -- Unicode/UTF-8 encoded variants
        or request_uri ilike '%u002e%u002e%u002f%'
        or request_uri ilike '%u002E%u002E%u002F%'
        -- Backslash variants
        or request_uri ilike '%..\\%'
        or request_uri ilike '%..%5c%'
        or request_uri ilike '%..%5C%'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "os_file_access_attempt" {
  title           = "OS File Access Attempt"
  description     = "Detect when a web server received requests attempting to access common operating system files to check for LFI vulnerabilities targeting system files."
  documentation   = file("./detections/docs/os_file_access_attempt.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.os_file_access_attempt

  tags = merge(local.local_file_inclusion_common_tags, {
    mitre_attack_ids = "TA0001:T1083"
  })
}

query "os_file_access_attempt" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- Unix/Linux system files
        request_uri ilike '%/etc/passwd%'
        or request_uri ilike '%/etc/shadow%'
        or request_uri ilike '%/etc/hosts%'
        or request_uri ilike '%/etc/issue%'
        or request_uri ilike '%/proc/self/%'
        or request_uri ilike '%/proc/version%'
        or request_uri ilike '%/var/log/%'
        -- Windows system files
        or request_uri ilike '%win.ini%'
        or request_uri ilike '%system32%'
        or request_uri ilike '%boot.ini%'
        or request_uri ilike '%windows/system.ini%'
        or request_uri ilike '%autoexec.bat%'
        or request_uri ilike '%config.sys%'
        -- Common web server files
        or request_uri ilike '%/usr/local/apache%'
        or request_uri ilike '%/usr/local/etc/httpd%'
        or request_uri ilike '%/var/www/%'
        or request_uri ilike '%/var/apache%'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "restricted_file_access_attempt" {
  title           = "Restricted File Access Attempt"
  description     = "Detect when a web server received requests for restricted files such as application source code, configuration files, or internal application data."
  documentation   = file("./detections/docs/restricted_file_access_attempt.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.restricted_file_access_attempt

  tags = merge(local.local_file_inclusion_common_tags, {
    mitre_attack_ids = "TA0001:T1083"
  })
}

query "restricted_file_access_attempt" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- Source code/config files
        request_uri ilike '%.conf%'
        or request_uri ilike '%.config%'
        or request_uri ilike '%.ini%'
        or request_uri ilike '%.inc%'
        or request_uri ilike '%.sql%'
        or request_uri ilike '%.bak%'
        or request_uri ilike '%.old%'
        or request_uri ilike '%.backup%'
        -- Application files
        or request_uri ilike '%.php.swp%'
        or request_uri ilike '%.php~%'
        or request_uri ilike '%.jsp.old%'
        or request_uri ilike '%.jsp~%'
        or request_uri ilike '%.asp.bak%'
        or request_uri ilike '%.aspx~%'
        or request_uri ilike '%/WEB-INF/%'
        or request_uri ilike '%/META-INF/%'
        -- Database files
        or request_uri ilike '%.db%'
        or request_uri ilike '%.sqlite%'
        or request_uri ilike '%.mdb%'
        or request_uri ilike '%.accdb%'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "hidden_file_access_attempt" {
  title           = "Hidden File Access Attempt"
  description     = "Detect attempts to access hidden files and directories, including version control repositories and sensitive configuration files."
  documentation   = file("./detections/docs/hidden_file_access_attempt.md")
  severity        = "medium"
  display_columns = local.detection_display_columns

  query = query.hidden_file_access_attempt

  tags = merge(local.local_file_inclusion_common_tags, {
    mitre_attack_ids = "TA0001:T1083"
  })
}

query "hidden_file_access_attempt" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- Hidden files and directories
        request_uri ilike '%/.git/%'
        or request_uri ilike '%/.svn/%'
        or request_uri ilike '%/.DS_Store%'
        or request_uri ilike '%/.env%'
        or request_uri ilike '%/.aws/%'
        or request_uri ilike '%/.ssh/%'
        or request_uri ilike '%/.bash_history%'
        or request_uri ilike '%/.htaccess%'
        or request_uri ilike '%/.htpasswd%'
        or request_uri ilike '%/.config/%'
        or request_uri ilike '%/.vscode/%'
        or request_uri ilike '%/.idea/%'
        -- Docker/Kubernetes files
        or request_uri ilike '%/docker-compose%'
        or request_uri ilike '%/Dockerfile%'
        or request_uri ilike '%/kubernetes/%'
        or request_uri ilike '%/kubeconfig%'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "malicious_scanner" {
  title           = "Malicious Scanner or Attack Tool"
  description     = "Detect when known penetration testing or vulnerability scanning tools are used against the web server. These tools are often used for reconnaissance before targeted attacks."
  documentation   = file("./detections/docs/malicious_scanner.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.malicious_scanner

  tags = merge(local.local_file_inclusion_common_tags, {
    mitre_attack_ids = "TA0043:T1592"
  })
}

query "malicious_scanner" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      http_user_agent is not null
      and (
        -- SQLi tools
        http_user_agent ilike '%sqlmap%'
        or http_user_agent ilike '%sqlninja%'
        or http_user_agent ilike '%havij%'
        or http_user_agent ilike '%sql injection%'
        or http_user_agent ilike '%sql power injector%'
        -- LFI/scanning tools
        or http_user_agent ilike '%nikto%'
        or http_user_agent ilike '%dirbuster%'
        or http_user_agent ilike '%gobuster%'
        or http_user_agent ilike '%dotdotpwn%'
        or http_user_agent ilike '%w3af%'
        or http_user_agent ilike '%nessus%'
        or http_user_agent ilike '%acunetix%'
        or http_user_agent ilike '%burpsuite%'
        or http_user_agent ilike '%burp suite%'
        or http_user_agent ilike '%nmap%'
        or http_user_agent ilike '%ZAP/%'
        or http_user_agent ilike '%OWASP ZAP%'
        or http_user_agent ilike '%Wfuzz/%'
        or http_user_agent ilike '%masscan%'
        -- Generic attack tools
        or http_user_agent ilike '%metasploit%'
        or http_user_agent ilike '%hydra%'
        or http_user_agent ilike '%wget/%'
        or http_user_agent ilike '%curl/%'
        or http_user_agent = 'python-requests'
        or http_user_agent = 'python-urllib'
        or http_user_agent = ''
        or http_user_agent is null
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "user_agent_attack" {
  title           = "User Agent Attack"
  description     = "Detect when a web server received requests with attack patterns in the User-Agent header. This can indicate attempts to exploit vulnerable software or bypass security controls."
  documentation   = file("./detections/docs/user_agent_attack.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.user_agent_attack

  tags = merge(local.local_file_inclusion_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

query "user_agent_attack" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      http_user_agent is not null
      and (
        -- SQL Injection patterns
        http_user_agent ilike '%union%select%'
        or http_user_agent ilike '%select%from%'
        or http_user_agent ilike '%insert%into%'
        or http_user_agent ilike '%delete%from%'
        or http_user_agent ilike '%update%set%'
        or http_user_agent ilike '%drop%table%'
        or http_user_agent ilike '%1=1%'
        or http_user_agent ilike '%1%=%1%'
        or http_user_agent ilike '%sleep(%'
        or http_user_agent ilike '%benchmark(%'
        -- LFI patterns
        or http_user_agent ilike '%../%'
        or http_user_agent ilike '%/../%'
        or http_user_agent ilike '%/./%'
        or http_user_agent ilike '%\\..\\%'
        or http_user_agent ilike '%\\.\\%'
        or http_user_agent ilike '%/etc/passwd%'
        or http_user_agent ilike '%/etc/shadow%'
        or http_user_agent ilike '%/win.ini%'
        or http_user_agent ilike '%c:\\windows%'
        -- XSS patterns
        or http_user_agent ilike '%<script%'
        or http_user_agent ilike '%alert(%'
        or http_user_agent ilike '%onerror=%'
        or http_user_agent ilike '%onload=%'
        -- OS Command injection
        or http_user_agent ilike '%;%'
        or http_user_agent ilike '%&&%'
        or http_user_agent ilike '%||%'
        or http_user_agent ilike '%`%'
        or http_user_agent ilike '%$(%)%'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "header_based_lfi_attempt" {
  title           = "Header-Based LFI Attempt"
  description     = "Detect when a web server received requests with LFI attack patterns in the User-Agent or other headers, which may indicate attempts to bypass basic WAF protections."
  documentation   = file("./detections/docs/header_based_lfi_attempt.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.header_based_lfi_attempt

  tags = merge(local.local_file_inclusion_common_tags, {
    mitre_attack_ids = "TA0001:T1190"
  })
}

query "header_based_lfi_attempt" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      http_user_agent is not null
      and (
        -- Path traversal in User-Agent
        http_user_agent ilike '%../%'
        or http_user_agent ilike '%/../%'
        or http_user_agent ilike '%\\..\\%'
        or http_user_agent ilike '%\\.\\%'
        -- Encoded path traversal in User-Agent
        or http_user_agent ilike '%..%2f%'
        or http_user_agent ilike '%..%2F%'
        or http_user_agent ilike '%%2e%2e%2f%'
        or http_user_agent ilike '%%2E%2E%2F%'
        or http_user_agent ilike '%..%5c%'
        or http_user_agent ilike '%..%5C%'
        -- OS file access in User-Agent
        or http_user_agent ilike '%/etc/passwd%'
        or http_user_agent ilike '%/etc/shadow%'
        or http_user_agent ilike '%/etc/hosts%'
        or http_user_agent ilike '%/proc/self/%'
        or http_user_agent ilike '%win.ini%'
        or http_user_agent ilike '%system32%'
        or http_user_agent ilike '%boot.ini%'
      )
    order by
      tp_timestamp desc;
  EOQ
}
