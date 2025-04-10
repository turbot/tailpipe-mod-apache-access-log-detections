locals {
  remote_command_execution_common_tags = merge(local.apache_access_log_detections_common_tags, {
    category = "Remote Command Execution"
  })
}

benchmark "remote_command_execution_detections" {
  title       = "Remote Command Execution (RCE) Detections"
  description = "This benchmark contains REC focused detections when scanning access logs."
  type        = "detection"
  children = [
    detection.log4shell_remote_command_execution_attempt,
    detection.spring4shell_remote_command_execution_attempt
  ]

  tags = merge(local.remote_command_execution_common_tags, {
    type = "Benchmark"
  })
}

detection "log4shell_remote_command_execution_attempt" {
  title           = "Log4Shell (Log4j) Remote Command Execution Attempt"
  description     = "Detects attempted exploitation of the Log4Shell vulnerability (CVE-2021-44228) in Log4j which can lead to remote code execution. These attacks typically use JNDI lookups through various protocols to load and execute malicious code."
  documentation   = file("./detections/docs/log4shell_remote_command_execution_attempt.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.log4shell_remote_command_execution_attempt

  tags = merge(local.remote_command_execution_common_tags, {
    mitre_attack_ids = "TA0002:T1059"
  })
}

query "log4shell_remote_command_execution_attempt" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      (
        -- Basic Log4j patterns
        (
          -- Standard JNDI pattern
          request_uri ilike '%$${jndi:%'
          or http_user_agent ilike '%$${jndi:%'
          -- Nested expressions - potential bypass technique
          or request_uri ~ '\\$\\{[^\\}]{0,15}\\$\\{'
          or http_user_agent ~ '\\$\\{[^\\}]{0,15}\\$\\{'
          -- Looking for ctx (another common pattern)
          or request_uri ~ '\\$\\{ctx:'
          or http_user_agent ~ '\\$\\{ctx:'
          -- HTML entity encoded variants
          or request_uri ilike '%&dollar;{jndi:%'
          or http_user_agent ilike '%&dollar;{jndi:%'
          or request_uri ilike '%$&lbrace;jndi:%'
          or http_user_agent ilike '%$&lbrace;jndi:%'
          or request_uri ilike '%&dollar;&lbrace;jndi:%'
          or http_user_agent ilike '%&dollar;&lbrace;jndi:%'
          -- Common obfuscation techniques
          or request_uri ~ '\\$\\{lower:\\$\\{upper:j\\}ndi'
          or http_user_agent ~ '\\$\\{lower:\\$\\{upper:j\\}ndi'
          or request_uri ~ '\\$\\{:-j\\}\\$\\{:-n\\}\\$\\{:-d\\}\\$\\{:-i\\}'
          or http_user_agent ~ '\\$\\{:-j\\}\\$\\{:-n\\}\\$\\{:-d\\}\\$\\{:-i\\}'
        )
      )
    order by
      tp_timestamp desc
  EOQ
}

detection "spring4shell_remote_command_execution_attempt" {
  title           = "Spring4Shell Remote Command Execution Attempt"
  description     = "Detects attempted exploitation of the Spring4Shell vulnerability (CVE-2022-22965) in Spring Framework which can lead to remote code execution. These attacks typically use malicious class-loading payloads to bypass protections and execute arbitrary code."
  documentation   = file("./detections/docs/spring4shell_remote_command_execution_attempt.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.spring4shell_remote_command_execution_attempt

  tags = merge(local.remote_command_execution_common_tags, {
    mitre_attack_ids = "TA0002:T1059"
  })
}

query "spring4shell_remote_command_execution_attempt" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      (
        -- Spring4Shell malicious class-loading payloads
        request_uri ~ '(?:class\\.module\\.classLoader\\.resources\\.context\\.parent\\.pipeline|springframework\\.context\\.support\\.FileSystemXmlApplicationContext)'
        or http_user_agent ~ '(?:class\\.module\\.classLoader\\.resources\\.context\\.parent\\.pipeline|springframework\\.context\\.support\\.FileSystemXmlApplicationContext)'
        -- URL-encoded variants
        or request_uri ~ '(?:class%2Emodule%2EclassLoader|springframework%2Econtext%2Esupport)'
        or http_user_agent ~ '(?:class%2Emodule%2EclassLoader|springframework%2Econtext%2Esupport)'
        -- Common Spring4Shell attack patterns
        or request_uri ilike '%class.module.classLoader%'
        or http_user_agent ilike '%class.module.classLoader%'
        or request_uri ilike '%springframework.context.support%'
        or http_user_agent ilike '%springframework.context.support%'
      )
    order by
      tp_timestamp desc
  EOQ
}
