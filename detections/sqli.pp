locals {
  sql_injection_common_tags = merge(local.apache_access_log_detections_common_tags, {
    category = "SQL Injection"
  })
}

benchmark "sql_injection_detections" {
  title       = "SQL Injection (SQLi) Detections"
  description = "This benchmark contains SQLi focused detections when scanning access logs."
  type        = "detection"
  children = [
    detection.sql_injection_basic_attack,
    detection.sql_injection_blind_based,
    detection.sql_injection_error_based,
    detection.sql_injection_time_based,
    detection.sql_injection_union_based,
    detection.sql_injection_user_agent_based,
    detection.suspicious_automation_sqli,
  ]

  tags = merge(local.sql_injection_common_tags, {
    type = "Benchmark"
  })
}

detection "sql_injection_basic_attack" {
  title           = "SQL Injection Basic Attack"
  description     = "Detect basic SQL injection attempts targeting common SQL keywords and syntax patterns that might indicate an attempt to manipulate database queries."
  documentation   = file("./detections/docs/sql_injection_basic_attack.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.sql_injection_basic_attack

  tags = merge(local.sql_injection_common_tags, {
    mitre_attack_ids = "TA0009:T1190"
  })
}

query "sql_injection_basic_attack" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- Basic SQL commands
        request_uri ilike '%select%from%'
        or request_uri ilike '%insert%into%'
        or request_uri ilike '%delete%from%'
        or request_uri ilike '%update%set%'
        or request_uri ilike '%drop%table%'
        or request_uri ilike '%truncate%table%'
        or request_uri ilike '%create%table%'
        or request_uri ilike '%alter%table%'
        or request_uri ilike '%exec%xp_%'
        or request_uri ilike '%information_schema%'
        -- Common SQL injection patterns
        or request_uri ilike '%or%1=1%'
        or request_uri ilike '%or%1%=%1%'
        or request_uri ilike '%or%true%'
        or request_uri ilike '%/*%*/%'
        or request_uri ilike '%--+%'
        or request_uri ilike '%-- %'
        or request_uri ilike '%;--%'
        -- URL encoded variants
        or request_uri ilike '%\x27%'
        or request_uri ilike '%\x22%'
        or request_uri ilike '%\x3D\x3D%'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "sql_injection_union_based" {
  title           = "SQL Injection Union Based Attack"
  description     = "Detect UNION-based SQL injection attacks that attempt to join results from another query to the original query's results."
  documentation   = file("./detections/docs/sql_injection_union_based.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.sql_injection_union_based

  tags = merge(local.sql_injection_common_tags, {
    mitre_attack_ids = "TA0009:T1190"
  })
}

query "sql_injection_union_based" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- UNION-based patterns
        request_uri ilike '%union%select%'
        or request_uri ilike '%union%all%select%'
        or request_uri ilike '%union+select%'
        or request_uri ilike '%union+all+select%'
        -- URL encoded variants
        or request_uri ilike '%union%20select%'
        or request_uri ilike '%union%20all%20select%'
        or request_uri ilike '%union%09select%'
        or request_uri ilike '%union%0Aselect%'
        or request_uri ilike '%union%0Dselect%'
        -- Evasion techniques specific to UNION
        or request_uri ilike '%uni%on%sel%ect%'
        or request_uri ilike '%uni*/*/on/**/sel/**/ect%'
        or request_uri ilike '%un?on+sel?ct%'
        or request_uri ilike '%u%n%i%o%n%s%e%l%e%c%t%'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "sql_injection_blind_based" {
  title           = "SQL Injection Blind Based Attack"
  description     = "Detect blind SQL injection attacks that attempt to extract information from the database using boolean conditions or time delays."
  documentation   = file("./detections/docs/sql_injection_blind_based.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.sql_injection_blind_based

  tags = merge(local.sql_injection_common_tags, {
    mitre_attack_ids = "TA0009:T1190"
  })
}

query "sql_injection_blind_based" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- Blind condition checks
        request_uri ilike '%and%1=1%'
        or request_uri ilike '%and%1=2%'
        or request_uri ilike '%and%if%'
        or request_uri ilike '%case%when%'
        or request_uri ilike '%substr%(%'
        or request_uri ilike '%substring%(%'
        or request_uri ilike '%ascii%(%'
        or request_uri ilike '%length%(%'
        or request_uri ilike '%benchmark%(%'
        -- Blind patterns with comparison operators
        or request_uri ilike '%and+1>0%'
        or request_uri ilike '%and+1<2%'
        or request_uri ilike '%and+ascii(substring%'
        or request_uri ilike '%and+length(%)%'
        -- URL encoded variants common in blind injections
        or request_uri ilike '%and%20%'
        or request_uri ilike '%and%28select%'
        or request_uri ilike '%and%28case%'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "sql_injection_error_based" {
  title           = "SQL Injection Error Based Attack"
  description     = "Detect error-based SQL injection attacks that attempt to extract information from database error messages."
  documentation   = file("./detections/docs/sql_injection_error_based.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.sql_injection_error_based

  tags = merge(local.sql_injection_common_tags, {
    mitre_attack_ids = "TA0009:T1190"
  })
}

query "sql_injection_error_based" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- Error-based extraction patterns
        request_uri ilike '%convert%(%'
        or request_uri ilike '%cast%(%'
        or request_uri ilike '%extractvalue%(%'
        or request_uri ilike '%updatexml%(%'
        or request_uri ilike '%floor%(%'
        or request_uri ilike '%exp%(%'
        or request_uri ilike '%concat%(%'
        or request_uri ilike '%concat_ws%(%'
        or request_uri ilike '%group_concat%(%'
        -- Known error-based functions with database fingerprinting
        or request_uri ilike '%db_name%(%'
        or request_uri ilike '%@@version%'
        or request_uri ilike '%version%(%'
        or request_uri ilike '%pg_sleep%(%'
        or request_uri ilike '%sys.%'
        or request_uri ilike '%sys.xp_%'
        -- Common error triggers
        or request_uri ilike '%having%1=1%'
        or request_uri ilike '%order%by%'
        or request_uri ilike '%group%by%'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "sql_injection_time_based" {
  title           = "SQL Injection Time Based Attack"
  description     = "Detect time-based SQL injection attacks that attempt to extract information by causing delays in database response times."
  documentation   = file("./detections/docs/sql_injection_time_based.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.sql_injection_time_based

  tags = merge(local.sql_injection_common_tags, {
    mitre_attack_ids = "TA0009:T1190"
  })
}

query "sql_injection_time_based" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_uri is not null
      and (
        -- Time-based functions for various database types
        request_uri ilike '%sleep%(%'
        or request_uri ilike '%benchmark%(%'
        or request_uri ilike '%pg_sleep%(%'
        or request_uri ilike '%dbms_pipe.receive_message%(%'
        or request_uri ilike '%waitfor%delay%'
        or request_uri ilike '%GENERATE_SERIES%'
        -- Time-based with conditional logic
        or request_uri ilike '%if%sleep%'
        or request_uri ilike '%if%benchmark%'
        or request_uri ilike '%case%when%sleep%'
        or request_uri ilike '%and%sleep%'
        -- URL encoded variants
        or request_uri ilike '%and%20sleep%'
        or request_uri ilike '%or%20sleep%'
        or request_uri ilike '%waitfor%20delay%'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "sql_injection_user_agent_based" {
  title           = "SQL Injection User Agent Based Attack"
  description     = "Detect SQL injection attacks that use the User-Agent header rather than URL parameters to bypass WAF protections or input filtering."
  documentation   = file("./detections/docs/sql_injection_user_agent_based.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.sql_injection_user_agent_based

  tags = merge(local.sql_injection_common_tags, {
    mitre_attack_ids = "TA0009:T1190"
  })
}

query "sql_injection_user_agent_based" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      http_user_agent is not null
      and (
        -- Basic SQL injection patterns in User-Agent
        http_user_agent ilike '%select%from%'
        or http_user_agent ilike '%union%select%'
        or http_user_agent ilike '%insert%into%'
        or http_user_agent ilike '%update%set%'
        or http_user_agent ilike '%delete%from%'
        or http_user_agent ilike '%drop%table%'
        -- Common SQL comment markers and logic patterns
        or http_user_agent ilike '%--+%'
        or http_user_agent ilike '%-- %'
        or http_user_agent ilike '%;--%'
        or http_user_agent ilike '%/*%*/%'
        or http_user_agent ilike '%or%1=1%'
        or http_user_agent ilike '%or%1%=%1%'
        or http_user_agent ilike '%or%true%'
        -- Database-specific User-Agent attacks
        or http_user_agent ilike '%@@version%'
        or http_user_agent ilike '%information_schema%'
        or http_user_agent ilike '%sql_injectionte_master%'
        or http_user_agent ilike '%pg_tables%'
        or http_user_agent ilike '%sys.%'
        -- Time-based techniques
        or http_user_agent ilike '%sleep(%'
        or http_user_agent ilike '%benchmark(%'
        or http_user_agent ilike '%pg_sleep(%'
        or http_user_agent ilike '%waitfor%delay%'
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "suspicious_automation_sqli" {
  title           = "Suspicious Automation and SQL Injection Attempts"
  description     = "Detect potentially malicious automation combined with SQL injection patterns in requests, which indicates reconnaissance and probing for database vulnerabilities."
  documentation   = file("./detections/docs/suspicious_automation_sqli.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.suspicious_automation_sqli

  tags = merge(local.sql_injection_common_tags, {
    mitre_attack_ids = "TA0043:T1592,TA0009:T1190"
  })
}

query "suspicious_automation_sqli" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      -- SQL injection patterns in the request URI
      (
        request_uri ilike '%union%select%'
        or request_uri ilike '%select%from%'
        or request_uri ilike '%1=1%'
        or request_uri ilike '%information_schema%'
      )
      -- Combined with suspicious user agents
      and (
        -- Known SQLi tools
        http_user_agent ilike '%sqlmap%'
        or http_user_agent ilike '%havij%'
        or http_user_agent ilike '%sqlninja%'
        -- Generic automation tools often used for SQLi
        or http_user_agent ilike '%python%'
        or http_user_agent ilike '%curl/%'
        or http_user_agent ilike '%wget/%'
        or http_user_agent ilike '%go-http-client%'
        or http_user_agent ilike '%ruby%'
        or http_user_agent ilike '%perl%'
        -- Missing or highly suspicious user agents
        or http_user_agent = ''
        or http_user_agent is null
        or http_user_agent = 'Mozilla'
        or http_user_agent ilike '%vulnerable%'
      )
    order by
      tp_timestamp desc;
  EOQ
}
