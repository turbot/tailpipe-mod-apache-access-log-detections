locals {
  apache_compliance_common_tags = merge(local.apache_access_log_detections_common_tags, {
    category = "Compliance"
  })
}

benchmark "apache_compliance_detections" {
  title       = "Apache Compliance Detections"
  description = "This benchmark contains compliance-focused detections when scanning Apache access logs."
  type        = "detection"
  children = [
    detection.apache_pii_data_exposure,
    detection.apache_restricted_resource_access
  ]

  tags = merge(local.apache_compliance_common_tags, {
    type = "Benchmark"
  })
}

detection "apache_pii_data_exposure" {
  title           = "PII Data Exposure in URLs"
  description     = "Detect potential exposure of Personally Identifiable Information (PII) in URLs."
  severity        = "critical"
  display_columns = ["request_ip", "request_path", "pii_type", "status_code", "timestamp"]

  query = query.apache_pii_data_exposure

  tags = merge(local.apache_compliance_common_tags, {
    mitre_attack_id = "TA0006:T1552.001" # Credential Access:Credentials In Files
  })
}

query "apache_pii_data_exposure" {
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

detection "apache_restricted_resource_access" {
  title           = "Restricted Resource Access"
  description     = "Detect access attempts to restricted resources or administrative areas."
  severity        = "high"
  display_columns = ["request_ip", "request_path", "request_method", "status_code", "timestamp"]

  query = query.apache_restricted_resource_access

  tags = merge(local.apache_compliance_common_tags, {
    mitre_attack_id = "TA0001:T1190,TA0008:T1133" # Initial Access:Exploit Public-Facing Application, Lateral Movement:External Remote Services
  })
}

query "apache_restricted_resource_access" {
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