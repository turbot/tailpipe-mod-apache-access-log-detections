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
    detection.apache_pii_data_exposed_in_url,
    detection.apache_restricted_resource_accessed,
    detection.apache_unauthorized_ip_access_detected,
    detection.apache_data_privacy_requirement_violated
  ]

  tags = merge(local.apache_compliance_common_tags, {
    type = "Benchmark"
  })
}

detection "apache_pii_data_exposed_in_url" {
  title           = "Apache PII Data Exposed In URL"
  description     = "Detect when an Apache web server logged Personally Identifiable Information (PII) in URLs to check for potential data privacy violations, regulatory non-compliance, and sensitive information disclosure."
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.apache_pii_data_exposed_in_url

  tags = merge(local.apache_compliance_common_tags, {
    mitre_attack_id = "TA0006:T1552.001" # Credential Access:Credentials In Files
  })
}

query "apache_pii_data_exposed_in_url" {
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

detection "apache_restricted_resource_accessed" {
  title           = "Apache Restricted Resource Accessed"
  description     = "Detect when an Apache web server processed requests to restricted resources or administrative areas to check for unauthorized access attempts, privilege escalation, or security policy violations."
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.apache_restricted_resource_accessed

  tags = merge(local.apache_compliance_common_tags, {
    mitre_attack_id = "TA0001:T1190,TA0008:T1133" # Initial Access:Exploit Public-Facing Application, Lateral Movement:External Remote Services
  })
}

query "apache_restricted_resource_accessed" {
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

detection "apache_unauthorized_ip_access_detected" {
  title           = "Apache Unauthorized IP Access Detected"
  description     = "Detect when an Apache web server received requests from unauthorized IP ranges or geographic locations to check for potential security policy violations, access control bypasses, or geofencing compliance issues."
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.apache_unauthorized_ip_access_detected

  tags = merge(local.apache_compliance_common_tags, {
    mitre_attack_id = "TA0008:T1133,TA0003:T1078.004" # Lateral Movement:External Remote Services, Persistence:Cloud Accounts
  })
}

query "apache_unauthorized_ip_access_detected" {
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

detection "apache_data_privacy_requirement_violated" {
  title           = "Apache Data Privacy Requirement Violated"
  description     = "Detect when an Apache web server processed requests that potentially violate data privacy requirements to check for regulatory compliance issues, sensitive data handling violations, or privacy policy infractions."
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.apache_data_privacy_requirement_violated

  tags = merge(local.apache_compliance_common_tags, {
    mitre_attack_id = "TA0009:T1530,TA0006:T1552.001" # Collection:Data from Cloud Storage, Credential Access:Credentials In Files
  })
}

query "apache_data_privacy_requirement_violated" {
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