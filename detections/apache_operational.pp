locals {
  apache_operational_common_tags = merge(local.apache_access_log_detections_common_tags, {
    category = "Operational"
  })
}

benchmark "apache_operational_detections" {
  title       = "Apache Operational Detections"
  description = "This benchmark contains operational detections when scanning Apache access logs."
  type        = "detection"
  children = [
    detection.apache_status_500_errors,
    detection.apache_missing_user_agent,
    detection.apache_large_payload_requests
  ]

  tags = merge(local.apache_operational_common_tags, {
    type = "Benchmark"
  })
}

detection "apache_status_500_errors" {
  title           = "HTTP 500 Internal Server Errors"
  description     = "Detect individual HTTP 500 Internal Server Error responses that indicate server-side failures."
  severity        = "high"
  display_columns = ["request_ip", "request_path", "request_method", "status_code", "timestamp"]

  query = query.apache_status_500_errors

  tags = merge(local.apache_operational_common_tags, {
    mitre_attack_id = "TA0040:T1499.004" # Impact:Application or System Exploitation
  })
}

query "apache_status_500_errors" {
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
      status = 500
    order by
      tp_timestamp desc;
  EOQ
}

detection "apache_missing_user_agent" {
  title           = "Missing User Agent Detected"
  description     = "Detect requests with missing user agent headers, which could indicate malicious tools or scripted attacks."
  severity        = "medium"
  display_columns = ["request_ip", "request_path", "request_method", "status_code", "timestamp"]

  query = query.apache_missing_user_agent

  tags = merge(local.apache_operational_common_tags, {
    mitre_attack_id = "TA0043:T1592" # Reconnaissance:Gather Victim Host Information
  })
}

query "apache_missing_user_agent" {
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
      http_user_agent is null
      or http_user_agent = '-'
      or http_user_agent = ''
    order by
      tp_timestamp desc;
  EOQ
}

detection "apache_large_payload_requests" {
  title           = "Large Payload Requests"
  description     = "Detect requests with unusually large body sizes that could indicate file uploads or data exfiltration."
  severity        = "medium"
  display_columns = ["request_ip", "request_path", "request_method", "body_bytes", "status_code", "timestamp"]

  query = query.apache_large_payload_requests

  tags = merge(local.apache_operational_common_tags, {
    mitre_attack_id = "TA0009:T1530,TA0010:T1048" # Collection:Data from Cloud Storage Object, Exfiltration:Exfiltration Over Alternative Protocol
  })
}

query "apache_large_payload_requests" {
  sql = <<-EOQ
    select
      remote_addr as request_ip,
      request_uri as request_path,
      request_method,
      body_bytes_sent as body_bytes,
      status as status_code,
      tp_timestamp as timestamp
    from
      apache_access_log
    where
      body_bytes_sent > 10485760  -- Larger than 10MB
    order by
      body_bytes_sent desc;
  EOQ
}
