locals {
  apache_performance_common_tags = merge(local.apache_access_log_detections_common_tags, {
    category = "Performance"
  })
}

benchmark "apache_performance_detections" {
  title       = "Apache Performance Detections"
  description = "This benchmark contains performance-focused detections when scanning Apache access logs."
  type        = "detection"
  children = [
    detection.apache_very_slow_requests,
    detection.apache_large_static_file_requests,
    detection.apache_timeout_errors
  ]

  tags = merge(local.apache_performance_common_tags, {
    type = "Benchmark"
  })
}

detection "apache_very_slow_requests" {
  title           = "Very Slow HTTP Requests"
  description     = "Detect individual HTTP requests with abnormally high response times."
  severity        = "high"
  display_columns = ["request_ip", "request_path", "request_method", "response_time", "status_code", "timestamp"]

  query = query.apache_very_slow_requests

  tags = merge(local.apache_performance_common_tags, {
    mitre_attack_id = "TA0040:T1499.003" # Impact:Application Exhaustion Flood
  })
}

query "apache_very_slow_requests" {
  sql = <<-EOQ
    select
      remote_addr as request_ip,
      request_uri as request_path,
      request_method,
      request_time as response_time,
      status as status_code,
      tp_timestamp as timestamp
    from
      apache_access_log
    where
      request_time > 5  -- Requests taking more than 5 seconds
    order by
      request_time desc;
  EOQ
}

detection "apache_large_static_file_requests" {
  title           = "Large Static File Requests"
  description     = "Detect requests for large static files that could impact server performance."
  severity        = "medium"
  display_columns = ["request_ip", "request_path", "file_type", "body_bytes", "status_code", "timestamp"]

  query = query.apache_large_static_file_requests

  tags = merge(local.apache_performance_common_tags, {
    mitre_attack_id = "TA0040:T1499.002" # Impact:Service Exhaustion Flood
  })
}

query "apache_large_static_file_requests" {
  sql = <<-EOQ
    select
      remote_addr as request_ip,
      request_uri as request_path,
      case
        when lower(request_uri) like '%.jpg' or lower(request_uri) like '%.jpeg' then 'Image (JPEG)'
        when lower(request_uri) like '%.png' then 'Image (PNG)'
        when lower(request_uri) like '%.gif' then 'Image (GIF)'
        when lower(request_uri) like '%.pdf' then 'Document (PDF)'
        when lower(request_uri) like '%.mp4' or lower(request_uri) like '%.avi' or lower(request_uri) like '%.mov' then 'Video'
        when lower(request_uri) like '%.mp3' or lower(request_uri) like '%.wav' then 'Audio'
        when lower(request_uri) like '%.zip' or lower(request_uri) like '%.tar' or lower(request_uri) like '%.gz' then 'Archive'
        else 'Other'
      end as file_type,
      body_bytes_sent as body_bytes,
      status as status_code,
      tp_timestamp as timestamp
    from
      apache_access_log
    where
      body_bytes_sent > 5242880  -- Larger than 5MB
      and (
        lower(request_uri) like '%.jpg' or
        lower(request_uri) like '%.jpeg' or
        lower(request_uri) like '%.png' or
        lower(request_uri) like '%.gif' or
        lower(request_uri) like '%.pdf' or
        lower(request_uri) like '%.mp4' or
        lower(request_uri) like '%.avi' or
        lower(request_uri) like '%.mov' or
        lower(request_uri) like '%.mp3' or
        lower(request_uri) like '%.wav' or
        lower(request_uri) like '%.zip' or
        lower(request_uri) like '%.tar' or
        lower(request_uri) like '%.gz'
      )
    order by
      body_bytes_sent desc;
  EOQ
}

detection "apache_timeout_errors" {
  title           = "Request Timeout Errors"
  description     = "Detect HTTP 408 Request Timeout or 504 Gateway Timeout errors indicating resource constraints."
  severity        = "high"
  display_columns = ["request_ip", "request_path", "request_method", "status_code", "timestamp"]

  query = query.apache_timeout_errors

  tags = merge(local.apache_performance_common_tags, {
    mitre_attack_id = "TA0040:T1499.004" # Impact:Application or System Exploitation
  })
}

query "apache_timeout_errors" {
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
      status in (408, 504)  -- Request Timeout or Gateway Timeout
    order by
      tp_timestamp desc;
  EOQ
}
