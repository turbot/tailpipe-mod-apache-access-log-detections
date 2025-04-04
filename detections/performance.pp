locals {
  performance_common_tags = merge(local.apache_access_log_detections_common_tags, {
    category = "Performance"
  })
}

benchmark "performance_detections" {
  title       = "Performance Detections"
  description = "This benchmark contains performance-focused detections when scanning access logs."
  type        = "detection"
  children = [
    detection.very_slow_request_detected,
    detection.large_static_file_requested,
    detection.request_timeout_occurred,
    detection.slow_response_time_detected,
    detection.response_time_anomaly_detected,
    detection.high_traffic_endpoint_detected,
    detection.connection_pool_exhaustion_risk_detected
  ]

  tags = merge(local.performance_common_tags, {
    type = "Benchmark"
  })
}

detection "very_slow_request_detected" {
  title           = "Very Slow Request Detected"
  description     = "Detect when a web server processed HTTP requests with abnormally high response times to check for performance bottlenecks, resource contention, or potential DoS conditions."
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.very_slow_request_detected

  tags = merge(local.performance_common_tags, {
    mitre_attack_id = "TA0040:T1499.003" # Impact:Application Exhaustion Flood
  })
}

query "very_slow_request_detected" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      request_time > 5  -- Requests taking more than 5 seconds
    order by
      request_time desc;
  EOQ
}

detection "large_static_file_requested" {
  title           = "Large Static File Requested"
  description     = "Detect when a web server processed requests for large static files to check for potential bandwidth consumption, server load issues, or content delivery optimization opportunities."
  severity        = "medium"
  display_columns = local.detection_display_columns

  query = query.large_static_file_requested

  tags = merge(local.performance_common_tags, {
    mitre_attack_id = "TA0040:T1499.002" # Impact:Service Exhaustion Flood
  })
}

query "large_static_file_requested" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
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

detection "request_timeout_occurred" {
  title           = "Request Timeout Occurred"
  description     = "Detect when a web server returned HTTP 408 Request Timeout or 504 Gateway Timeout errors to check for resource constraints, server overload, or slow upstream services."
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.request_timeout_occurred

  tags = merge(local.performance_common_tags, {
    mitre_attack_id = "TA0040:T1499.004" # Impact:Application or System Exploitation
  })
}

query "request_timeout_occurred" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      status in (408, 504)  -- Request Timeout or Gateway Timeout
    order by
      tp_timestamp desc;
  EOQ
}

detection "slow_response_time_detected" {
  title           = "Slow Response Time Detected"
  description     = "Detect when a web server processed requests to endpoints with consistently high response times to check for performance bottlenecks, inefficient code paths, or database query issues."
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.slow_response_time_detected

  tags = merge(local.performance_common_tags, {
    mitre_attack_id = "TA0040:T1499.003,TA0040:T1496.001" # Impact:Application Exhaustion Flood, Impact:Compute Hijacking
  })
}

query "slow_response_time_detected" {
  sql = <<-EOQ
    with response_stats as (
      select
        request_uri as endpoint,
        count(*) as request_count,
        avg(request_time) as avg_response_time,
        max(request_time) as max_response_time
      from
        apache_access_log
      where
        request_uri is not null
        and request_time > 0
      group by
        request_uri
      having
        count(*) >= 5  -- Minimum request threshold
    )
    select
      endpoint,
      round(avg_response_time::numeric, 3) as avg_response_time,
      request_count,
      round(max_response_time::numeric, 3) as max_response_time
    from
      response_stats
    where
      avg_response_time > 1  -- 1 second threshold
      or max_response_time > 3  -- 3 second max threshold
    order by
      avg_response_time desc;
  EOQ
}

detection "response_time_anomaly_detected" {
  title           = "Response Time Anomaly Detected"
  description     = "Detect when a web server experienced sudden increases in response time compared to historical patterns to check for performance degradation, service disruptions, or infrastructure changes."
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.response_time_anomaly_detected

  tags = merge(local.performance_common_tags, {
    mitre_attack_id = "TA0040:T1499.003,TA0040:T1496.001" # Impact:Application Exhaustion Flood, Impact:Compute Hijacking
  })
}

query "response_time_anomaly_detected" {
  sql = <<-EOQ
    with time_windows as (
      select
        time_bucket('5 minutes', tp_timestamp) as window_start,
        time_bucket('5 minutes', tp_timestamp) + interval '5 minutes' as window_end,
        avg(request_time) as avg_response_time,
        avg(avg(request_time)) over (
          order by time_bucket('5 minutes', tp_timestamp)
          rows between 12 preceding and 1 preceding
        ) as historical_avg
      from
        apache_access_log
      where
        request_time > 0
      group by
        time_bucket('5 minutes', tp_timestamp)
    )
    select
      window_start,
      window_end,
      round(avg_response_time::numeric, 3) as avg_response_time,
      round(historical_avg::numeric, 3) as historical_avg,
      round(((avg_response_time - historical_avg) / greatest(historical_avg, 0.001) * 100)::numeric, 2) as deviation_percent
    from
      time_windows
    where
      historical_avg > 0
      and ((avg_response_time - historical_avg) / greatest(historical_avg, 0.001)) > 0.5  -- 50% increase threshold
    order by
      window_start desc;
  EOQ
}

detection "high_traffic_endpoint_detected" {
  title           = "High Traffic Endpoint Detected"
  description     = "Detect when a web server handled unusually high traffic volumes to specific endpoints to check for resource consumption patterns, hot spots in the application, or potential areas for optimization."
  severity        = "medium"
  display_columns = local.detection_display_columns

  query = query.high_traffic_endpoint_detected

  tags = merge(local.performance_common_tags, {
    mitre_attack_id = "TA0040:T1499.002,TA0040:T1498.001" # Impact:Service Exhaustion Flood, Impact:Direct Network Flood
  })
}

query "high_traffic_endpoint_detected" {
  sql = <<-EOQ
    with endpoint_traffic as (
      select
        request_uri as endpoint,
        count(*) as request_count,
        avg(request_time) as avg_response_time,
        sum(bytes_sent) as total_bytes_sent
      from
        apache_access_log
      where
        request_uri is not null
      group by
        request_uri
    ),
    total_requests as (
      select sum(request_count) as total
      from endpoint_traffic
    )
    select
      endpoint,
      request_count,
      round((request_count * 100.0 / tr.total)::numeric, 2) as traffic_percent,
      round(avg_response_time::numeric, 3) as avg_response_time
    from
      endpoint_traffic et
    cross join
      total_requests tr
    where
      request_count > 10  -- Minimum request threshold
    order by
      request_count desc
    limit 10;
  EOQ
}

detection "connection_pool_exhaustion_risk_detected" {
  title           = "Connection Pool Exhaustion Risk Detected"
  description     = "Detect when a web server showed signs of connection pool exhaustion based on concurrent connections to check for capacity limits, resource constraints, or potential denial of service conditions."
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.connection_pool_exhaustion_risk_detected

  tags = merge(local.performance_common_tags, {
    mitre_attack_id = "TA0040:T1499.002" # Impact:Service Exhaustion Flood
  })
}

query "connection_pool_exhaustion_risk_detected" {
  sql = <<-EOQ
    with connection_stats as (
      select
        time_bucket('1 minute', tp_timestamp) as timestamp,
        count(*) as concurrent_connections,
        count(*) filter (where status = 503) / nullif(count(*), 0)::float * 100 as rejection_rate
      from
        apache_access_log
      where
        status is not null
      group by
        time_bucket('1 minute', tp_timestamp)
    )
    select
      timestamp,
      concurrent_connections,
      round(rejection_rate::numeric, 2) as rejection_rate
    from
      connection_stats
    where
      concurrent_connections > 100  -- Adjust based on server capacity
      or rejection_rate > 5  -- 5% rejection rate threshold
    order by
      timestamp desc;
  EOQ
}
