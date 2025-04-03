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
    detection.apache_timeout_errors,
    detection.apache_slow_response_time,
    detection.apache_response_time_anomalies,
    detection.apache_high_traffic_endpoints,
    detection.apache_connection_pool_exhaustion
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

detection "apache_slow_response_time" {
  title           = "Slow Response Time Detected"
  description     = "Detect endpoints with consistently high response times exceeding threshold."
  severity        = "high"
  display_columns = ["endpoint", "avg_response_time", "request_count", "max_response_time"]

  query = query.apache_slow_response_time

  tags = merge(local.apache_performance_common_tags, {
    mitre_attack_id = "TA0040:T1499.003,TA0040:T1496.001" # Impact:Application Exhaustion Flood, Impact:Compute Hijacking
  })
}

query "apache_slow_response_time" {
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

detection "apache_response_time_anomalies" {
  title           = "Response Time Anomalies Detected"
  description     = "Detect sudden increases in response time compared to historical patterns."
  severity        = "high"
  display_columns = ["window_start", "window_end", "avg_response_time", "historical_avg", "deviation_percent"]

  query = query.apache_response_time_anomalies

  tags = merge(local.apache_performance_common_tags, {
    mitre_attack_id = "TA0040:T1499.003,TA0040:T1496.001" # Impact:Application Exhaustion Flood, Impact:Compute Hijacking
  })
}

query "apache_response_time_anomalies" {
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

detection "apache_high_traffic_endpoints" {
  title           = "High Traffic Endpoints"
  description     = "Identify endpoints receiving unusually high traffic volumes."
  severity        = "medium"
  display_columns = ["endpoint", "request_count", "traffic_percent", "avg_response_time"]

  query = query.apache_high_traffic_endpoints

  tags = merge(local.apache_performance_common_tags, {
    mitre_attack_id = "TA0040:T1499.002,TA0040:T1498.001" # Impact:Service Exhaustion Flood, Impact:Direct Network Flood
  })
}

query "apache_high_traffic_endpoints" {
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

detection "apache_connection_pool_exhaustion" {
  title           = "Connection Pool Exhaustion Risk"
  description     = "Detect risk of connection pool exhaustion based on concurrent connections."
  severity        = "critical"
  display_columns = ["timestamp", "concurrent_connections", "rejection_rate"]

  query = query.apache_connection_pool_exhaustion

  tags = merge(local.apache_performance_common_tags, {
    mitre_attack_id = "TA0040:T1499.002" # Impact:Service Exhaustion Flood
  })
}

query "apache_connection_pool_exhaustion" {
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
