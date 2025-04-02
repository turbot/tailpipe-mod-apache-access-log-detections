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
    detection.apache_slow_response_time,
    detection.apache_response_time_anomalies,
    detection.apache_high_traffic_endpoints,
    detection.apache_connection_pool_exhaustion
  ]

  tags = merge(local.apache_performance_common_tags, {
    type = "Benchmark"
  })
}

detection "apache_slow_response_time" {
  title           = "Slow Response Time Detected"
  description     = "Detect endpoints with consistently high response times exceeding threshold."
  severity        = "high"
  display_columns = ["endpoint", "avg_response_time", "request_count", "max_response_time"]

  query = query.apache_slow_response_time

  tags = merge(local.apache_performance_common_tags, {
    type = "Latency"
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
    type = "Anomaly"
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
    type = "Capacity"
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
    type = "Capacity"
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