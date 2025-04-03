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
    detection.apache_large_payload_requests,
    detection.apache_high_error_rate,
    detection.apache_unusual_traffic_spike,
    detection.apache_error_rate_by_endpoint,
    detection.apache_client_error_analysis,
    detection.apache_server_error_analysis
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

detection "apache_high_error_rate" {
  title           = "High Error Rate Detected"
  description     = "Detect when the rate of HTTP errors exceeds a threshold within a time window."
  severity        = "high"
  display_columns = ["error_count", "total_requests", "error_rate", "window_start", "window_end"]

  query = query.apache_high_error_rate

  tags = merge(local.apache_operational_common_tags, {
    mitre_attack_id = "TA0040:T1499.002" # Impact:Service Exhaustion Flood
  })
}

query "apache_high_error_rate" {
  sql = <<-EOQ
    with error_windows as (
      select
        count(*) filter (where status >= 400) as error_count,
        count(*) as total_requests,
        (count(*) filter (where status >= 400))::float / count(*) as error_rate,
        time_bucket('5 minutes', tp_timestamp) as window_start,
        time_bucket('5 minutes', tp_timestamp) + interval '5 minutes' as window_end
      from
        apache_access_log
      where
        status is not null
      group by
        time_bucket('5 minutes', tp_timestamp)
      having
        count(*) >= 10  -- Minimum request threshold
        and (count(*) filter (where status >= 400))::float / count(*) >= 0.1  -- 10% error rate threshold
    )
    select
      error_count,
      total_requests,
      round((error_rate * 100)::numeric, 2) as error_rate,
      window_start,
      window_end
    from
      error_windows
    order by
      window_start desc;
  EOQ
}

detection "apache_unusual_traffic_spike" {
  title           = "Unusual Traffic Spike Detected"
  description     = "Detect unusual spikes in traffic volume compared to historical patterns."
  severity        = "medium"
  display_columns = ["request_count", "avg_historical_requests", "deviation_percent", "window_start", "window_end"]

  query = query.apache_unusual_traffic_spike

  tags = merge(local.apache_operational_common_tags, {
    mitre_attack_id = "TA0040:T1498,TA0040:T1499.002" # Impact:Network Denial of Service, Impact:Service Exhaustion Flood
  })
}

query "apache_unusual_traffic_spike" {
  sql = <<-EOQ
    with traffic_windows as (
      select
        count(*) as request_count,
        time_bucket('5 minutes', tp_timestamp) as window_start,
        avg(count(*)) over (
          order by time_bucket('5 minutes', tp_timestamp)
          rows between 12 preceding and 1 preceding
        ) as avg_historical_requests,
        time_bucket('5 minutes', tp_timestamp) + interval '5 minutes' as window_end
      from
        apache_access_log
      group by
        time_bucket('5 minutes', tp_timestamp)
    )
    select
      request_count,
      round(avg_historical_requests::numeric, 2) as avg_historical_requests,
      round(((request_count - avg_historical_requests) / greatest(avg_historical_requests, 1) * 100)::numeric, 2) as deviation_percent,
      window_start,
      window_end
    from
      traffic_windows
    where
      avg_historical_requests > 0
      and ((request_count - avg_historical_requests) / greatest(avg_historical_requests, 1)) > 1  -- 100% increase threshold
    order by
      window_start desc;
  EOQ
}

detection "apache_error_rate_by_endpoint" {
  title           = "High Error Rate by Endpoint"
  description     = "Detect endpoints with unusually high error rates."
  severity        = "high"
  display_columns = ["endpoint", "error_count", "total_requests", "error_rate"]

  query = query.apache_error_rate_by_endpoint

  tags = merge(local.apache_operational_common_tags, {
    mitre_attack_id = "TA0040:T1499.002,TA0001:T1190" # Impact:Service Exhaustion Flood, Initial Access:Exploit Public-Facing Application
  })
}

query "apache_error_rate_by_endpoint" {
  sql = <<-EOQ
    select
      request_uri as endpoint,
      count(*) filter (where status >= 400) as error_count,
      count(*) as total_requests,
      round((count(*) filter (where status >= 400))::float / count(*)::numeric, 4) * 100 as error_rate
    from
      apache_access_log
    where
      request_uri is not null
      and status is not null
    group by
      request_uri
    having
      count(*) >= 5  -- Minimum request threshold
      and (count(*) filter (where status >= 400))::float / count(*) >= 0.1  -- 10% error rate threshold
    order by
      error_rate desc,
      total_requests desc;
  EOQ
}

detection "apache_client_error_analysis" {
  title           = "Client Error Analysis"
  description     = "Analyze patterns in client-side errors (4xx) to identify potential client issues."
  severity        = "medium"
  display_columns = ["status_code", "error_count", "percentage", "top_uri", "uri_count"]

  query = query.apache_client_error_analysis

  tags = merge(local.apache_operational_common_tags, {
    mitre_attack_id = "TA0001:T1190,TA0043:T1595" # Initial Access:Exploit Public-Facing Application, Reconnaissance:Active Scanning
  })
}

query "apache_client_error_analysis" {
  sql = <<-EOQ
    with client_errors as (
      select
        status as status_code,
        count(*) as error_count
      from
        apache_access_log
      where
        status >= 400 and status < 500
      group by
        status
    ),
    error_uris as (
      select
        status as status_code,
        request_uri,
        count(*) as uri_count,
        row_number() over (partition by status order by count(*) desc) as rn
      from
        apache_access_log
      where
        status >= 400 and status < 500
        and request_uri is not null
      group by
        status, request_uri
    ),
    total_client_errors as (
      select sum(error_count) as total from client_errors
    )
    select
      ce.status_code,
      ce.error_count,
      round((ce.error_count * 100.0 / tce.total)::numeric, 2) as percentage,
      eu.request_uri as top_uri,
      eu.uri_count
    from
      client_errors ce
    join
      total_client_errors tce on true
    left join
      error_uris eu on ce.status_code = eu.status_code and eu.rn = 1
    order by
      ce.error_count desc;
  EOQ
}

detection "apache_server_error_analysis" {
  title           = "Server Error Analysis"
  description     = "Analyze patterns in server-side errors (5xx) to identify potential server issues."
  severity        = "high"
  display_columns = ["status_code", "error_count", "percentage", "top_uri", "uri_count"]

  query = query.apache_server_error_analysis

  tags = merge(local.apache_operational_common_tags, {
    mitre_attack_id = "TA0040:T1499.004,TA0040:T1499.003" # Impact:Application or System Exploitation, Impact:Application Exhaustion Flood
  })
}

query "apache_server_error_analysis" {
  sql = <<-EOQ
    with server_errors as (
      select
        status as status_code,
        count(*) as error_count
      from
        apache_access_log
      where
        status >= 500
      group by
        status
    ),
    error_uris as (
      select
        status as status_code,
        request_uri,
        count(*) as uri_count,
        row_number() over (partition by status order by count(*) desc) as rn
      from
        apache_access_log
      where
        status >= 500
        and request_uri is not null
      group by
        status, request_uri
    ),
    total_server_errors as (
      select sum(error_count) as total from server_errors
    )
    select
      se.status_code,
      se.error_count,
      round((se.error_count * 100.0 / tse.total)::numeric, 2) as percentage,
      eu.request_uri as top_uri,
      eu.uri_count
    from
      server_errors se
    join
      total_server_errors tse on true
    left join
      error_uris eu on se.status_code = eu.status_code and eu.rn = 1
    order by
      se.error_count desc;
  EOQ
}
