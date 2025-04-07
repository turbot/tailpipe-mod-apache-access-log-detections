dashboard "activity_dashboard" {
  title         = "Access Log Activity Dashboard"
  documentation = file("./dashboards/docs/activity_dashboard.md")

  tags = {
    type    = "Dashboard"
    service = "Apache/AccessLog"
  }

  container {
    # Analysis
    card {
      query = query.activity_dashboard_total_logs
      width = 2
    }

    card {
      query = query.activity_dashboard_success_count
      width = 2
      type  = "ok"
    }

    card {
      query = query.activity_dashboard_bad_request_count
      width = 2
      type  = "info"
    }

    card {
      query = query.activity_dashboard_error_count
      width = 2
      type  = "alert"
    }
  }

  container {

    chart {
      title = "Requests by Day"
      query = query.activity_dashboard_requests_per_daily
      width = 6
      type  = "heatmap"
    }

    chart {
      title = "Requests by HTTP Method"
      query = query.activity_dashboard_method_distribution
      width = 6
      type  = "bar"
    }

    chart {
      title = "Requests by Status Code"
      query = query.activity_dashboard_status_distribution
      width = 6
      type  = "pie"
    }

    chart {
      title = "User Agents Distribution"
      query = query.activity_dashboard_user_agents_distribution
      width = 6
      type  = "pie"
    }

    chart {
      title = "Top 10 Clients (Request Count)"
      query = query.activity_dashboard_top_10_clients
      width = 6
      type  = "table"
    }

    chart {
      title = "Top 10 URIs (Request Count)"
      query = query.activity_dashboard_top_10_urls
      width = 6
      type  = "table"
    }

    chart {
      title = "Top 10 Slowest Endpoints"
      query = query.activity_dashboard_slowest_endpoints
      width = 6
      type  = "table"
    }

    chart {
      title = "Top Client Error Paths"
      query = query.activity_dashboard_client_error_paths
      width = 6
      type  = "table"
    }
  }

}

# Queries
query "activity_dashboard_total_logs" {
  title       = "Log Count"
  description = "Count the total Apache log entries."

  sql = <<-EOQ
    select
      count(*) as "Total Requests"
    from 
      apache_access_log;
  EOQ

  tags = {
    folder = "Apache"
  }
}

query "activity_dashboard_success_count" {
  title       = "Successful Request Count"
  description = "Count of successful HTTP requests (status 200-399)."

  sql = <<-EOQ
    select
      count(*) as "Successful (200-399)"
    from 
      apache_access_log
    where
      status between 200 and 399;
  EOQ

  tags = {
    folder = "Apache"
  }
}

query "activity_dashboard_bad_request_count" {
  title       = "Bad Request Count"
  description = "Count of client error HTTP requests (status 400-499)."

  sql = <<-EOQ
    select
      count(*) as "Bad Requests (400-499)"
    from 
      apache_access_log
    where
      status between 400 and 499;
  EOQ

  tags = {
    folder = "Apache"
  }
}

query "activity_dashboard_error_count" {
  title       = "Server Error Count"
  description = "Count of server error HTTP requests (status 500-599)."

  sql = <<-EOQ
    select
      count(*) as "Server Errors (500-599)"
    from 
      apache_access_log
    where
      status between 500 and 599;
  EOQ

  tags = {
    folder = "Apache"
  }
}

query "activity_dashboard_top_10_clients" {
  title       = "Top 10 Clients"
  description = "List the top 10 client IPs by request count."

  sql = <<-EOQ
    select
      remote_addr as "Client IP",
      count(*) as "Request Count"
    from
      apache_access_log
    group by
      remote_addr
    order by
      count(*) desc
    limit 10;
  EOQ

  tags = {
    folder = "Apache"
  }
}

query "activity_dashboard_top_10_urls" {
  title       = "Top 10 URIs"
  description = "List the top 10 requested URIs by request count."

  sql = <<-EOQ
    select
      request_uri as "URL",
      count(*) as "Request Count"
    from
      apache_access_log
    where
      request_uri is not null
    group by
      request_uri
    order by
      count(*) desc
    limit 10;
  EOQ

  tags = {
    folder = "Apache"
  }
}

query "activity_dashboard_requests_per_daily" {
  title       = "Daily Requests"
  description = "Count of requests grouped by day."

  sql = <<-EOQ
    select
      strftime(tp_timestamp, '%Y-%m-%d') as "Date",
      count(*) as "Request Count"
    from
      apache_access_log
    group by
      strftime(tp_timestamp, '%Y-%m-%d')
    order by
      strftime(tp_timestamp, '%Y-%m-%d');
  EOQ

  tags = {
    folder = "Apache"
  }
}

query "activity_dashboard_status_distribution" {
  title       = "Status Code Distribution"
  description = "Distribution of HTTP status codes by category."

  sql = <<-EOQ
    select
      case
        when status between 200 and 299 then '2xx Success'
        when status between 300 and 399 then '3xx Redirect'
        when status between 400 and 499 then '4xx Client Error'
        when status between 500 and 599 then '5xx Server Error'
        else 'Other'
      end as "Status Category",
      count(*) as "Request Count"
    from
      apache_access_log
    where
      status is not null
    group by
      case
        when status between 200 and 299 then '2xx Success'
        when status between 300 and 399 then '3xx Redirect'
        when status between 400 and 499 then '4xx Client Error'
        when status between 500 and 599 then '5xx Server Error'
        else 'Other'
      end;
  EOQ

  tags = {
    folder = "Apache"
  }
}

query "activity_dashboard_method_distribution" {
  title       = "HTTP Method Distribution"
  description = "Distribution of HTTP methods used in requests."

  sql = <<-EOQ
    select
      request_method as "HTTP Method",
      count(*) as "Request Count"
    from
      apache_access_log
    where
      request_method is not null
    group by
      request_method
    order by
      count(*) asc;
  EOQ

  tags = {
    folder = "Apache"
  }
}

query "activity_dashboard_slowest_endpoints" {
  title       = "Top 10 Slowest Endpoints"
  description = "List of the 10 slowest endpoints by average response time."

  sql = <<-EOQ
    select
      request_uri as "Endpoint",
      case 
        when avg(request_time) < 1 then round(avg(request_time) * 1000)::text || 'ms'
        else round(avg(request_time), 1)::text || 's'
      end as "Avg Response Time",
      count(*) as "Request Count"
    from
      apache_access_log
    where
      request_uri is not null
      and request_time > 0
    group by
      request_uri
    having
      count(*) > 5  -- Only show endpoints with more than 5 requests
    order by
      avg(request_time) desc
    limit 10;
  EOQ

  tags = {
    folder = "Apache"
  }
}

query "activity_dashboard_client_error_paths" {
  title       = "Top Client Error Paths"
  description = "List of paths that generated the most client errors (status 400-499)."

  sql = <<-EOQ
    select
      request_uri as "Path",
      count(*) as "Error Count",
      string_agg(distinct status::text, ', ' order by status::text) as "Status Codes"
    from
      apache_access_log
    where
      status between 400 and 499
      and request_uri is not null
    group by
      request_uri
    order by
      count(*) desc
    limit 10;
  EOQ

  tags = {
    folder = "Apache"
  }
}

query "activity_dashboard_user_agents_distribution" {
  title       = "User Agents Distribution"
  description = "Distribution of user agents in requests."

  sql = <<-EOQ
    select
      http_user_agent as "User Agent",
      count(*) as "Request Count"
    from
      apache_access_log
    where
      http_user_agent is not null
    group by
      http_user_agent;
  EOQ

  tags = {
    folder = "Apache"
  }
} 
