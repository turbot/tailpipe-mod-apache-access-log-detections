locals {
  apache_access_log_detections_common_tags = {
    category = "Detections"
    plugin   = "apache"
    service  = "Apache/AccessLog"
  }
}

locals {
  # Local internal variables to build the SQL select clause for common
  # dimensions. Do not edit directly.
  detection_sql_columns = <<-EOQ
  tp_timestamp as timestamp,
  request_method as operation,
  request_uri as resource,
  status,
  http_user_agent as actor,
  tp_source_ip as source_ip,
  tp_id as source_id,
  -- Create new aliases to preserve original row data
  status as status_src,
  timestamp as timestamp_src,
  *
  exclude (status, timestamp)
  EOQ
}

locals {
  # Local internal variables to build the SQL select clause for common
  # dimensions. Do not edit directly.
  detection_display_columns = [
    "timestamp",
    "operation",
    "resource",
    "status",
    "actor",
    "source_ip",
    "source_id",
  ]
}
