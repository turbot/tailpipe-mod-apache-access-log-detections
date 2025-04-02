benchmark "apache_access_log_detections" {
  title       = "Apache Access Log Detections"
  description = "This benchmark contains recommendations when scanning Apache access logs."
  type        = "detection"
  children = [
    benchmark.apache_security_detections,
    benchmark.apache_operational_detections,
    benchmark.apache_performance_detections,
    benchmark.apache_compliance_detections
  ]

  tags = merge(local.apache_access_log_detections_common_tags, {
    type = "Benchmark"
  })
}

locals {
  apache_access_log_detections_common_tags = {
    service = "Apache"
  }
} 