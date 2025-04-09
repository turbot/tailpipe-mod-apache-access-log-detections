benchmark "access_log_detections" {
  title       = "Access Log Detections"
  description = "This benchmark contains recommendations when scanning access logs."
  type        = "detection"
  children = [
    #benchmark.security_detections,
    benchmark.local_file_inclusion_detections,
    benchmark.sql_injection_detections
  ]

  tags = merge(local.apache_access_log_detections_common_tags, {
    type = "Benchmark"
  })
}
