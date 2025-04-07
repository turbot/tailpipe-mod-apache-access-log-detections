locals {
  cwe_20_common_tags = local.apache_access_log_detections_common_tags
}

benchmark "cwe_20" {
  title       = "CWE-20: Improper Input Validation"
  description = "The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly."
  type        = "detection"
  children = [
    detection.forcedentry_spyware_attempted,
    detection.geoserver_sql_injection_attempted,
    detection.ilias_lfi_attempted,
    detection.ollama_path_traversal_attempted,
    detection.webkit_integer_overflow_attempted,
  ]

  tags = merge(local.cwe_20_common_tags, {
    type = "Benchmark"
  })
}