locals {
  cwe_1004_common_tags = local.apache_access_log_detections_common_tags
}

benchmark "cwe_1004" {
  title       = "CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag"
  description = "The product uses a cookie to store sensitive information, but the cookie is not marked with the HttpOnly flag."
  type        = "detection"
  children = [
    detection.apache_mod_status_info_disclosure_attempted,
  ]

  tags = merge(local.cwe_1004_common_tags, {
    type = "Benchmark"
  })
}