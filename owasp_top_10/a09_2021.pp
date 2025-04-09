locals {
  owasp_top_10_a09_2021_common_tags = merge(local.owasp_top_10_common_tags, {
    owasp_top_10_version = "a09_2021"
  })
}

benchmark "owasp_top_10_a09_2021" {
  title       = "A09:2021 - Security Logging and Monitoring Failures"
  description = "Security logging and monitoring failures relate to code and infrastructure that does not protect against integrity violations."
  type        = "detection"
  children = [
    detection.log_file_access_attempted,
    detection.security_log_manipulation_attempted
  ]

  tags = merge(local.owasp_top_10_common_tags, {
    type = "Benchmark"
  })
}
