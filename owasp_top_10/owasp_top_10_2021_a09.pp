locals {
  owasp_top_10_2021_a09_common_tags = merge(local.owasp_top_10_common_tags, {
    owasp_top_10_version = "2021_a09"
  })
}

benchmark "owasp_top_10_2021_a09" {
  title       = "A09:2021 - Security Logging and Monitoring Failures"
  description = "Security logging and monitoring failures relate to code and infrastructure that does not protect against integrity violations."
  type        = "detection"
  children = [
    
  ]

  tags = merge(local.owasp_top_10_common_tags, {
    type = "Benchmark"
  })
}
