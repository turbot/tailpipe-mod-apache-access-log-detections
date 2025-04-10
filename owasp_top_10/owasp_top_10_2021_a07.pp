locals {
  owasp_top_10_2021_a07_common_tags = merge(local.owasp_top_10_common_tags, {
    owasp_top_10_version = "2021_a07"
  })
}

benchmark "owasp_top_10_2021_a07" {
  title       = "A07:2021 - Identification and Authentication Failures"
  description = "Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks."
  type        = "detection"
  children = [
    
  ]

  tags = merge(local.owasp_top_10_common_tags, {
    type = "Benchmark"
  })
}
