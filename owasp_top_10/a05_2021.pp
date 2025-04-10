locals {
  owasp_top_10_a05_2021_common_tags = merge(local.owasp_top_10_common_tags, {
    owasp_top_10_version = "a05_2021"
  })
}

benchmark "owasp_top_10_a05_2021" {
  title       = "A05:2021 - Security Misconfiguration"
  description = "Security misconfiguration can happen at any level of the application stack, from improper network services to application-specific issues."
  type        = "detection"
  children = [
    # References to security.pp detections have been removed
  ]

  tags = merge(local.owasp_top_10_common_tags, {
    type = "Benchmark"
  })
}
