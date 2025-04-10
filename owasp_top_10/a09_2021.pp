locals {
  owasp_top_10_a09_2021_common_tags = merge(local.owasp_top_10_common_tags, {
    owasp_top_10_version = "a09_2021"
  })
}

benchmark "owasp_top_10_a09_2021" {
  title       = "A09:2021 - Security Logging and Monitoring Failures"
  description = "Insufficient logging and monitoring, coupled with missing or ineffective integration with incident response, allows attackers to operate undetected."
  type        = "detection"
  children = [
    # References to security.pp detections have been removed
  ]

  tags = merge(local.owasp_top_10_common_tags, {
    type = "Benchmark"
  })
}
