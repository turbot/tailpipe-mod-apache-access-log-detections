locals {
  owasp_top_10_a07_2021_common_tags = merge(local.owasp_top_10_common_tags, {
    owasp_top_10_version = "a07_2021"
  })
}

benchmark "owasp_top_10_a07_2021" {
  title       = "A07:2021 - Identification and Authentication Failures"
  description = "Weaknesses in authentication can allow attackers to assume identities of other users or bypass authentication entirely."
  type        = "detection"
  children = [
    # References to security.pp detections have been removed
  ]

  tags = merge(local.owasp_top_10_common_tags, {
    type = "Benchmark"
  })
}
