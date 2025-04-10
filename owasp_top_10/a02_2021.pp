locals {
  owasp_top_10_a02_2021_common_tags = merge(local.owasp_top_10_common_tags, {
    owasp_top_10_version = "a02_2021"
  })
}

benchmark "owasp_top_10_a02_2021" {
  title       = "A02:2021 - Cryptographic Failures"
  description = "Failures related to cryptography that often lead to exposure of sensitive data or system compromise."
  type        = "detection"
  children = [
    # References to security.pp detections have been removed
  ]

  tags = merge(local.owasp_top_10_common_tags, {
    type = "Benchmark"
  })
}
