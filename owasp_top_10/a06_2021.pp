locals {
  owasp_top_10_a06_2021_common_tags = merge(local.owasp_top_10_common_tags, {
    owasp_top_10_version = "a06_2021"
  })
}

benchmark "owasp_top_10_a06_2021" {
  title       = "A06:2021 - Vulnerable and Outdated Components"
  description = "Using components with known vulnerabilities can undermine application defenses and enable various attacks."
  type        = "detection"
  children = [
    # References to security.pp detections have been removed
  ]

  tags = merge(local.owasp_top_10_common_tags, {
    type = "Benchmark"
  })
}
