locals {
  owasp_top_10_a04_2021_common_tags = merge(local.owasp_top_10_common_tags, {
    owasp_top_10_version = "a04_2021"
  })
}

benchmark "owasp_top_10_a04_2021" {
  title       = "A04:2021 - Insecure Design"
  description = "Insecure design encompasses a broad category of weaknesses related to design and architectural flaws."
  type        = "detection"
  children = [
    # References to security.pp detections have been removed
  ]

  tags = merge(local.owasp_top_10_common_tags, {
    type = "Benchmark"
  })
}
