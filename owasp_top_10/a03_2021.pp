locals {
  owasp_top_10_a03_2021_common_tags = merge(local.owasp_top_10_common_tags, {
    owasp_top_10_version = "a03_2021"
  })
}

benchmark "owasp_top_10_a03_2021" {
  title       = "A03:2021 - Injection"
  description = "Injection flaws allow an attacker to supply malicious data to an interpreter as part of a command or query."
  type        = "detection"
  children = [
    # References to security.pp detections have been removed
  ]

  tags = merge(local.owasp_top_10_common_tags, {
    type = "Benchmark"
  })
}
