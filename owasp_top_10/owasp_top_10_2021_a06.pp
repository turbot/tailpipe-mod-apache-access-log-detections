locals {
  owasp_top_10_2021_a06_common_tags = merge(local.owasp_top_10_common_tags, {
    owasp_top_10_version = "2021_a06"
  })
}

benchmark "owasp_top_10_2021_a06" {
  title       = "A06:2021 - Vulnerable and Outdated Components"
  description = "Components such as libraries, frameworks, and other software modules run with the same privileges as the application. If a vulnerable component is exploited, such an attack can facilitate serious data loss or server takeover."
  type        = "detection"
  children = [
    
  ]

  tags = merge(local.owasp_top_10_common_tags, {
    type = "Benchmark"
  })
}
