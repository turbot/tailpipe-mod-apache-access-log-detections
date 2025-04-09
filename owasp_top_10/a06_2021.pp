locals {
  owasp_top_10_a06_2021_common_tags = merge(local.owasp_top_10_common_tags, {
    owasp_top_10_version = "a06_2021"
  })
}

benchmark "owasp_top_10_a06_2021" {
  title       = "A06:2021 - Vulnerable and Outdated Components"
  description = "Components such as libraries, frameworks, and other software modules run with the same privileges as the application. If a vulnerable component is exploited, such an attack can facilitate serious data loss or server takeover."
  type        = "detection"
  children = [
    detection.vulnerable_component_access_attempted,
    detection.outdated_software_version_detected
  ]

  tags = merge(local.owasp_top_10_common_tags, {
    type = "Benchmark"
  })
}
