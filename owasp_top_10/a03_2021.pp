locals {
  owasp_top_10_a03_2021_common_tags = merge(local.owasp_top_10_common_tags, {
    owasp_top_10_version = "a03_2021"
  })
}

benchmark "owasp_top_10_a03_2021" {
  title       = "A03:2021 - Injection"
  description = "Injection slides down to the third position. 94% of the applications were tested for some form of injection with a max incidence rate of 19%, an average incidence rate of 3%, and 274k occurrences."
  type        = "detection"
  children = [
    detection.sql_injection_attempted,
    detection.xss_attempted
  ]

  tags = merge(local.owasp_top_10_common_tags, {
    type = "Benchmark"
  })
}
