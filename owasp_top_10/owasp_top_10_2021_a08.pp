locals {
  owasp_top_10_2021_a08_common_tags = merge(local.owasp_top_10_common_tags, {
    owasp_top_10_version = "2021_a08"
  })
}

benchmark "owasp_top_10_2021_a08" {
  title       = "A08:2021 - Software and Data Integrity Failures"
  description = "Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations."
  type        = "detection"
  children = [
    
  ]

  tags = merge(local.owasp_top_10_common_tags, {
    type = "Benchmark"
  })
}
