locals {
  owasp_top_10_a08_2021_common_tags = merge(local.owasp_top_10_common_tags, {
    owasp_top_10_version = "a08_2021"
  })
}

benchmark "owasp_top_10_a08_2021" {
  title       = "A08:2021 - Software and Data Integrity Failures"
  description = "Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations."
  type        = "detection"
  children = [
    detection.insecure_deserialization_attempted,
    detection.unauthorized_package_access
  ]

  tags = merge(local.owasp_top_10_common_tags, {
    type = "Benchmark"
  })
}
