locals {
  owasp_top_10_a04_2021_common_tags = merge(local.owasp_top_10_common_tags, {
    owasp_top_10_version = "ao4_2021"
  })
}

benchmark "owasp_top_10_a04_2021" {
  title       = "A04:2021 - Insecure Design"
  description = "Insecure design is a broad category representing different weaknesses, expressed as “missing or ineffective control design.” Insecure design is not the source for all other Top 10 risk categories."
  type        = "detection"
  children = [
    detection.cisco_http_auth_bypass_attempted,
    detection.cisco_ios_http_dos_attempted,
    detection.cisco_snmp_community_exposure_attempted,
    detection.cisco_snmp_rw_access_attempted,
  ]

  tags = merge(local.owasp_top_10_common_tags, {
    type = "Benchmark"
  })
}
