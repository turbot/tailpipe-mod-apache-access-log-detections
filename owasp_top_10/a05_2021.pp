locals {
  owasp_top_10_a05_2021_common_tags = merge(local.owasp_top_10_common_tags, {
    owasp_top_10_version = "a05_2021"
  })
}

benchmark "owasp_top_10_a05_2021" {
  title       = "A05:2021 - Security Misconfiguration"
  description = "Security misconfiguration is the most frequently reported category in the OWASP Top 10, with 94% of applications tested exhibiting some form of misconfiguration with a max incidence rate of 20%, an average incidence rate of 4%, and 274k occurrences."
  type        = "detection"
  children = [
    detection.apache_mod_status_info_disclosure_attempted,
    detection.apache_mod_headers_bypass_attempted,
  ]

  tags = merge(local.owasp_top_10_common_tags, {
    type = "Benchmark"
  })
}
