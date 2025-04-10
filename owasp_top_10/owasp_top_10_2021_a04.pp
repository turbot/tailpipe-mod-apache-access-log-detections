locals {
  owasp_top_10_2021_a04_common_tags = merge(local.owasp_top_10_common_tags, {
    owasp_top_10_version = "2021_a04"
  })
}

benchmark "owasp_top_10_2021_a04" {
  title       = "A04:2021 - Insecure Design"
  description = "Insecure design is a broad category representing different weaknesses, expressed as " missing or ineffective control design." Insecure design is not the source for all other Top 10 risk categories."
  type        = "detection"
  children = [
    
  ]

  tags = merge(local.owasp_top_10_common_tags, {
    type = "Benchmark"
  })
}
