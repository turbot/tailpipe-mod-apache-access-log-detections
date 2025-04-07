locals {
  owasp_top_10_common_tags = local.apache_access_log_detections_common_tags
}

benchmark "owasp_top_10" {
  title       = "OWASP Top 10"
  description = "The OWASP Top 10 is a standard awareness document for developers and web application security. It represents a broad consensus about the most critical security risks to web applications."
  type        = "detection"
  children = [
    benchmark.owasp_top_10_a01_2021,
    benchmark.owasp_top_10_a02_2021,
    benchmark.owasp_top_10_a03_2021,
    benchmark.owasp_top_10_a04_2021,
    # benchmark.owasp_top_10_a05_2021,
  ]

  tags = merge(local.owasp_top_10_common_tags, {
    type = "Benchmark"
  })
}
