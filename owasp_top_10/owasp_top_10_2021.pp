locals {
  owasp_top_10_2021_common_tags = local.apache_access_log_detections_common_tags
}

benchmark "owasp_top_10_2021" {
  title       = "OWASP Top 10 2021"
  description = "The OWASP Top 10 is a standard awareness document for developers and web application security. It represents a broad consensus about the most critical security risks to web applications."
  type        = "detection"
  children = [
    benchmark.owasp_top_10_2021_a01,
    benchmark.owasp_top_10_2021_a02,
    benchmark.owasp_top_10_2021_a03,
    benchmark.owasp_top_10_2021_a04,
    benchmark.owasp_top_10_2021_a05,
    benchmark.owasp_top_10_2021_a06,
    benchmark.owasp_top_10_2021_a07,
    benchmark.owasp_top_10_2021_a08,
    benchmark.owasp_top_10_2021_a09,
    benchmark.owasp_top_10_2021_a10
  ]

  tags = merge(local.owasp_top_10_2021_common_tags, {
    type = "Benchmark"
  })
}
