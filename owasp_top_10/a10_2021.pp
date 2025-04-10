locals {
  owasp_top_10_a10_2021_common_tags = merge(local.owasp_top_10_common_tags, {
    owasp_top_10_version = "a10_2021"
  })
}

benchmark "owasp_top_10_a10_2021" {
  title       = "A10:2021 - Server-Side Request Forgery"
  description = "Server-Side Request Forgery flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL."
  type        = "detection"
  children = [
    # References to security.pp detections have been removed
  ]

  tags = merge(local.owasp_top_10_common_tags, {
    type = "Benchmark"
  })
}
