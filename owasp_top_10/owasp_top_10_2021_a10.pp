locals {
  owasp_top_10_2021_a10_common_tags = merge(local.owasp_top_10_common_tags, {
    owasp_top_10_version = "2021_a10"
  })
}

benchmark "owasp_top_10_2021_a10" {
  title       = "A10:2021 - Server-Side Request Forgery"
  description = "SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall, VPN, or another type of network access control list (ACL)."
  type        = "detection"
  children = [
    
  ]

  tags = merge(local.owasp_top_10_common_tags, {
    type = "Benchmark"
  })
}
