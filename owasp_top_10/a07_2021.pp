locals {
  owasp_top_10_a07_2021_common_tags = merge(local.owasp_top_10_common_tags, {
    owasp_top_10_version = "a07_2021"
  })
}

benchmark "owasp_top_10_a07_2021" {
  title       = "A07:2021 - Identification and Authentication Failures"
  description = "Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks."
  type        = "detection"
  children = [
    detection.apache_mod_lua_uaf_attempted,
    detection.apache_mod_proxy_uwsgi_bo_attempted,
  ]

  tags = merge(local.owasp_top_10_common_tags, {
    type = "Benchmark"
  })
}
