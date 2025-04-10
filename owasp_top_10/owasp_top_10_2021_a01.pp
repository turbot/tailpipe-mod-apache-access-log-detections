locals {
  owasp_top_10_2021_a01_common_tags = merge(local.owasp_top_10_common_tags, {
    owasp_top_10_version = "2021_a01"
  })
}

benchmark "owasp_top_10_2021_a01" {
  title       = "A01:2021 - Broken Access Control"
  description = "Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of all data or performing a business function outside the user's limits."
  type        = "detection"
  children = [
    detection.path_traversal,
    detection.encoded_path_traversal,
    detection.os_file_access,
    detection.restricted_file_access,
    detection.hidden_file_access,
    detection.header_based_local_file_inclusion,
    detection.user_agent_exploitation
  ]

  tags = merge(local.owasp_top_10_common_tags, {
    type = "Benchmark"
  })
}
