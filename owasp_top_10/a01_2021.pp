locals {
  owasp_top_10_a01_2021_common_tags = merge(local.owasp_top_10_common_tags, {
    owasp_top_10_version = "a01_2021"
  })
}

benchmark "owasp_top_10_a01_2021" {
  title       = "A01:2021 - Broken Access Control"
  description = "Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of all data or performing a business function outside the user's limits."
  type        = "detection"
  children = [
    detection.ilias_lfi_attempted,
    detection.lollms_path_traversal_attempted,
    detection.ollama_path_traversal_attempted,
    detection.pip_directory_traversal_attempted,
  ]

  tags = merge(local.owasp_top_10_common_tags, {
    type = "Benchmark"
  })
}
