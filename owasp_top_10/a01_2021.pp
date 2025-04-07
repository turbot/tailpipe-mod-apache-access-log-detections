locals {
  owasp_top_10_a01_2021_common_tags = merge(local.owasp_top_10_common_tags, {
    owasp_top_10_version = "ao1_2021"
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
    # benchmark.a01_2021_cwe_22,
  ]

  tags = merge(local.owasp_top_10_common_tags, {
    type = "Benchmark"
  })
}

# benchmark "a01_2021_cwe_22" {
#   title       = "CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"
#   description = "The product uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the product does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory."
#   children = [
#     detection.ilias_lfi_attempted,
#     detection.lollms_path_traversal_attempted,
#     detection.ollama_path_traversal_attempted,
#     detection.pip_directory_traversal_attempted,
#   ]

#   tags = merge(local.owasp_top_10_common_tags, {
#     type = "Benchmark"
#   })
# }
