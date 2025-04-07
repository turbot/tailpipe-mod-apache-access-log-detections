locals {
  cwe_22_common_tags = local.apache_access_log_detections_common_tags
}

benchmark "cwe_22" {
  title       = "CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"
  description = "The product uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the product does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory."
  type        = "detection"
  children = [
    detection.ilias_lfi_attempted,
    detection.lollms_path_traversal_attempted,
    detection.ollama_path_traversal_attempted,
    detection.pip_directory_traversal_attempted,
  ]

  tags = merge(local.cwe_22_common_tags, {
    type = "Benchmark"
  })
}