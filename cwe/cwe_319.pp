locals {
  cwe_319_common_tags = local.apache_access_log_detections_common_tags
}

benchmark "cwe_319" {
  title       = "CWE-319: Cleartext Transmission of Sensitive Information"
  description = "The product transmits sensitive or security-critical data in cleartext in a communication channel that can be sniffed by unauthorized actors."
  type        = "detection"
  children = [
    detection.insecure_session_cookie_detected,
    detection.backup_client_password_hash_exposed,
    detection.camera_config_exposure_attempted,
  ]

  tags = merge(local.cwe_319_common_tags, {
    type = "Benchmark"
  })
}