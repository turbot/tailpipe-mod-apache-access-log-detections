locals {
  cwe_326_common_tags = local.apache_access_log_detections_common_tags
}

benchmark "cwe_326" {
  title       = "CWE-326: Inadequate Encryption Strength"
  description = "The product stores or transmits sensitive data using an encryption scheme that is theoretically sound, but is not strong enough for the level of protection required."
  type        = "detection"
  children = [
    detection.network_config_exposure_attempted,
  ]

  tags = merge(local.cwe_326_common_tags, {
    type = "Benchmark"
  })
}