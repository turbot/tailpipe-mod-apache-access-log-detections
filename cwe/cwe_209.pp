locals {
  cwe_209_common_tags = local.apache_access_log_detections_common_tags
}

benchmark "cwe_209" {
  title       = "CWE-209: Inadequate Encryption Strength"
  description = "The product stores or transmits sensitive data using an encryption scheme that is theoretically sound, but is not strong enough for the level of protection required."
  type        = "detection"
  children = [
    detection.cisco_snmp_community_exposure_attempted,
    detection.cisco_snmp_rw_access_attempted,
  ]

  tags = merge(local.cwe_209_common_tags, {
    type = "Benchmark"
  })
}