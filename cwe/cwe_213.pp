locals {
  cwe_213_common_tags = local.apache_access_log_detections_common_tags
}

benchmark "cwe_213" {
  title       = "CWE-213: Exposure of Sensitive Information Due to Incompatible Policies"
  description = "The product's intended functionality exposes information to certain actors in accordance with the developer's security policy, but this information is regarded as sensitive according to the intended security policies of other stakeholders such as the product's administrator, users, or others whose information is being processed."
  type        = "detection"
  children = [
    detection.cisco_http_auth_bypass_attempted,
    detection.cisco_ios_http_dos_attempted,
  ]

  tags = merge(local.cwe_213_common_tags, {
    type = "Benchmark"
  })
}