locals {
  mitre_attack_v161_ta0007_t1083_common_tags = merge(local.mitre_attack_v161_ta0007_common_tags, {
    mitre_attack_technique_id = "T1083"
  })
}

benchmark "mitre_attack_v161_ta0007_t1083" {
  title         = "T1083 File and Directory Discovery"
  type          = "detection"
  documentation = file("./mitre_attack_v161/docs/ta0007_t1083.md")
  children = [
    detection.path_traversal,
    detection.encoded_path_traversal,
    detection.os_file_access,
    detection.restricted_file_access,
    detection.hidden_file_access
  ]

  tags = local.mitre_attack_v161_ta0007_t1083_common_tags
} 