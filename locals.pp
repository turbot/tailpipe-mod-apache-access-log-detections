locals {
  apache_access_log_detections_common_tags = {
    category = "Detections"
    plugin   = "apache"
    service  = "Apache/AccessLog"
  }
}

