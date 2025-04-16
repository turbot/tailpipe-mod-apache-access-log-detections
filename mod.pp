mod "apache_access_log_detections" {
  # hub metadata
  title         = "Apache Access Log Detections"
  description   = "Search your Apache access logs for high risk actions using Tailpipe."
  color         = "#CC2336"
  documentation = file("./docs/index.md")
  icon          = "/images/mods/turbot/apache-access-log-detections.svg"
  categories    = ["apache", "dashboard", "detections"]
  database      = var.database

  opengraph {
    title       = "Tailpipe Mod for Apache Access Log Detections"
    description = "Search your Apache access logs for high risk actions using Tailpipe."
    image       = "/images/mods/turbot/apache-access-log-detections-social-graphic.png"
  }
}
