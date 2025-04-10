locals {
  owasp_top_10_2021_a02_common_tags = merge(local.owasp_top_10_common_tags, {
    owasp_top_10_version = "2021_a02"
  })
}

benchmark "owasp_top_10_2021_a02" {
  title       = "A02:2021 - Cryptographic Failures"
  description = "The first thing is to determine the protection needs of data in transit and at rest. For example, passwords, credit card numbers, health records, personal information, and business secrets require extra protection, mainly if that data falls under privacy laws, e.g., EU's General Data Protection Regulation (GDPR), or regulations, e.g., financial data protection such as PCI Data Security Standard (PCI DSS)."
  type        = "detection"
  children = [
    
  ]

  tags = merge(local.owasp_top_10_common_tags, {
    type = "Benchmark"
  })
}
