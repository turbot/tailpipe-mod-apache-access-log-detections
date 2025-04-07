locals {
  owasp_top_10_a02_2021_common_tags = merge(local.owasp_top_10_common_tags, {
    owasp_top_10_version = "a02_2021"
  })
}

benchmark "owasp_top_10_a02_2021" {
  title       = "A02:2021 - Cryptographic Failures"
  description = "The first thing is to determine the protection needs of data in transit and at rest. For example, passwords, credit card numbers, health records, personal information, and business secrets require extra protection, mainly if that data falls under privacy laws, e.g., EU's General Data Protection Regulation (GDPR), or regulations, e.g., financial data protection such as PCI Data Security Standard (PCI DSS)."
  type        = "detection"
  children = [
    benchmark.cwe_319,
    benchmark.cwe_326,
  ]

  tags = merge(local.owasp_top_10_common_tags, {
    type = "Benchmark"
  })
}
