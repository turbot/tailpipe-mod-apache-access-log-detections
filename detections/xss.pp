locals {
  xss_common_tags = merge(local.apache_access_log_detections_common_tags, {
    category = "Cross-Site Scripting"
  })
}

benchmark "xss_detections" {
  title       = "Cross-Site Scripting Detections"
  description = "This benchmark contains cross site scripting (XSS) focused detections when scanning access logs."
  type        = "detection"
  children = [
    detection.basic_xss_attack,
    detection.xss_angular_template,
    detection.xss_attribute_injection,
    detection.xss_dom_based,
    detection.xss_encoded_attack,
    detection.xss_event_handler,
    detection.xss_html_injection,
    detection.xss_javascript_methods,
    detection.xss_javascript_uri,
    detection.xss_script_tag,
  ]

  tags = merge(local.xss_common_tags, {
    type = "Benchmark"
  })
}

detection "basic_xss_attack" {
  title           = "Basic XSS Attack"
  description     = "Detect basic Cross-Site Scripting (XSS) attack patterns in HTTP requests and User-Agent headers."
  documentation   = file("./detections/docs/basic_xss_attack.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.basic_xss_attack

  tags = merge(local.xss_common_tags, {
    mitre_attack_ids = "TA0009:T1059.007",
    owasp_top_10 = "A03:2021-Injection"
  })
}

query "basic_xss_attack" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      (
        request_uri is not null
        and (
          -- Script tag patterns
          request_uri ilike '%<script%'
          or request_uri ilike '%</script>%'
          -- Common XSS patterns
          or request_uri ilike '%alert(%'
          or request_uri ilike '%prompt(%'
          or request_uri ilike '%confirm(%'
          or request_uri ilike '%eval(%'
          or request_uri ilike '%document.cookie%'
          or request_uri ilike '%document.domain%'
          or request_uri ilike '%document.write%'
          -- URL encoded variants
          or request_uri ilike '%&#x3C;script%'
          or request_uri ilike '%\\x3Cscript%'
        )
      )
      OR
      (
        http_user_agent is not null
        and (
          -- Script tag patterns
          http_user_agent ilike '%<script%'
          or http_user_agent ilike '%</script>%'
          -- Common XSS patterns
          or http_user_agent ilike '%alert(%'
          or http_user_agent ilike '%prompt(%'
          or http_user_agent ilike '%confirm(%'
          or http_user_agent ilike '%eval(%'
          or http_user_agent ilike '%document.cookie%'
          or http_user_agent ilike '%document.domain%'
          or http_user_agent ilike '%document.write%'
          -- URL encoded variants
          or http_user_agent ilike '%&#x3C;script%'
          or http_user_agent ilike '%\\x3Cscript%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "xss_script_tag" {
  title           = "XSS Script Tag Vector"
  description     = "Detect Cross-Site Scripting attacks using script tags to execute arbitrary JavaScript code in requests and User-Agent headers."
  documentation   = file("./detections/docs/xss_script_tag.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.xss_script_tag

  tags = merge(local.xss_common_tags, {
    mitre_attack_ids = "TA0009:T1059.007",
    owasp_top_10 = "A03:2021-Injection"
  })
}

query "xss_script_tag" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      (
        request_uri is not null
        and (
          -- Standard script tags
          request_uri ilike '%<script>%'
          or request_uri ilike '%<script%src%'
          or request_uri ilike '%<script/%'
          -- Obfuscated script tags
          or request_uri ilike '%<scr%ipt%'
          or request_uri ilike '%<scr\\x00ipt%'
          or request_uri ilike '%<s%00cript%'
        )
      )
      OR
      (
        http_user_agent is not null
        and (
          -- Standard script tags
          http_user_agent ilike '%<script>%'
          or http_user_agent ilike '%<script%src%'
          or http_user_agent ilike '%<script/%'
          -- Obfuscated script tags
          or http_user_agent ilike '%<scr%ipt%'
          or http_user_agent ilike '%<scr\\x00ipt%'
          or http_user_agent ilike '%<s%00cript%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "xss_attribute_injection" {
  title           = "XSS Attribute Injection"
  description     = "Detect Cross-Site Scripting attacks using HTML attribute injection, such as event handlers or dangerous attributes in requests and User-Agent headers."
  documentation   = file("./detections/docs/xss_attribute_injection.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.xss_attribute_injection

  tags = merge(local.xss_common_tags, {
    mitre_attack_ids = "TA0009:T1059.007",
    owasp_top_10 = "A03:2021-Injection"
  })
}

query "xss_attribute_injection" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      (
        request_uri is not null
        and (
          -- Event handlers
          request_uri ilike '%onload=%'
          or request_uri ilike '%onerror=%'
          or request_uri ilike '%onclick=%'
          or request_uri ilike '%onmouseover=%'
          -- Dangerous attributes
          or request_uri ilike '%formaction=%'
          or request_uri ilike '%xlink:href=%'
          or request_uri ilike '%data:text/html%'
          or request_uri ilike '%pattern=%'
        )
      )
      OR
      (
        http_user_agent is not null
        and (
          -- Event handlers
          http_user_agent ilike '%onload=%'
          or http_user_agent ilike '%onerror=%'
          or http_user_agent ilike '%onclick=%'
          or http_user_agent ilike '%onmouseover=%'
          -- Dangerous attributes
          or http_user_agent ilike '%formaction=%'
          or http_user_agent ilike '%xlink:href=%'
          or http_user_agent ilike '%data:text/html%'
          or http_user_agent ilike '%pattern=%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "xss_javascript_uri" {
  title           = "XSS JavaScript URI Vector"
  description     = "Detect Cross-Site Scripting attacks using javascript: URI schemes in attributes like href or src in requests and User-Agent headers."
  documentation   = file("./detections/docs/xss_javascript_uri.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.xss_javascript_uri

  tags = merge(local.xss_common_tags, {
    mitre_attack_ids = "TA0009:T1059.007",
    owasp_top_10 = "A03:2021-Injection"
  })
}

query "xss_javascript_uri" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      (
        request_uri is not null
        and (
          -- JavaScript URI schemes
          request_uri ilike '%javascript:%'
          or request_uri ilike '%vbscript:%'
          -- Obfuscated javascript: URIs
          or request_uri ilike '%j%a%v%a%s%c%r%i%p%t%'
          or request_uri ilike '%jav&#x0A;ascript:%'
          or request_uri ilike '%javascript:url(%'
        )
      )
      OR
      (
        http_user_agent is not null
        and (
          -- JavaScript URI schemes
          http_user_agent ilike '%javascript:%'
          or http_user_agent ilike '%vbscript:%'
          -- Obfuscated javascript: URIs
          or http_user_agent ilike '%j%a%v%a%s%c%r%i%p%t%'
          or http_user_agent ilike '%jav&#x0A;ascript:%'
          or http_user_agent ilike '%javascript:url(%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "xss_event_handler" {
  title           = "XSS Event Handler Attack"
  description     = "Detect Cross-Site Scripting attacks using HTML event handlers like onload, onerror, and onclick in requests and User-Agent headers."
  documentation   = file("./detections/docs/xss_event_handler.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.xss_event_handler

  tags = merge(local.xss_common_tags, {
    mitre_attack_ids = "TA0009:T1059.007",
    owasp_top_10 = "A03:2021-Injection"
  })
}

query "xss_event_handler" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      (
        request_uri is not null
        and (
          -- Common event handlers
          request_uri ilike '%onload=%'
          or request_uri ilike '%onerror=%'
          or request_uri ilike '%onmouseover=%'
          or request_uri ilike '%onfocus=%'
          or request_uri ilike '%onmouseout=%'
          -- Less common event handlers
          or request_uri ilike '%onreadystatechange=%'
          or request_uri ilike '%onbeforeonload=%'
          or request_uri ilike '%onanimationstart=%'
        )
      )
      OR
      (
        http_user_agent is not null
        and (
          -- Common event handlers
          http_user_agent ilike '%onload=%'
          or http_user_agent ilike '%onerror=%'
          or http_user_agent ilike '%onmouseover=%'
          or http_user_agent ilike '%onfocus=%'
          or http_user_agent ilike '%onmouseout=%'
          -- Less common event handlers
          or http_user_agent ilike '%onreadystatechange=%'
          or http_user_agent ilike '%onbeforeonload=%'
          or http_user_agent ilike '%onanimationstart=%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "xss_html_injection" {
  title           = "XSS HTML Injection"
  description     = "Detect Cross-Site Scripting attacks using HTML tag injection that may execute JavaScript in requests and User-Agent headers."
  documentation   = file("./detections/docs/xss_html_injection.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.xss_html_injection

  tags = merge(local.xss_common_tags, {
    mitre_attack_ids = "TA0009:T1059.007",
    owasp_top_10 = "A03:2021-Injection"
  })
}

query "xss_html_injection" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      (
        request_uri is not null
        and (
          -- Common HTML tags that can be used for XSS
          request_uri ilike '%<iframe%'
          or request_uri ilike '%<img%'
          or request_uri ilike '%<svg%'
          or request_uri ilike '%<object%'
          or request_uri ilike '%<embed%'
          -- HTML5 tags that can be used for XSS
          or request_uri ilike '%<video%'
          or request_uri ilike '%<audio%'
        )
      )
      OR
      (
        http_user_agent is not null
        and (
          -- Common HTML tags that can be used for XSS
          http_user_agent ilike '%<iframe%'
          or http_user_agent ilike '%<img%'
          or http_user_agent ilike '%<svg%'
          or http_user_agent ilike '%<object%'
          or http_user_agent ilike '%<embed%'
          -- HTML5 tags that can be used for XSS
          or http_user_agent ilike '%<video%'
          or http_user_agent ilike '%<audio%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "xss_javascript_methods" {
  title           = "XSS JavaScript Methods"
  description     = "Detect Cross-Site Scripting attacks using dangerous JavaScript methods like eval(), setTimeout(), and Function() in requests and User-Agent headers."
  documentation   = file("./detections/docs/xss_javascript_methods.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.xss_javascript_methods

  tags = merge(local.xss_common_tags, {
    mitre_attack_ids = "TA0009:T1059.007",
    owasp_top_10 = "A03:2021-Injection"
  })
}

query "xss_javascript_methods" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      (
        request_uri is not null
        and (
          -- Dangerous JavaScript methods
          request_uri ilike '%eval(%'
          or request_uri ilike '%setTimeout(%'
          or request_uri ilike '%setInterval(%'
          or request_uri ilike '%new Function(%'
          or request_uri ilike '%fetch(%'
          or request_uri ilike '%document.write(%'
          or request_uri ilike '%document.cookie%'
        )
      )
      OR
      (
        http_user_agent is not null
        and (
          -- Dangerous JavaScript methods
          http_user_agent ilike '%eval(%'
          or http_user_agent ilike '%setTimeout(%'
          or http_user_agent ilike '%setInterval(%'
          or http_user_agent ilike '%new Function(%'
          or http_user_agent ilike '%fetch(%'
          or http_user_agent ilike '%document.write(%'
          or http_user_agent ilike '%document.cookie%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "xss_encoded_attack" {
  title           = "XSS Encoded Attack"
  description     = "Detect Cross-Site Scripting attacks using various encoding techniques to bypass filters in requests and User-Agent headers."
  documentation   = file("./detections/docs/xss_encoded_attack.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.xss_encoded_attack

  tags = merge(local.xss_common_tags, {
    mitre_attack_ids = "TA0009:T1059.007",
    owasp_top_10 = "A03:2021-Injection"
  })
}

query "xss_encoded_attack" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      (
        request_uri is not null
        and (
          -- HTML entity encoding
          request_uri ilike '%&#x%'
          or request_uri ilike '%&#%'
          -- Base64 encoding
          or request_uri ilike '%data:text/html;base64,%'
          -- URL encoding
          or request_uri ilike '%\\u00%'
          or request_uri ilike '%\\x%'
          -- UTF-7 encoding (IE specific)
          or request_uri ilike '%+ADw-%'
        )
      )
      OR
      (
        http_user_agent is not null
        and (
          -- HTML entity encoding
          http_user_agent ilike '%&#x%'
          or http_user_agent ilike '%&#%'
          -- Base64 encoding
          or http_user_agent ilike '%data:text/html;base64,%'
          -- URL encoding
          or http_user_agent ilike '%\\u00%'
          or http_user_agent ilike '%\\x%'
          -- UTF-7 encoding (IE specific)
          or http_user_agent ilike '%+ADw-%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "xss_dom_based" {
  title           = "DOM-Based XSS Attack"
  description     = "Detect potential DOM-based Cross-Site Scripting attacks targeting JavaScript DOM manipulation in requests and User-Agent headers."
  documentation   = file("./detections/docs/xss_dom_based.md")
  severity        = "high"
  display_columns = local.detection_display_columns

  query = query.xss_dom_based

  tags = merge(local.xss_common_tags, {
    mitre_attack_ids = "TA0009:T1059.007",
    owasp_top_10 = "A03:2021-Injection"
  })
}

query "xss_dom_based" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      (
        request_uri is not null
        and (
          -- DOM manipulation methods
          request_uri ilike '%document.getElementById%'
          or request_uri ilike '%document.querySelector%'
          or request_uri ilike '%document.write%'
          or request_uri ilike '%innerHTML%'
          or request_uri ilike '%outerHTML%'
          or request_uri ilike '%document.location%'
          or request_uri ilike '%window.location%'
          or request_uri ilike '%document.URL%'
          or request_uri ilike '%document.documentURI%'
        )
      )
      OR
      (
        http_user_agent is not null
        and (
          -- DOM manipulation methods
          http_user_agent ilike '%document.getElementById%'
          or http_user_agent ilike '%document.querySelector%'
          or http_user_agent ilike '%document.write%'
          or http_user_agent ilike '%innerHTML%'
          or http_user_agent ilike '%outerHTML%'
          or http_user_agent ilike '%document.location%'
          or http_user_agent ilike '%window.location%'
          or http_user_agent ilike '%document.URL%'
          or http_user_agent ilike '%document.documentURI%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}

detection "xss_angular_template" {
  title           = "AngularJS Template Injection"
  description     = "Detect potential AngularJS template injection attacks that can lead to Cross-Site Scripting in requests and User-Agent headers."
  documentation   = file("./detections/docs/xss_angular_template.md")
  severity        = "critical"
  display_columns = local.detection_display_columns

  query = query.xss_angular_template

  tags = merge(local.xss_common_tags, {
    mitre_attack_ids = "TA0009:T1059.007",
    owasp_top_10 = "A03:2021-Injection"
  })
}

query "xss_angular_template" {
  sql = <<-EOQ
    select
      ${local.detection_sql_columns}
    from
      apache_access_log
    where
      (
        request_uri is not null
        and (
          -- AngularJS syntax
          request_uri ilike '%\{\{%'
          or request_uri ilike '%\}\}%'
          -- Common AngularJS injection patterns
          or request_uri ilike '%constructor.constructor%'
          or request_uri ilike '%$eval%'
          or request_uri ilike '%ng-init%'
        )
      )
      OR
      (
        http_user_agent is not null
        and (
          -- AngularJS syntax
          http_user_agent ilike '%\{\{%'
          or http_user_agent ilike '%\}\}%'
          -- Common AngularJS injection patterns
          or http_user_agent ilike '%constructor.constructor%'
          or http_user_agent ilike '%$eval%'
          or http_user_agent ilike '%ng-init%'
        )
      )
    order by
      tp_timestamp desc;
  EOQ
}
