# pass

resource "aws_appsync_graphql_api" "all" {
  authentication_type = "API_KEY"
  name                = "example"

  log_config {
    cloudwatch_logs_role_arn = "aws_iam_role.example.arn"
    field_log_level          = "ALL"
  }
}

resource "aws_wafv2_web_acl_association" "appsync_all" {
  resource_arn = aws_appsync_graphql_api.all.arn
  web_acl_arn  = aws_wafv2_web_acl.appsync.arn
}

resource "aws_appsync_graphql_api" "error" {
  authentication_type = "API_KEY"
  name                = "example"

  log_config {
    cloudwatch_logs_role_arn = "aws_iam_role.example.arn"
    field_log_level          = "ERROR"
  }
}

# fail

resource "aws_appsync_graphql_api" "none" {
  authentication_type = "API_KEY"
  name                = "example"

  log_config {
    cloudwatch_logs_role_arn = "aws_iam_role.example.arn"
    field_log_level          = "NONE"
  }
}

resource "aws_wafv2_web_acl" "appsync" {
  name        = "appsync-waf-acl"
  scope       = "REGIONAL"
  description = "WAF Web ACL for AppSync"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "appsyncWAF"
    sampled_requests_enabled   = true
  }
}
