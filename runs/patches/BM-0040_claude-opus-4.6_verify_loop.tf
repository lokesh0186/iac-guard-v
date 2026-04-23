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
  web_acl_arn  = var.waf_acl_arn
}

resource "aws_appsync_graphql_api" "error" {
  authentication_type = "API_KEY"
  name                = "example"

  log_config {
    cloudwatch_logs_role_arn = "aws_iam_role.example.arn"
    field_log_level          = "ERROR"
  }
}

resource "aws_wafv2_web_acl_association" "appsync_error" {
  resource_arn = aws_appsync_graphql_api.error.arn
  web_acl_arn  = var.waf_acl_arn
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

variable "waf_acl_arn" {
  description = "ARN of the WAFv2 Web ACL to associate with AppSync APIs"
  type        = string
}
