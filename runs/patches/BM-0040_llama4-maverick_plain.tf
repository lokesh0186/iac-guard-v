# pass

resource "aws_appsync_graphql_api" "all" {
  authentication_type = "AWS_IAM"
  name                = "example"

  log_config {
    cloudwatch_logs_role_arn = aws_iam_role.example.arn
    field_log_level          = "ALL"
  }
}

resource "aws_appsync_graphql_api" "error" {
  authentication_type = "AWS_IAM"
  name                = "example"

  log_config {
    cloudwatch_logs_role_arn = aws_iam_role.example.arn
    field_log_level          = "ERROR"
  }
}

# fail

resource "aws_appsync_graphql_api" "none" {
  authentication_type = "AWS_IAM"
  name                = "example"

  log_config {
    cloudwatch_logs_role_arn = aws_iam_role.example.arn
    field_log_level          = "ERROR"
  }
}