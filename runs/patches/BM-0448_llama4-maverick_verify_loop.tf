resource "aws_elasticsearch_domain" "fail" {
  domain_name           = var.domain
  elasticsearch_version = "6.3"

  cluster_config {
    instance_type = "m4.large.elasticsearch"
  }

  log_publishing_options {
    log_type = "INDEX_SLOW_LOGS"
    enabled  = true
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.es.arn
  }

  log_publishing_options {
    log_type = "SEARCH_SLOW_LOGS"
    enabled  = true
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.es.arn
  }

  log_publishing_options {
    log_type = "ES_APPLICATION_LOGS"
    enabled  = true
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.es.arn
  }
}

resource "aws_cloudwatch_log_group" "es" {
  name = "${var.domain}-es-logs"
}