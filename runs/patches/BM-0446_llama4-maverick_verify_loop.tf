resource "aws_elasticsearch_domain" "fail" {
  domain_name           = var.domain
  elasticsearch_version = "6.3"

  cluster_config {
    instance_type = "m4.large.elasticsearch"
  }

  encrypt_at_rest {
    enabled    = true
    kms_key_id = aws_kms_key.es.arn
  }
}

resource "aws_kms_key" "es" {
  description             = "KMS key for ES"
  deletion_window_in_days = 10
}