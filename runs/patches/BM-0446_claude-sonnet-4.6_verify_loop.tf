resource "aws_kms_key" "es_cmk" {
  description             = "KMS key for Elasticsearch CMK encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true
}

resource "aws_elasticsearch_domain" "fail" {
  domain_name           = var.domain
  elasticsearch_version = "6.3"

  cluster_config {
    instance_type = "m4.large.elasticsearch"
  }

  encrypt_at_rest {
    enabled    = true
    kms_key_id = aws_kms_key.es_cmk.arn
  }
}

resource "aws_elasticsearch_domain" "pass" {
  domain_name           = var.domain
  elasticsearch_version = "6.3"

  cluster_config {
    instance_type = "m4.large.elasticsearch"
  }

  encrypt_at_rest {
    enabled    = true
    kms_key_id = aws_kms_key.es_cmk.arn
  }

  vpc_options {
    subnet_ids = [
      data.aws_subnet_ids.selected.ids[0],
      data.aws_subnet_ids.selected.ids[1],
    ]

    security_group_ids = [aws_security_group.es.id]
  }

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }

}
