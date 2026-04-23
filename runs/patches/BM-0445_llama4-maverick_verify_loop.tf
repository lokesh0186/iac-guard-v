resource "aws_elasticsearch_domain" "fail" {
  domain_name           = var.domain
  elasticsearch_version = "6.3"

  cluster_config {
    instance_type = "m4.large.elasticsearch"
  }
  encrypt_at_rest {
    enabled = true
  }
}