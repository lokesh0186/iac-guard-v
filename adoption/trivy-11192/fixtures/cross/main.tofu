resource "aws_ebs_volume" "cross_hcl" {
  availability_zone = "us-east-1a"
  size              = 1
  encrypted         = true
}
