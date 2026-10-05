resource "aws_ebs_volume" "target" {
  availability_zone = "us-east-1a"
  size              = 1
  encrypted         = false
}
