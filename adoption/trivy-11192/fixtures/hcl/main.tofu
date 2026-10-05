resource "aws_ebs_volume" "effective" {
  availability_zone = "us-east-1a"
  size              = 1
  encrypted         = true
}
