resource "aws_ami_copy" "fail" {
  name              = "terraform-example"
  description       = "A copy of ami-xxxxxxxx"
  source_ami_id     = "ami-xxxxxxxx"
  source_ami_region = "us-west-1"
  encrypted         = true
  kms_key_id        = aws_kms_key.ami_key.arn
  tags = {
    Name = "HelloWorld"
    test = "failed"
  }
}

resource "aws_kms_key" "ami_key" {
  description             = "CMK for AMI copy encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true
}

resource "aws_ami_copy" "fail2" {
  name              = "terraform-example"
  description       = "A copy of ami-xxxxxxxx"
  source_ami_id     = "ami-xxxxxxxx"
  source_ami_region = "us-west-1"
  tags = {
    Name = "HelloWorld"
    test = "failed"
  }
}


resource "aws_ami_copy" "pass" {
  name              = "terraform-example"
  description       = "A copy of ami-xxxxxxxx"
  source_ami_id     = "ami-xxxxxxxx"
  source_ami_region = "us-west-1"
  encrypted         = true
  tags = {
    Name = "HelloWorld"
    test = "failed"
  }
}
