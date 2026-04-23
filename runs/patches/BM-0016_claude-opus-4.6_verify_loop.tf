resource "aws_ami_copy" "fail" {
  name              = "terraform-example"
  description       = "A copy of ami-xxxxxxxx"
  source_ami_id     = "ami-xxxxxxxx"
  source_ami_region = "us-west-1"
  encrypted         = true
  kms_key_id        = "alias/my-cmk"
  tags = {
    Name = "HelloWorld"
    test = "failed"
  }
}


resource "aws_ami_copy" "fail2" {
  name              = "terraform-example"
  description       = "A copy of ami-xxxxxxxx"
  source_ami_id     = "ami-xxxxxxxx"
  source_ami_region = "us-west-1"
  encrypted         = true
  kms_key_id        = "alias/my-cmk"
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
  kms_key_id        = "alias/my-cmk"
  tags = {
    Name = "HelloWorld"
    test = "failed"
  }
}
