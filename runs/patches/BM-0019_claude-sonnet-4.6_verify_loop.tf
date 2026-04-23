resource "aws_ami" "pass" {
  name                = "terraform-example"
  virtualization_type = "hvm"
  root_device_name    = "/dev/xvda1"

  ebs_block_device {
    device_name = "/dev/xvda1"
    volume_size = 8
    snapshot_id = "someid"
  }

  ebs_block_device {
    device_name = "/dev/xvda2"
    volume_size = 8
    encrypted   = true
  }
}

resource "aws_ami" "pass2" {
  name                = "terraform-example"
  virtualization_type = "hvm"
  root_device_name    = "/dev/xvda1"

  ebs_block_device {
    device_name = "/dev/xvda1"
    volume_size = 8
    encrypted   = true
  }
}

resource "aws_ami" "fail" {
  name                = "terraform-example"
  virtualization_type = "hvm"
  root_device_name    = "/dev/xvda1"

  ebs_block_device {
    device_name = "/dev/xvda1"
    volume_size = 8
    snapshot_id = "someid"
    encrypted   = true
    kms_key_id  = "arn:aws:kms:eu-west-2:123456789012:key/mrk-1234abcd12ab34cd56ef1234567890ab"
  }

  ebs_block_device {
    device_name = "/dev/xvda2"
    volume_size = 8
    encrypted   = true
    kms_key_id  = "arn:aws:kms:eu-west-2:123456789012:key/mrk-1234abcd12ab34cd56ef1234567890ab"
  }
}

resource "aws_ami" "fail2" {
  name                = "terraform-example"
  virtualization_type = "hvm"
  root_device_name    = "/dev/xvda1"

  ebs_block_device {
    device_name = "/dev/xvda1"
    volume_size = 8
    encrypted   = true
    kms_key_id  = "arn:aws:kms:eu-west-2:123456789012:key/mrk-1234abcd12ab34cd56ef1234567890ab"
  }
}

resource "aws_ami" "fail3" {
  name                = "terraform-example"
  virtualization_type = "hvm"
  root_device_name    = "/dev/xvda1"

  ebs_block_device {
    device_name = "/dev/xvda1"
    volume_size = 8
    encrypted   = true
    kms_key_id  = "arn:aws:kms:eu-west-2:123456789012:key/mrk-1234abcd12ab34cd56ef1234567890ab"
  }
}


provider "aws" {
  region = "eu-west-2"
}
