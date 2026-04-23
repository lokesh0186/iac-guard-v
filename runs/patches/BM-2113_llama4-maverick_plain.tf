provider "aws" {
  region = "us-west-2"
}

resource "aws_security_group" "example" {
  name        = "example-sg"
  description = "Example security group"

  # Inbound rule allowing all traffic
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Outbound rule allowing all traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "example" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
  vpc_security_group_ids = [aws_security_group.example.id]
}

resource "aws_security_group_rule" "example_ingress" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.example.id
}

provider "aws" {
  alias  = "us-east-1"
  region = "us-east-1"
}

resource "aws_security_group" "example_fixed" {
  provider = aws.us-east-1
  name        = "example-sg-fixed"
  description = "Example security group with restricted access"

  # Inbound rule allowing SSH from a specific IP
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["192.0.2.0/32"]
  }

  # Outbound rule allowing HTTPS to a specific IP
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/32"]
  }
}

resource "aws_instance" "example_fixed" {
  provider = aws.us-east-1
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
  vpc_security_group_ids = [aws_security_group.example_fixed.id]
} 
removed = true<|eot_id|>

Here is the valid HCL code.

provider "aws" {
  region = "us-west-2"
}

resource "aws_security_group" "example_fixed" {
  name        = "example-sg-fixed"
  description = "Example security group with restricted access"

  # Inbound rule allowing SSH from a specific IP
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["192.0.2.0/32"]
  }

  # Outbound rule allowing HTTPS to a specific IP
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/32"]
  }
}

resource "aws_instance" "example_fixed" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
  vpc_security_group_ids = [aws_security_group.example_fixed.id]
}