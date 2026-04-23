# pass

# EC2 instance

resource "aws_instance" "default" {
  ami           = "ami-12345"
  instance_type = "t3.micro"
  vpc_security_group_ids = [aws_security_group.default.id]
}

resource "aws_security_group" "default" {
  name        = "default_sg"
  description = "default security group"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "private" {
  ami           = "ami-12345"
  instance_type = "t3.micro"
  vpc_security_group_ids = [aws_security_group.private.id]

  associate_public_ip_address = false
}

resource "aws_security_group" "private" {
  name        = "private_sg"
  description = "private security group"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# launch template

resource "aws_launch_template" "default" {
  image_id      = "ami-12345"
  instance_type = "t3.micro"
  vpc_security_group_ids = [aws_security_group.default.id]
}

resource "aws_launch_template" "private" {
  image_id      = "ami-12345"
  instance_type = "t3.micro"
  vpc_security_group_ids = [aws_security_group.private.id]

  network_interfaces {
    associate_public_ip_address = false
  }
}

# fail

# EC2 instance

resource "aws_instance" "public" {
  ami           = "ami-12345"
  instance_type = "t3.micro"
  vpc_security_group_ids = [aws_security_group.public.id]

  associate_public_ip_address = false
}

resource "aws_security_group" "public" {
  name        = "public_sg"
  description = "public security group"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# launch template

resource "aws_launch_template" "public" {
  image_id      = "ami-12345"
  instance_type = "t3.micro"
  vpc_security_group_ids = [aws_security_group.public.id]

  network_interfaces {
    associate_public_ip_address = false
  }
}

variable "public" {
  default = {
    "key1": false,
    "key2": false
  }
}

resource "aws_instance" "public_foreach" {
  for_each = var.public
  ami           = "ami-12345"
  instance_type = "t3.micro"
  vpc_security_group_ids = [aws_security_group.public_foreach.id]

  associate_public_ip_address = each.value
}

resource "aws_security_group" "public_foreach" {
  name        = "public_foreach_sg"
  description = "public foreach security group"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

variable "public_loop" {
  default = [{
    "name": "key3",
  },
  {
    "name": "key4",
  }]
}

variable "loop_list" {
  default = ["k", "v"]
}

resource "aws_instance" "public_foreach_loop" {
  for_each = { for val in var.public_loop : val.name => false }
  ami           = "ami-12345"
  instance_type = "t3.micro"
  vpc_security_group_ids = [aws_security_group.public_foreach_loop.id]

  associate_public_ip_address = each.value
}

resource "aws_security_group" "public_foreach_loop" {
  name        = "public_foreach_loop_sg"
  description = "public foreach loop security group"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "public_foreach_loop_list" {
  for_each = { for val in var.loop_list : val => false }
  ami           = "ami-12345"
  instance_type = "t3.micro"
  vpc_security_group_ids = [aws_security_group.public_foreach_loop_list.id]

  associate_public_ip_address = each.value
}

resource "aws_security_group" "public_foreach_loop_list" {
  name        = "public_foreach_loop_list_sg"
  description = "public foreach loop list security group"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

variable "loop_list_of_dicts" {
  default = [
    {
      "name": "public",
      "public_ip": false
    },
    {
      "name": "private",
      "public_ip": false
    }
  ]
}

locals {
  loop_list_of_dicts = [
    for val in var.loop_list_of_dicts : {
      name = val.name
      public_ip = val.public_ip
    }
  ]
}

resource "aws_instance" "public_foreach_loop_list_of_dicts" {
  for_each = { for val in local.loop_list_of_dicts : val.name => val }

  ami                         = "ami-12345"
  instance_type               = "t3.micro"
  vpc_security_group_ids      = [aws_security_group.public_foreach_loop_list_of_dicts.id]
  associate_public_ip_address = each.value.public_ip
}

resource "aws_security_group" "public_foreach_loop_list_of_dicts" {
  name        = "public_foreach_loop_list_of_dicts_sg"
  description = "public foreach loop list of dicts security group"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}