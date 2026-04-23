resource "aws_launch_template" "fail" {
  name          = "vulnerable-lt-${random_id.id.hex}"
  image_id      = "ami-0c55b24b055c14ff6" # Replace with a valid AMI ID for your region
  instance_type = "t2.micro"
  network_interfaces {
    associate_public_ip_address = true # THIS IS THE VULNERABILITY
  }
}

resource "aws_autoscaling_group" "vulnerable_asg" {
  name             = "vulnerable-asg-${random_id.id.hex}"
  min_size         = 1
  max_size         = 3
  desired_capacity = 1
  vpc_zone_identifier = ["subnet-0bb1c79de3EXAMPLE", "subnet-0bb1c79de4EXAMPLE"] # Replace with valid subnet IDs

  launch_template {
    id      = aws_launch_template.fail.id
    version = "$Latest"
  }

  tags = [
    {
      key                 = "Name"
      value               = "VulnerableAutoScalingGroup"
      propagate_at_launch = true
    },
  ]
}

resource "random_id" "id" {
  byte_length = 8
}

resource "aws_launch_template" "pass" {
  name          = "safe-lt-${random_id.id.hex}"
  image_id      = "ami-0c55b24b055c14ff6" # Replace with a valid AMI ID for your region
  instance_type = "t2.micro"
  network_interfaces {
    associate_public_ip_address = false
  }
}

resource "aws_autoscaling_group" "safe_asg" {
  name             = "safe-asg-${random_id.id.hex}"
  min_size         = 1
  max_size         = 3
  desired_capacity = 1
  vpc_zone_identifier = ["subnet-0bb1c79de3EXAMPLE", "subnet-0bb1c79de4EXAMPLE"] # Replace with valid subnet IDs

  launch_template {
    id      = aws_launch_template.pass.id
    version = "$Latest"
  }

  tags = [
    {
      key                 = "Name"
      value               = "SafeAutoScalingGroup"
      propagate_at_launch = true
    },
  ]
}
