resource "aws_launch_configuration" "safe_lc" {
  name          = "safe-lc-${random_id.id.hex}"
  image_id      = "ami-0c55b24b055c14ff6" 
  instance_type = "t2.micro"
  associate_public_ip_address = false 
}

resource "aws_autoscaling_group" "safe_asg" {
  name                 = "safe-asg-${random_id.id.hex}"
  launch_configuration = aws_launch_configuration.safe_lc.name
  min_size             = 1
  max_size             = 3
  desired_capacity   = 1
  vpc_zone_identifier = ["subnet-0bb1c79de3EXAMPLE", "subnet-0bb1c79de4EXAMPLE"] 


  tags = [
    {
      key                 = "Name"
      value               = "SafeAutoScalingGroup"
      propagate_at_launch = true
    },
  ]
}

resource "random_id" "id" {
  byte_length = 8
}