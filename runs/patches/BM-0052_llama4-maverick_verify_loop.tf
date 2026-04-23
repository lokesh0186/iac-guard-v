resource "aws_autoscaling_group" "vulnerable_asg" {
  name                 = "vulnerable-asg-${random_id.id.hex}"
  launch_template {
    id      = aws_launch_template.vulnerable_lt.id
    version = "$Latest"
  }
  min_size             = 1
  max_size             = 3
  desired_capacity   = 1
  vpc_zone_identifier = ["subnet-0bb1c79de3EXAMPLE", "subnet-0bb1c79de4EXAMPLE"]
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
resource "aws_launch_template" "vulnerable_lt" {
  name          = "vulnerable-lt-${random_id.id.hex}"
  image_id      = "ami-0c55b24b055c14ff6"
  instance_type = "t2.micro"
}