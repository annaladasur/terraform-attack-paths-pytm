resource "aws_instance" "app" {
  ami                    = "ami-0abcdef1234567890"
  instance_type          = "t3.small"
  subnet_id              = aws_subnet.app.id
  vpc_security_group_ids = [aws_security_group.app.id]
  iam_instance_profile   = aws_iam_instance_profile.app.name
  monitoring             = true
  ebs_optimized          = true

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }

  root_block_device {
    encrypted = true
  }

  tags = {
    Name    = "orders-app"
    Service = "orders"
  }
}
