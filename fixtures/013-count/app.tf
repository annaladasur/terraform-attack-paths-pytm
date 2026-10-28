resource "aws_instance" "app" {
  count                  = 2
  ami                    = "ami-0abcdef1234567890"
  instance_type          = "t3.small"
  subnet_id              = aws_subnet.app.id
  vpc_security_group_ids = [aws_security_group.app.id]
  iam_instance_profile   = aws_iam_instance_profile.app.name

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tags = {
    Name = "orders-app-${count.index}"
  }
}
