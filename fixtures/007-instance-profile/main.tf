resource "aws_vpc" "main" {
  cidr_block = "10.40.0.0/16"
}

resource "aws_subnet" "private" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.40.1.0/24"
}

resource "aws_security_group" "worker" {
  name   = "payroll-worker"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["10.40.0.0/16"]
  }
}

resource "aws_iam_role" "app" {
  name = "app"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Action    = "sts:AssumeRole"
        Principal = { Service = "ec2.amazonaws.com" }
      }
    ]
  })
}

resource "aws_iam_instance_profile" "app" {
  name = "app"
  role = aws_iam_role.app.name
}

resource "aws_iam_role_policy" "app" {
  name = "payroll-export-read"
  role = aws_iam_role.app.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = ["arn:aws:s3:::acme-payroll-exports-111122223333/*"]
      }
    ]
  })
}

resource "aws_instance" "worker" {
  ami                         = "ami-0abcdef1234567890"
  instance_type               = "t3.small"
  subnet_id                   = aws_subnet.private.id
  vpc_security_group_ids      = [aws_security_group.worker.id]
  iam_instance_profile        = aws_iam_instance_profile.app.name

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }
}

resource "aws_s3_bucket" "payroll" {
  bucket = "acme-payroll-exports-111122223333"

  tags = {
    DataClassification = "confidential"
  }
}

resource "aws_s3_bucket_public_access_block" "payroll" {
  bucket                  = aws_s3_bucket.payroll.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
