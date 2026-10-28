resource "aws_vpc" "main" {
  cidr_block = "10.30.0.0/16"
}

resource "aws_subnet" "private" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.30.1.0/24"
}

resource "aws_security_group" "worker" {
  name   = "worker"
  vpc_id = aws_vpc.main.id

  ingress {
    description = "internal callers only"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["10.30.0.0/16"]
  }
}

resource "aws_iam_role" "worker" {
  name = "worker"

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

resource "aws_iam_instance_profile" "worker" {
  name = "worker"
  role = aws_iam_role.worker.name
}

resource "aws_iam_role_policy" "worker" {
  name = "read-config"
  role = aws_iam_role.worker.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = ["arn:aws:s3:::clean-app-config-111122223333/*"]
      }
    ]
  })
}

resource "aws_instance" "worker" {
  ami                         = "ami-0abcdef1234567890"
  instance_type               = "t3.small"
  subnet_id                   = aws_subnet.private.id
  vpc_security_group_ids      = [aws_security_group.worker.id]
  iam_instance_profile        = aws_iam_instance_profile.worker.name

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
}

resource "aws_s3_bucket" "config" {
  bucket = "clean-app-config-111122223333"

  tags = {
    DataClassification = "internal"
  }
}

resource "aws_s3_bucket" "customer" {
  bucket = "clean-customer-data-111122223333"

  tags = {
    DataClassification = "confidential"
  }
}

resource "aws_s3_bucket_public_access_block" "config" {
  bucket                  = aws_s3_bucket.config.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "customer" {
  bucket                  = aws_s3_bucket.customer.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
