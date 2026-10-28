variable "bucket_arn" {
  type = string
}

resource "aws_iam_role" "this" {
  name = "claims-api"

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

resource "aws_iam_instance_profile" "this" {
  name = "claims-api"
  role = aws_iam_role.this.name
}

resource "aws_iam_role_policy" "this" {
  name = "claims-read"
  role = aws_iam_role.this.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = ["${var.bucket_arn}/*"]
      }
    ]
  })
}

output "instance_profile_name" {
  value = aws_iam_instance_profile.this.name
}
