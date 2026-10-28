resource "aws_iam_role" "app" {
  name = "orders-app"

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
  name = "orders-app"
  role = aws_iam_role.app.name
}

resource "aws_iam_role_policy" "app_s3" {
  name = "orders-app-s3"
  role = aws_iam_role.app.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadReports"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Resource = [aws_s3_bucket.reports.arn, "${aws_s3_bucket.reports.arn}/*"]
      }
    ]
  })
}
