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

resource "aws_iam_role_policy" "app" {
  name = "s3-with-guardrail"
  role = aws_iam_role.app.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "BroadS3"
        Effect   = "Allow"
        Action   = ["s3:*"]
        Resource = "*"
      },
      {
        Sid    = "NeverHR"
        Effect = "Deny"
        Action = ["s3:*"]
        Resource = [
          "arn:aws:s3:::acme-hr-records-111122223333",
          "arn:aws:s3:::acme-hr-records-111122223333/*",
        ]
      }
    ]
  })
}
