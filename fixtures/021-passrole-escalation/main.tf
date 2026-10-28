resource "aws_iam_user" "dev" {
  name = "dev-sam"
}

resource "aws_iam_user_policy" "dev" {
  name = "launch-ops-instances"
  user = aws_iam_user.dev.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "PassOpsRole"
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = aws_iam_role.ops.arn
      },
      {
        Sid      = "RunInstances"
        Effect   = "Allow"
        Action   = "ec2:RunInstances"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role" "ops" {
  name = "ops-automation"

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

resource "aws_iam_role_policy_attachment" "ops_admin" {
  role       = aws_iam_role.ops.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_user" "auditor" {
  name = "auditor-kim"
}

resource "aws_iam_user_policy" "auditor" {
  name = "read-iam"
  user = aws_iam_user.auditor.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["iam:Get*", "iam:List*"]
        Resource = "*"
      }
    ]
  })
}
