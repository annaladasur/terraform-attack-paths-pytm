resource "aws_iam_role" "deployer" {
  name = "deployer"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Action    = "sts:AssumeRole"
        Principal = { Service = "lambda.amazonaws.com" }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "deployer_admin" {
  role       = aws_iam_role.deployer.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_lambda_function" "deploy" {
  function_name = "deploy-hook"
  role          = aws_iam_role.deployer.arn
  runtime       = "python3.12"
  handler       = "app.handler"
  s3_bucket     = "artifacts-111122223333"
  s3_key        = "deploy-hook.zip"
}

resource "aws_iam_user" "ci" {
  name = "ci-deployer"
}

resource "aws_iam_user_policy" "ci" {
  name = "ci-everything"
  user = aws_iam_user.ci.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["iam:*"]
        Resource = "*"
      }
    ]
  })
}
