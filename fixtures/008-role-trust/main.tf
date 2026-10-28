resource "aws_iam_role" "frontend" {
  name = "frontend"

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

resource "aws_lambda_function" "frontend" {
  function_name = "orders-frontend"
  role          = aws_iam_role.frontend.arn
  runtime       = "python3.12"
  handler       = "app.handler"
  s3_bucket     = "artifacts-111122223333"
  s3_key        = "frontend.zip"
}

resource "aws_lambda_function_url" "frontend" {
  function_name      = aws_lambda_function.frontend.function_name
  authorization_type = "NONE"
}

resource "aws_iam_role_policy" "frontend_assume" {
  name = "assume-data-reader"
  role = aws_iam_role.frontend.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = aws_iam_role.data_reader.arn
      }
    ]
  })
}

resource "aws_iam_role" "data_reader" {
  name = "data-reader"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Action    = "sts:AssumeRole"
        Principal = { AWS = aws_iam_role.frontend.arn }
      }
    ]
  })
}

resource "aws_iam_role_policy" "data_reader" {
  name = "read-db-secret"
  role = aws_iam_role.data_reader.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = aws_secretsmanager_secret.db.arn
      }
    ]
  })
}

resource "aws_secretsmanager_secret" "db" {
  name = "prod/orders/db"
}
