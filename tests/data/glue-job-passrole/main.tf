# Minimal Glue-job PassRole escalation (written for the test suite).
# A user who can create and start Glue jobs and pass a Glue role reads what that role can read.
provider "aws" {
  region = "us-east-1"
}

resource "aws_iam_user" "etl" {
  name = "etl-operator"
}

resource "aws_iam_user_policy" "etl" {
  name = "glue-jobs"
  user = aws_iam_user.etl.name
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      { "Effect" : "Allow", "Action" : ["glue:CreateJob", "glue:StartJobRun"], "Resource" : "*" },
      { "Effect" : "Allow", "Action" : "iam:PassRole", "Resource" : aws_iam_role.job.arn }
    ]
  })
}

resource "aws_iam_role" "job" {
  name = "glue-job"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "glue.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "job" {
  name = "read-parameter"
  role = aws_iam_role.job.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "ssm:GetParameter", Resource = aws_ssm_parameter.db_password.arn }]
  })
}

resource "aws_ssm_parameter" "db_password" {
  name  = "/prod/db/password"
  type  = "SecureString"
  value = "not-a-real-secret"
}
