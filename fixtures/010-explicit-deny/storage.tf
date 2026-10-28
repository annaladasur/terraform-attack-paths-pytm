resource "aws_s3_bucket" "hr" {
  bucket = "acme-hr-records-111122223333"

  tags = {
    DataClassification = "confidential"
  }
}

resource "aws_s3_bucket_public_access_block" "hr" {
  bucket                  = aws_s3_bucket.hr.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "logs" {
  bucket = "acme-app-logs-111122223333"

  tags = {
    DataClassification = "internal"
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
