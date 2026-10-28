resource "aws_s3_bucket" "customer_data" {
  bucket_prefix = "orders-customer-"

  tags = {
    DataClassification = "confidential"
  }
}

resource "aws_s3_bucket" "reports" {
  bucket = "orders-reports-111122223333"

  tags = {
    DataClassification = "internal"
  }
}
