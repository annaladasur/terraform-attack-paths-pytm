locals {
  buckets = {
    "public-site" = "public"
    "invoices"    = "confidential"
    "scratch"     = "internal"
  }
}

resource "aws_s3_bucket" "data" {
  for_each = local.buckets
  bucket   = "acme-${each.key}-111122223333"

  tags = {
    DataClassification = each.value
  }
}
