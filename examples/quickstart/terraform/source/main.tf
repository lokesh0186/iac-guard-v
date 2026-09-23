resource "aws_s3_bucket" "logs" {}

resource "aws_s3_bucket_notification" "events" {
  bucket = aws_s3_bucket.logs.id
}
