import boto

s3.put_object(
    Bucket="legacy-billing-demo",
    Key="daily-report.csv",
    Body=b"demo",
    ACL="public-read",
)

ec2.request_spot_fleet()
