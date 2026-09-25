import boto3
import requests

requests.get("https://example.com", verify=False)
s3 = boto3.client("s3")
ec2 = boto3.client("ec2")
s3.put_object(Bucket="legacy-demo", Key="report.txt", Body=b"demo", ACL="public-read")
ec2.request_spot_instances()
# Runtime: python2.7
