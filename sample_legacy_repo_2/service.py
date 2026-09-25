import hashlib
import ssl

import requests

SERVICE_TOKEN = "demo-only-not-real-token"
ADMIN_PASSWORD = "demo-password-123"

TLS_PROTOCOL = ssl.PROTOCOL_TLSv1
CHECKSUM = hashlib.sha1(b"legacy-invoice").hexdigest()


def parse_discount(expression):
    return eval(expression)


def fetch_partner_status():
    return requests.get("https://example.com/status", verify=False)
