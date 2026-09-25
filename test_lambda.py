import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("lsd_lambda", Path("lambda/lambda_function.py"))
LAMBDA = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAMBDA)


class LambdaTests(unittest.TestCase):
    def test_remediation_contract_returns_validated_groq_patch(self):
        finding = {"type": "weak_hash", "title": "MD5 usage", "detail": "MD5 usage", "severity": "medium", "file": "app.py", "line": 2, "suggested_fix": "Use SHA-256"}
        context = {"finding_index": 0, "file": "app.py", "line": 2, "source_line": "hashlib.md5(data)"}
        groq_output = json.dumps({"patches": [{"finding_index": 0, "file": "app.py", "line": 2, "replacement": "hashlib.sha256(data)", "required_imports": [], "explanation": "Use SHA-256."}]})
        event = {"body": json.dumps({"action": "remediate", "findings": [finding], "contexts": [context]})}
        with patch.object(LAMBDA, "call_groq", return_value=groq_output):
            response = LAMBDA.lambda_handler(event, None)
        body = json.loads(response["body"])
        self.assertEqual(200, response["statusCode"])
        self.assertEqual("hashlib.sha256(data)", body["patches"][0]["replacement"])

    def test_unredacted_secret_context_is_rejected_before_groq(self):
        finding = {"type": "hardcoded_secret", "title": "Secret", "detail": "redacted", "severity": "critical", "file": "app.py", "line": 1, "suggested_fix": "Use environment"}
        context = {"finding_index": 0, "file": "app.py", "line": 1, "source_line": 'API_KEY = "real-secret-value"'}
        event = {"body": json.dumps({"action": "remediate", "findings": [finding], "contexts": [context]})}
        with patch.object(LAMBDA, "call_groq") as groq:
            response = LAMBDA.lambda_handler(event, None)
        self.assertEqual(400, response["statusCode"])
        groq.assert_not_called()


if __name__ == "__main__":
    unittest.main()
