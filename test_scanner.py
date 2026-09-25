import io
import unittest
import zipfile

from fixer import apply_automatic_fixes, validate_groq_patches
from scanner import files_from_directory, remediation_contexts, scan_directory, scan_files, scan_zip


class ScannerTests(unittest.TestCase):
    def test_demo_detects_redacted_secret_and_legacy_rules(self):
        findings = scan_directory("demo_repo")["findings"]
        self.assertTrue(any(item["type"] == "hardcoded_secret" and item["detail"] == "Potential secret detected; value redacted" for item in findings))
        self.assertGreaterEqual(sum(item["type"] == "hardcoded_secret" for item in findings), 2)
        self.assertTrue(any(item["type"] == "legacy_boto_v2" for item in findings))
        self.assertTrue(any(item["type"] == "outdated_dependency" for item in findings))

    def test_zip_path_traversal_is_rejected(self):
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr("../escape.py", "print('no')")
        with self.assertRaises(ValueError):
            scan_zip(payload.getvalue())

    def test_groq_patches_are_gated_and_secret_context_is_redacted(self):
        files = files_from_directory("demo_repo")
        findings = scan_files(files)["findings"]
        contexts = remediation_contexts(files, findings)
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", str(contexts))
        self.assertNotIn("SuperSecret123", str(contexts))

        weak_index = next(index for index, item in enumerate(findings) if item["type"] == "weak_hash")
        secret_index = next(index for index, item in enumerate(findings) if item["type"] == "hardcoded_secret")
        patches = validate_groq_patches(files, findings, [
            {"finding_index": weak_index, "file": findings[weak_index]["file"], "line": findings[weak_index]["line"], "replacement": "hashlib.sha256(b\"legacy\")", "required_imports": [], "explanation": "Use a stronger hash."},
            {"finding_index": secret_index, "file": findings[secret_index]["file"], "line": findings[secret_index]["line"], "replacement": 'AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")', "required_imports": ["os"], "explanation": "Load the credential from the environment."},
        ])

        automatic_files, automatic = apply_automatic_fixes(files, patches)
        self.assertIn("hashlib.sha256", automatic_files["app.py"])
        self.assertIn("AKIAABCDEFGHIJKLMNOP", automatic_files["app.py"])
        self.assertEqual(1, len(automatic))

        self.assertTrue(patches[1]["requires_approval"])
        self.assertNotIn('os.getenv("AWS_ACCESS_KEY_ID")', automatic_files["app.py"])


if __name__ == "__main__":
    unittest.main()
