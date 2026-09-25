"""Local, redacting legacy-risk scanner used by the Streamlit demo."""
from __future__ import annotations

import io
import json
import re
import zipfile
from pathlib import Path, PurePosixPath

TEXT_SUFFIXES = {".py", ".js", ".ts", ".json", ".txt", ".yml", ".yaml", ".ini", ".cfg", ".toml", ".md", ".properties", ".conf", ".sh"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "build", "dist", "__pycache__"}
MAX_FILE_BYTES = 1_000_000
MAX_ZIP_TOTAL_BYTES = 20_000_000
OUTDATED = {"django": (3, 2), "requests": (2, 25), "flask": (2, 0), "boto3": (1, 26), "pyyaml": (5, 4), "jinja2": (3, 0), "numpy": (1, 20), "paramiko": (2, 9), "cryptography": (3, 4)}


def _finding(kind, title, severity, file, line, suggested_fix):
    return {"type": kind, "title": title, "detail": "Potential secret detected; value redacted" if kind == "hardcoded_secret" else title, "severity": severity, "file": file, "line": line, "suggested_fix": suggested_fix}


def _version(value):
    numbers = re.findall(r"\d+", value)
    return tuple(map(int, (numbers + ["0", "0"])[:2]))


def _scan_text(name, text):
    findings = []
    lines = text.splitlines()
    secret = re.compile(r"(?i)\b[A-Za-z_]*(?:api[_-]?key|password|passwd|secret|token)[A-Za-z_]*\s*[:=]\s*['\"][^'\"]+['\"]")
    rules = [
        (r"\bAKIA[0-9A-Z]{16}\b", "hardcoded_secret", "AWS access key embedded in source", "critical", "Rotate the credential and use IAM roles"),
        (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "hardcoded_secret", "Private key embedded in source", "critical", "Remove the key, rotate it, and use a secret manager"),
        (r"\b(?:import\s+boto\b|from\s+boto\b)", "legacy_boto_v2", "Legacy boto v2 SDK usage", "high", "Migrate to boto3"),
        (r"\b(?:public-read|public-read-write)\b", "public_s3_acl", "Public-read S3 ACL", "high", "Keep S3 private and use explicit, least-privilege access"),
        (r"\brequest_spot_(?:instances|fleet)\b", "legacy_ec2_spot_api", "Legacy EC2 Spot request API", "high", "Use EC2 Fleet or Auto Scaling instead"),
        (r"\b(?:TLSv1|PROTOCOL_TLSv1)\b", "weak_tls", "TLS 1.0 usage", "high", "Require TLS 1.2 or newer"),
        (r"\b(?:hashlib\.)?(?:md5|sha1)\s*\(", "weak_hash", "MD5 or SHA-1 usage", "medium", "Use SHA-256 or a purpose-built password hash"),
        (r"\beval\s*\(", "unsafe_eval", "eval() usage", "high", "Replace eval() with explicit parsing or a safe allow-list"),
        (r"\bverify\s*=\s*False\b", "tls_verification_disabled", "TLS certificate verification disabled", "high", "Enable certificate verification and trust the correct CA"),
        (r"\b(?:python:?2\.7|python2(?:\.7)?)\b", "end_of_life_python", "End-of-life Python runtime", "high", "Upgrade to a supported Python 3 runtime"),
    ]
    for number, line in enumerate(lines, 1):
        if secret.search(line):
            findings.append(_finding("hardcoded_secret", "Hardcoded credential in source", "critical", name, number, "Move the value to a secret manager and rotate it"))
        for pattern, kind, title, severity, fix in rules:
            if re.search(pattern, line):
                findings.append(_finding(kind, title, severity, name, number, fix))
    if Path(name).name == "requirements.txt":
        for number, line in enumerate(lines, 1):
            match = re.match(r"\s*([\w.-]+)\s*==\s*([^\s#]+)", line)
            if match and match.group(1).lower() in OUTDATED:
                package = match.group(1).lower()
                if _version(match.group(2)) < OUTDATED[package]:
                    findings.append(_finding("outdated_dependency", f"Outdated dependency: {package}=={match.group(2)}", "high", name, number, f"Upgrade {package} to a maintained version and test compatibility"))
    if Path(name).name == "package.json":
        try:
            dependencies = {**json.loads(text).get("dependencies", {}), **json.loads(text).get("devDependencies", {})}
        except json.JSONDecodeError:
            dependencies = {}
        if "aws-sdk" in dependencies and re.search(r"(?:\^|~)?2(?:\.|$)", str(dependencies["aws-sdk"])):
            findings.append(_finding("aws_sdk_v2", "AWS SDK for JavaScript v2", "medium", name, 1, "Migrate to modular AWS SDK v3 packages"))
    return findings


def _is_safe_zip_entry(info):
    path = PurePosixPath(info.filename.replace("\\", "/"))
    return not (path.is_absolute() or ".." in path.parts or not info.filename or (info.external_attr >> 16) & 0o170000 == 0o120000)


def files_from_zip(data):
    files, skipped, total = {}, [], 0
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            if not _is_safe_zip_entry(info):
                raise ValueError(f"Unsafe ZIP entry rejected: {info.filename}")
            path = PurePosixPath(info.filename)
            if any(part in SKIP_DIRS for part in path.parts) or path.suffix.lower() not in TEXT_SUFFIXES or info.file_size > MAX_FILE_BYTES:
                skipped.append(info.filename)
                continue
            total += info.file_size
            if total > MAX_ZIP_TOTAL_BYTES:
                raise ValueError("ZIP contains too much supported text to scan safely")
            files[info.filename] = archive.read(info).decode("utf-8", errors="replace")
    return files, skipped


def scan_files(files):
    findings = [finding for name, text in files.items() for finding in _scan_text(name, text)]
    return {"findings": findings, "files_scanned": len(files)}


def redact_source_line(line):
    line = re.sub(r"\bAKIA[0-9A-Z]{16}\b", "[REDACTED_AWS_ACCESS_KEY]", line)
    line = re.sub(
        r"(?i)(\b[A-Za-z_]*(?:api[_-]?key|password|passwd|secret|token)[A-Za-z_]*\s*[:=]\s*)['\"][^'\"]+['\"]",
        r'\1"[REDACTED]"',
        line,
    )
    if "PRIVATE KEY-----" in line:
        return "[REDACTED_PRIVATE_KEY_MARKER]"
    return line


def remediation_contexts(files, findings):
    contexts = []
    for index, finding in enumerate(findings):
        lines = files.get(finding["file"], "").splitlines()
        number = finding["line"]
        if 1 <= number <= len(lines):
            contexts.append({
                "finding_index": index,
                "file": finding["file"],
                "line": number,
                "source_line": redact_source_line(lines[number - 1]),
            })
    return contexts


def files_from_directory(directory):
    root = Path(directory)
    files = {}
    for path in root.rglob("*"):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.parts) or path.suffix.lower() not in TEXT_SUFFIXES or path.stat().st_size > MAX_FILE_BYTES:
            continue
        files[path.relative_to(root).as_posix()] = path.read_text(encoding="utf-8", errors="replace")
    return files


def scan_directory(directory):
    return scan_files(files_from_directory(directory))


def scan_zip(data):
    files, skipped = files_from_zip(data)
    result = scan_files(files)
    result["skipped_files"] = skipped
    return result
