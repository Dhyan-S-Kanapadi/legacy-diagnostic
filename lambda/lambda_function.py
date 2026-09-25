import json
import os
import re
import urllib.error
import urllib.request

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
MODEL = "openai/gpt-oss-120b"

ROADMAP_PROMPT = """You are a legacy system diagnostic agent. Produce a prioritized modernization roadmap from the supplied findings. Explain business and engineering impact, give concrete fixes, put CRITICAL first, do not invent findings, and keep the response under 500 words."""

REMEDIATION_PROMPT = """You are a secure code-remediation agent. You receive scanner findings and one sanitized source line for each finding. Secret values have already been replaced with redaction markers.

Return ONLY valid JSON in this exact shape:
{"patches":[{"finding_index":0,"file":"path","line":1,"replacement":"one complete replacement source line","required_imports":["module"],"explanation":"short reason"}]}

Rules:
- Generate exactly one patch per supplied finding_index and only for supplied findings.
- file and line must exactly match that finding's context.
- replacement must be exactly one source line with original indentation and no newline characters.
- required_imports contains only standard importable module names needed by the replacement.
- Never reproduce, guess, or invent a secret. Replace hardcoded credentials with environment-variable reads and request the appropriate import.
- Make the smallest concrete change that resolves the finding while preserving behavior where possible.
- Do not include markdown fences or text outside the JSON object.
- For hardcoded secrets, replace the assignment with os.getenv using the existing variable name and request the os import.
- For boto v2 imports, use boto3; for public S3 ACLs, use private; for verify=False, use verify=True.
- For MD5/SHA-1, use SHA-256; for eval(), use ast.literal_eval and request the ast import.
- For legacy request_spot_instances/request_spot_fleet calls, use run_instances and explain that behavior must be tested.
- For Python 2 runtime declarations, replace the version with python3.12.
- For outdated pinned dependencies, replace the old version with a maintained version.
- If a migration can change behavior, still return the smallest conservative recommendation and clearly say that manual validation is required; the caller never applies critical/high patches automatically."""

SECRET_ASSIGNMENT = re.compile(r"(?i)\b[A-Za-z_]*(?:api[_-]?key|password|passwd|secret|token)[A-Za-z_]*\s*[:=]\s*['\"](?!\[REDACTED)[^'\"]+['\"]")
REMEDIATION_SCHEMA = {
    "type": "object",
    "properties": {
        "patches": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "finding_index": {"type": "integer"},
                    "file": {"type": "string"},
                    "line": {"type": "integer"},
                    "replacement": {"type": "string"},
                    "required_imports": {"type": "array", "items": {"type": "string"}},
                    "explanation": {"type": "string"},
                },
                "required": ["finding_index", "file", "line", "replacement", "required_imports", "explanation"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["patches"],
    "additionalProperties": False,
}


def call_groq(system_prompt, payload, max_tokens, response_schema=None):
    api_key = os.environ.get("GROQ_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("GROQ_API_KEY environment variable is missing")
    model = os.environ.get("GROQ_MODEL", MODEL).strip()
    request_body = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(payload, separators=(",", ":"))},
            ],
            "temperature": 0,
            "max_completion_tokens": max_tokens,
        }
    if response_schema:
        request_body["response_format"] = {
            "type": "json_schema",
            "json_schema": {"name": "remediation_patches", "strict": True, "schema": response_schema},
        }
    request = urllib.request.Request(
        GROQ_API_URL,
        data=json.dumps(request_body).encode("utf-8"),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json", "Accept": "application/json", "User-Agent": "LSD/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=25) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        error.read()
        raise RuntimeError(f"Groq returned HTTP {error.code}") from error
    except urllib.error.URLError as error:
        raise RuntimeError(f"Could not connect to Groq: {error.reason}") from error
    except TimeoutError as error:
        raise RuntimeError("Groq request timed out") from error
    try:
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as error:
        raise RuntimeError("Groq returned an unexpected response") from error


def parse_json_object(text):
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
    value = json.loads(cleaned)
    if not isinstance(value, dict):
        raise ValueError("Groq response must be a JSON object")
    return value


def context_has_secret(context):
    line = str(context.get("source_line", ""))
    return bool(re.search(r"\bAKIA[0-9A-Z]{16}\b|PRIVATE KEY-----", line) or SECRET_ASSIGNMENT.search(line))


def validate_remediation_request(findings, contexts):
    if not isinstance(contexts, list) or len(contexts) > 100:
        raise ValueError("contexts must be a JSON array with at most 100 entries")
    by_index = {}
    for context in contexts:
        if not isinstance(context, dict) or not isinstance(context.get("finding_index"), int):
            raise ValueError("Each context requires an integer finding_index")
        index = context["finding_index"]
        if index < 0 or index >= len(findings) or index in by_index:
            raise ValueError("Invalid or duplicate finding_index")
        finding = findings[index]
        if context.get("file") != finding.get("file") or context.get("line") != finding.get("line"):
            raise ValueError("Context file and line must match its finding")
        if context_has_secret(context):
            raise ValueError("Unredacted secret detected in remediation context")
        by_index[index] = context
    return contexts


def validate_groq_patches(raw_patches, findings):
    if not isinstance(raw_patches, list):
        raise ValueError("Groq response is missing patches")
    patches, seen = [], set()
    for patch in raw_patches:
        if not isinstance(patch, dict) or not isinstance(patch.get("finding_index"), int):
            continue
        index = patch["finding_index"]
        if index < 0 or index >= len(findings) or index in seen:
            continue
        finding = findings[index]
        replacement = patch.get("replacement")
        imports = patch.get("required_imports", [])
        if patch.get("file") != finding.get("file") or patch.get("line") != finding.get("line"):
            continue
        if not isinstance(replacement, str) or not replacement.strip() or "\n" in replacement or "\r" in replacement or len(replacement) > 1000:
            continue
        if context_has_secret({"source_line": replacement}):
            continue
        if not isinstance(imports, list) or len(imports) > 5 or not all(isinstance(item, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", item) for item in imports):
            continue
        seen.add(index)
        patches.append({
            "finding_index": index,
            "file": finding["file"],
            "line": finding["line"],
            "replacement": replacement,
            "required_imports": imports,
            "explanation": str(patch.get("explanation", "Groq-generated remediation"))[:500],
        })
    return patches


def create_response(status_code, body):
    return {"statusCode": status_code, "headers": {"Content-Type": "application/json", "Cache-Control": "no-store"}, "body": json.dumps(body)}


def lambda_handler(event, context):
    try:
        method = event.get("requestContext", {}).get("http", {}).get("method", "POST")
        if method == "GET":
            return create_response(200, {"status": "healthy", "service": "lsd-scanner-invoker", "model": os.environ.get("GROQ_MODEL", MODEL)})

        expected_token = os.environ.get("APP_API_TOKEN", "").strip()
        headers = {str(key).lower(): str(value) for key, value in (event.get("headers") or {}).items()}
        if expected_token and headers.get("x-api-key", "") != expected_token:
            return create_response(401, {"error": "Unauthorized"})

        body = event.get("body", event)
        if isinstance(body, str):
            body = json.loads(body or "{}")
        if not isinstance(body, dict):
            return create_response(400, {"error": "Request body must be a JSON object"})
        findings = body.get("findings")
        if not isinstance(findings, list):
            return create_response(400, {"error": "findings must be a JSON array"})
        if not findings or len(findings) > 100:
            return create_response(413 if len(findings) > 100 else 400, {"error": "findings must contain 1 to 100 entries"})

        model = os.environ.get("GROQ_MODEL", MODEL)
        if body.get("action") == "remediate":
            contexts = validate_remediation_request(findings, body.get("contexts"))
            groq = parse_json_object(call_groq(REMEDIATION_PROMPT, {"findings": findings, "contexts": contexts}, 4000, REMEDIATION_SCHEMA))
            patches = validate_groq_patches(groq.get("patches"), findings)
            return create_response(200, {"patches": patches, "patch_count": len(patches), "model": model})

        roadmap = call_groq(ROADMAP_PROMPT, {"findings": findings}, 1500)
        return create_response(200, {"roadmap": roadmap, "finding_count": len(findings), "model": model})
    except json.JSONDecodeError:
        return create_response(400, {"error": "Request body or Groq response contains invalid JSON"})
    except ValueError as error:
        return create_response(400, {"error": str(error)})
    except Exception as error:
        print(f"LSD request failed: {type(error).__name__}")
        return create_response(500, {"error": "Internal remediation service error"})
