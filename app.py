import hashlib
import json
import os
from pathlib import Path

import requests
import streamlit as st

from fixer import apply_automatic_fixes, validate_groq_patches, zip_files
from scanner import files_from_directory, files_from_zip, remediation_contexts, scan_files

st.set_page_config(page_title="LSD | Legacy System Diagnostic", page_icon="🛡️", layout="wide")
st.markdown("<style>.stApp {background:#0b1020;color:#e5e7eb}.stButton>button {background:#2563eb;color:white}</style>", unsafe_allow_html=True)
st.title("Legacy System Health Diagnostic")
st.caption("Local deterministic scanning. Groq generates fixes from sanitized source context.")

with st.sidebar:
    st.header("Lambda configuration")
    function_url = st.text_input("Function URL", value=os.getenv("LSD_FUNCTION_URL", ""))
    api_token = st.text_input("API token", value=os.getenv("LSD_APP_API_TOKEN", ""), type="password")
    timeout = st.number_input("Request timeout (seconds)", min_value=5, max_value=60, value=30)


def load_source(source_id, files, skipped=None):
    st.session_state.source_id = source_id
    st.session_state.source_files = files
    st.session_state.scan_result = scan_files(files)
    st.session_state.scan_result["skipped_files"] = skipped or []
    st.session_state.pop("roadmap", None)
    st.session_state.pop("groq_patches", None)


def post_lambda(payload):
    response = requests.post(function_url, json=payload, headers={"x-api-key": api_token}, timeout=timeout)
    if response.status_code in (401, 403):
        raise RuntimeError("Authentication failed. Check the API token.")
    if response.status_code == 429:
        raise RuntimeError("Lambda or Groq is rate-limiting requests. Try again shortly.")
    if response.status_code >= 500:
        raise RuntimeError("Lambda failed. Check its CloudWatch logs.")
    response.raise_for_status()
    return response.json()


uploaded = st.file_uploader("Upload a repository ZIP", type="zip")
use_demo = st.button("Load seeded legacy demo")
if use_demo:
    load_source("seeded-demo", files_from_directory(Path(__file__).parent / "demo_repo"))
elif uploaded:
    try:
        data = uploaded.getvalue()
        source_id = hashlib.sha256(data).hexdigest()
        if st.session_state.get("source_id") != source_id:
            files, skipped = files_from_zip(data)
            load_source(source_id, files, skipped)
    except (ValueError, OSError) as error:
        st.error(f"ZIP rejected: {error}")

result = st.session_state.get("scan_result")
if result:
    findings = result["findings"]
    files = st.session_state.source_files
    counts = {level: sum(f["severity"] == level for f in findings) for level in ("critical", "high", "medium")}
    cols = st.columns(4)
    for col, (label, value) in zip(cols, [("Critical", counts["critical"]), ("High", counts["high"]), ("Medium", counts["medium"]), ("Total", len(findings))]):
        col.metric(label, value)
    st.caption(f"Files scanned: {result['files_scanned']}")
    st.dataframe(findings, width="stretch", hide_index=True)
    st.download_button("Download complete report", json.dumps({"files_scanned": result["files_scanned"], "findings": findings}, indent=2), "lsd-report.json", "application/json")

    st.subheader("Groq AI remediation")
    st.caption("Only redacted source lines are sent. Medium/low patches apply automatically; critical/high findings are never changed and require manual remediation.")
    if st.button("Ask Groq to generate fixes", disabled=not findings):
        if not function_url or not api_token:
            st.error("Enter both Function URL and API token in the sidebar.")
        else:
            try:
                with st.spinner("Groq is generating code patches..."):
                    body = post_lambda({"action": "remediate", "findings": findings, "contexts": remediation_contexts(files, findings)})
                st.session_state.groq_patches = validate_groq_patches(files, findings, body.get("patches"))
                st.success(f"Groq generated {len(st.session_state.groq_patches)} validated patches using {body.get('model', 'the configured model')}.")
            except requests.Timeout:
                st.error("Groq remediation request timed out.")
            except (requests.RequestException, RuntimeError, ValueError) as error:
                st.error(str(error))

    patches = st.session_state.get("groq_patches")
    if patches is not None:
        automatic = [item for item in patches if not item["requires_approval"]]
        severe = [item for item in patches if item["requires_approval"]]
        st.info(f"{len(automatic)} low/medium Groq patches apply automatically. {len(severe)} critical/high findings require manual remediation.")
        acknowledged = 0
        for item in severe:
            label = f"Acknowledge manual action required: {item['severity'].upper()} — {item['title']} — {item['file']}:{item['line']}"
            if st.checkbox(label, key=f"{st.session_state.source_id}-{item['id']}", help=item["explanation"]):
                acknowledged += 1

        fixed_files, applied = apply_automatic_fixes(files, patches)
        remaining = scan_files(fixed_files)
        before_col, after_col, changed_col = st.columns(3)
        before_col.metric("Findings before", len(findings))
        after_col.metric("Findings after", len(remaining["findings"]))
        changed_col.metric("Automatic changes applied", len(applied))
        if applied:
            st.markdown("#### Automatically applied low/medium changes")
            st.dataframe([
                {"severity": item["severity"], "action": "Applied automatically", "file": item["file"], "line": item["line"], "before": item["before"], "after": item["after"], "Groq explanation": item["explanation"]}
                for item in applied
            ], width="stretch", hide_index=True)
        if severe:
            st.markdown("#### Critical/high recommendations — manual changes only")
            st.warning(f"Acknowledged {acknowledged} of {len(severe)} manual actions. These recommendations are not applied to the ZIP.")
            st.dataframe([
                {"severity": item["severity"], "file": item["file"], "line": item["line"], "current": item["before"], "Groq recommendation": item["after"], "why": item["explanation"]}
                for item in severe
            ], width="stretch", hide_index=True)
        st.download_button("Download automatically fixed repository ZIP", zip_files(fixed_files), "lsd-auto-fixed-repository.zip", "application/zip")

    if st.button("Generate modernization roadmap"):
        if not function_url or not api_token:
            st.error("Enter both Function URL and API token in the sidebar.")
        else:
            try:
                st.session_state.roadmap = post_lambda({"findings": findings}).get("roadmap", "Lambda returned no roadmap.")
            except requests.Timeout:
                st.error("Lambda request timed out.")
            except (requests.RequestException, RuntimeError, ValueError) as error:
                st.error(str(error))
    if st.session_state.get("roadmap"):
        st.markdown(st.session_state.roadmap)
