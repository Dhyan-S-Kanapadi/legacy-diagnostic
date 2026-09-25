# Legacy System Health Diagnostic Agent
**Team LSD — Legacy Systems Diagnosticians**

An AWS Bedrock-powered agent that scans a codebase for legacy risk (outdated deps,
deprecated AWS usage, missing docs, hardcoded secrets) and produces a prioritized,
explainable modernization roadmap.

## Structure
```
lsd-legacy-diagnostic/
├── scanner/              # Rule-based diagnostic scanners (Ajay's part)
├── sample_legacy_repo/   # Deliberately outdated sample repo to scan for demo
├── lambda/                # AWS Lambda handler wiring scanner -> Bedrock agent
├── ui/                    # Demo front end
└── docs/                  # Problem statement, architecture, spec docs
```

## Status
- [ ] Scanner logic
- [ ] Sample legacy repo seeded
- [ ] Bedrock agent shell (AWS side)
- [ ] Lambda wired end-to-end
- [ ] UI
- [ ] Demo script

See `docs/` for the full project overview and the AWS-vs-build split spec.

## Streamlit demo

The root Streamlit app scans an uploaded repository ZIP locally, redacts secret
values, then sends only structured findings to the deployed Lambda endpoint.

```powershell
py -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
$env:LSD_FUNCTION_URL="https://your-function.lambda-url.region.on.aws/"
$env:LSD_APP_API_TOKEN="replace-me"
.venv\Scripts\python -m streamlit run app.py
```

Use **Load seeded legacy demo** for a no-upload demo. The scanner is heuristic,
not a replacement for a security review; ZIPs are never extracted to disk.

The remediation view sends only sanitized finding context through Lambda to
Groq. Groq returns validated, single-line code patches: medium/low patches apply
automatically in memory, while critical/high patches are never applied and are
shown as acknowledged manual actions. The UI shows redacted before/after evidence,
rescans the result, and provides a separate fixed ZIP containing only automatic
low/medium changes; it never modifies the upload in place.
