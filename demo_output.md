# LigmaFirewall — Demo Audit Output
**Target:** `demo_victim_repo`  
**Date:** 2026-05-01  
**Analyzer:** supply-chain-scanner

---

## Executive Summary
- **8 critical supply-chain findings** across npm and PyPI.
- **Typosquatted npm package** (`axois`) and **typosquatted PyPI package** (`litellm-ai`).
- `package.json` contains a **malicious `postinstall` hook** that exfiltrates environment variables to attacker C2.
- Vendored Python packages contain **import-time secret harvesting and outbound network calls**: `litellm_ai`, `ai_router`, `trivy`.
- Immediate action: remove malicious dependencies, quarantine vendored packages, rotate all exposed credentials.

---

## Findings

### CRITICAL

#### 1. Typosquatting — npm: `axois`
- `axois` is 80% similar to `axios` — likely typosquat.
- **Remediation:** `npm install axios` (remove `axois` from `package.json`)

#### 2. Malicious install script — `package.json` postinstall
- Script exfiltrates `process.env` to `https://exfil.attacker-c2.xyz/collect?...`
- **Remediation:** Remove `postinstall` script. Rotate all secrets present during `npm install`.

#### 3. Typosquatting — PyPI: `litellm-ai`
- `litellm-ai` is 88% similar to `litellm` — consistent with known March 2024 campaign.
- **Remediation:** `pip install litellm` (remove `litellm-ai` from `requirements.txt`). Rotate API keys.

#### 4. Import-time exfiltration — `vendor/ai_router/__init__.py`
- `harvest_secrets` helper invoked at import time.
- **Remediation:** Remove `vendor/ai_router/`, rotate credentials.

#### 5. Malicious import-time code — `vendor/litellm_ai/__init__.py`
- Outbound HTTP call fires on import.
- **Remediation:** Uninstall, inspect file, rotate all credentials present.

#### 6. Secret exfiltration — `vendor/ai_router/secrets.py:26`
- Reads env secrets and POSTs to `https://c2.evil.invalid/exfil`.
- **Secrets targeted:** `ANTHROPIC_API_KEY`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `KUBECONFIG`, `OPENAI_API_KEY`, `/root/.ssh/id_rsa`
- **Remediation:** Remove package, rotate all listed keys/tokens.

#### 7. Secret exfiltration — `vendor/litellm_ai/__init__.py:30`
- Reads env secrets, sends via `urllib.request.urlopen` to `http://127.0.0.1:19999/collect?h=`
- **Remediation:** Remove package, rotate all exposed credentials.

#### 8. Remote code execution — `vendor/trivy/setup.py:12`
- Shell command fetches remote payload from `https://evil.invalid/payload.sh`.
- **Remediation:** Block package, inspect CI logs, rebuild from trusted lockfiles.

---

## Immediate Response Plan
1. Remove from `requirements.txt`: `litellm-ai`, `ai-router`, `trivy`
2. Remove from `package.json` dependencies: `axois`; remove `postinstall` script
3. Quarantine: `vendor/ai_router/`, `vendor/litellm_ai/`, `vendor/trivy/`
4. Rotate credentials: OpenAI/Anthropic keys, AWS credentials, GitHub tokens, kubeconfig, SSH keys
5. Reinstall from trusted lockfiles only
6. Audit recent `npm install` / `pip install` CI activity
