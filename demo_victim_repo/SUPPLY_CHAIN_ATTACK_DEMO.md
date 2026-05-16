# Supply Chain Attack Demo

This folder intentionally contains fictional supply-chain attack indicators
modeled after maintainer-token compromise and malicious package publish flows.

What the scanner should flag:

- `requirements.txt`: `ai-router==2.1.3`, a fictional compromised patch release.
- `requirements.txt`: `trivy==0.55.2`, a fictional malicious scanner package.
- `vendor/ai_router/__init__.py`: import-time trigger for `harvest_secrets()`.
- `vendor/ai_router/secrets.py`: environment and credential reads followed by
  `requests.post(...)` to a suspicious endpoint.
- `vendor/trivy/setup.py`: install-style `curl ... | bash` bootstrapper.
- `package.json`: npm `postinstall` exfiltration and `axois` typosquat.

Safe demo command:

```bash
uv run python -c 'from tools.supply_chain import check_supply_chain_risks; print(check_supply_chain_risks("demo_victim_repo"))'
```

Expected response:

- Block the compromised versions.
- Pin `ai-router==2.1.2`.
- Remove PyPI `trivy` and use the official Trivy distribution channel.
- Rotate LLM, cloud, GitHub, PyPI, npm, SSH, Kubernetes, and CI secrets.
- Audit lockfiles and package caches before rebuilding CI.
