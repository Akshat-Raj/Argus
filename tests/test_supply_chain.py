import json
import unittest
from pathlib import Path

from tools.supply_chain import check_supply_chain_risks


class SupplyChainDemoTests(unittest.TestCase):
    def test_demo_victim_repo_flags_compromised_ai_router_pattern(self):
        repo = Path(__file__).resolve().parents[1] / "demo_victim_repo"
        report = json.loads(check_supply_chain_risks(str(repo)))
        finding_types = {finding["type"] for finding in report["findings"]}
        finding_files = {finding.get("file") for finding in report["findings"]}
        packages = {finding.get("package") for finding in report["findings"]}

        self.assertEqual(report["status"], "success")
        self.assertIn("IMPORT_TIME_EXFIL_TRIGGER", finding_types)
        self.assertIn("SECRET_EXFILTRATION_PATTERN", finding_types)
        self.assertIn("REMOTE_CODE_EXECUTION_FETCH", finding_types)
        self.assertIn("vendor/ai_router/secrets.py", finding_files)
        self.assertIn("vendor/trivy/setup.py", finding_files)
        self.assertIn("axois", packages)


if __name__ == "__main__":
    unittest.main()
