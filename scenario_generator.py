import os
import random
import logging
import httpx
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)

# Curated list of intentionally vulnerable repositories
CURATED_REPOS = [
    # CI/CD & Pipeline Misconfiguration
    "cider-security-research/cicd-goat",
    "rung/threat-matrix-cicd",
    
    # Semantic Flaws & Application Security
    "juice-shop/juice-shop",
    "WebGoat/WebGoat",
    "OWASP/NodeGoat",
    
    # Systems-Level & Memory Corruption
    "google/fuzzing",
    
    # LLM & AI Security
    "ReversecLabs/damn-vulnerable-llm-agent",
    "greshake/llm-security",
]

class ScenarioGenerator:
    def __init__(self, cache_size: int = 20):
        # Load environment variables from .env file
        try:
            from tools.mcp import _load_dotenv
            _load_dotenv()
        except ImportError:
            pass

        self.github_token = os.getenv("GITHUB_PERSONAL_ACCESS_TOKEN")
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.github_token:
            self.headers["Authorization"] = f"Bearer {self.github_token}"
        else:
            logger.warning("No GitHub Token found. Rate limits will be severely restricted (60 requests/hour).")
            
        self.cache: List[Dict[str, Any]] = []
        self._populate_cache(cache_size)
        
    def _populate_cache(self, count: int):
        logger.info(f"Populating ScenarioGenerator cache with {count} commits...")
        for _ in range(count):
            scenario = self._fetch_random_commit()
            if scenario:
                self.cache.append(scenario)
        logger.info(f"Cache populated with {len(self.cache)} scenarios.")

    def _fetch_random_commit(self) -> Optional[Dict[str, Any]]:
        repo = random.choice(CURATED_REPOS)
        try:
            with httpx.Client(headers=self.headers, timeout=10.0) as client:
                page = random.randint(1, 3)
                commits_url = f"https://api.github.com/repos/{repo}/commits?per_page=10&page={page}"
                
                resp = client.get(commits_url)
                if resp.status_code != 200:
                    return None
                
                commits = resp.json()
                if not commits:
                    commits_url = f"https://api.github.com/repos/{repo}/commits?per_page=10&page=1"
                    commits = client.get(commits_url).json()
                    
                if not commits:
                    return None
                    
                commit = random.choice(commits)
                sha = commit["sha"]
                message = commit["commit"]["message"]
                
                diff_url = f"https://api.github.com/repos/{repo}/commits/{sha}"
                diff_headers = self.headers.copy()
                diff_headers["Accept"] = "application/vnd.github.v3.diff"
                
                diff_resp = client.get(diff_url, headers=diff_headers)
                if diff_resp.status_code != 200:
                    return None
                    
                diff_text = diff_resp.text
                max_diff_length = 5000
                if len(diff_text) > max_diff_length:
                    diff_text = diff_text[:max_diff_length] + "\n...[DIFF TRUNCATED]..."

                agent_input = (
                    f"Perform a SAST and CI/CD security review on the following commit from repository {repo}.\n"
                    f"Commit Message: {message}\n\n"
                    f"Commit Diff:\n```diff\n{diff_text}\n```\n"
                )
                
                return {
                    "repo": repo,
                    "sha": sha,
                    "message": message,
                    "diff": diff_text,
                    "agent_input": agent_input
                }
        except Exception as e:
            return None

    def get_random_scenario(self) -> Optional[Dict[str, Any]]:
        """
        Returns a random scenario from the cached commits.
        """
        if not self.cache:
            return self._fetch_random_commit()
        return random.choice(self.cache)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    generator = ScenarioGenerator(cache_size=2)
    scenario = generator.get_random_scenario()
    if scenario:
        print(f"Successfully generated scenario for {scenario['repo']} ({scenario['sha']})")
        print("Agent Input Preview:")
        print(scenario["agent_input"][:500] + "...")
