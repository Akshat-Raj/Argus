import subprocess
from stable_baselines3 import PPO
from rl_env import SecurityOrchestratorEnv

def main():
    repo_path = "/Users/akahatraj/development/incp"
    
    print(f"Scanning latest commit in local repository: {repo_path}...")
    try:
        # Get diff of HEAD
        result = subprocess.run(
            ["git", "-C", repo_path, "show", "-p"],
            capture_output=True, text=True, check=True
        )
        diff_text = result.stdout
    except Exception as e:
        print(f"Error running git show: {e}")
        return

    # Truncate diff if it's absurdly large to prevent memory/regex blowing up
    # (The previous git show had 100k+ lines, likely model weights)
    if len(diff_text) > 100000:
        print(f"Diff is very large ({len(diff_text)} chars), truncating to prevent memory issues...")
        diff_text = diff_text[:100000]

    # Initialize a dummy env just to use its _extract_features method
    env = SecurityOrchestratorEnv(scenario_generator=None)
    
    # Mocking a scenario dict for feature extraction
    scenario = {
        "diff": diff_text,
        "message": "Local repository uncommitted changes or latest commit",
    }
    
    obs = env._extract_features(scenario)
    print(f"Extracted Observation Vector: {obs}")
    
    try:
        model = PPO.load("models/ppo_security_agent")
    except Exception as e:
        print(f"Error loading model: {e}")
        return
        
    # Get the model's action prediction
    action, _states = model.predict(obs, deterministic=True)
    
    action_map = {
        0: "Allow",
        1: "Quarantine",
        2: "Halt CI/CD",
        3: "Block User",
        4: "Manual Review Requested"
    }
    
    decision = action_map.get(int(action), "Unknown")
    
    print("\n" + "="*50)
    print("RL Agent Pipeline Decision")
    print("="*50)
    print(f"Target Repo : {repo_path}")
    print(f"RL Decision : {decision}")
    if decision == "Allow":
        print("Reasoning   : No significant threats detected. Proceeding.")
    elif decision in ["Quarantine", "Halt CI/CD", "Block User"]:
        print("Reasoning   : High-confidence threat detected. Automated mitigation applied.")
    else:
        print("Reasoning   : Ambiguous state. Escalating to human reviewer.")
    print("="*50)

if __name__ == "__main__":
    main()
