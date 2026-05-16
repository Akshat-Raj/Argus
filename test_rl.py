import logging
from stable_baselines3 import PPO
from rl_env import SecurityOrchestratorEnv
from scenario_generator import ScenarioGenerator

logging.basicConfig(level=logging.WARNING)

def test_model(num_tests=50):
    print("Initializing Scenario Generator for testing...")
    # Fetch fresh commits for testing
    generator = ScenarioGenerator(cache_size=num_tests)
    env = SecurityOrchestratorEnv(scenario_generator=generator)
    
    try:
        model = PPO.load("models/ppo_security_agent")
        print("Successfully loaded PPO model.\n")
    except Exception as e:
        print(f"Failed to load model: {e}")
        return

    tp = 0
    fp = 0
    tn = 0
    fn = 0
    manual_reviews = 0

    action_map = {
        0: "Allow",
        1: "Quarantine",
        2: "Halt CI/CD",
        3: "Block User",
        4: "Manual Review"
    }

    print(f"--- Running {num_tests} Test Scenarios ---")
    for i in range(num_tests):
        obs, _ = env.reset()
        
        action, _states = model.predict(obs, deterministic=True)
        action_val = int(action)
        action_str = action_map.get(action_val, "Unknown")
        
        is_malicious = env.is_malicious
        
        is_blocked = action_val in [1, 2, 3]
        is_allowed = action_val == 0
        is_manual = action_val == 4
        
        if is_malicious:
            if is_blocked:
                tp += 1
                result = "True Positive (Correctly Blocked)"
            elif is_allowed:
                fn += 1
                result = "False Negative (Missed Threat)"
            elif is_manual:
                manual_reviews += 1
                result = "Manual Review Requested"
        else:
            if is_blocked:
                fp += 1
                result = "False Positive (Unnecessarily Blocked)"
            elif is_allowed:
                tn += 1
                result = "True Negative (Correctly Allowed)"
            elif is_manual:
                manual_reviews += 1
                result = "Manual Review Requested"
                
        from tools.logger import log_rl_decision
        log_rl_decision(
            agent_name="RL-PPO-Agent",
            action_taken=action_str,
            is_malicious=is_malicious,
            reasoning=result
        )

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    print("\n=== RL Agent Evaluation Report ===")
    print("Security Effectiveness:")
    print(f"  True Positives: {tp}")
    print(f"  False Positives: {fp}")
    print(f"  False Negatives: {fn}")
    print(f"  True Negatives: {tn}")
    print(f"  Precision: {precision:.2f}")
    print(f"  Recall: {recall:.2f}")
    print(f"  F1-Score: {f1:.2f}")
    print(f"\nOperational Overhead:")
    print(f"  Manual Review Requests: {manual_reviews}")

if __name__ == "__main__":
    test_model()
