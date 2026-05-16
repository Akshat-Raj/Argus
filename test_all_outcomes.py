from stable_baselines3 import PPO
from rl_env import SecurityOrchestratorEnv

def main():
    print("Loading PPO Model...")
    try:
        model = PPO.load("models/ppo_security_agent")
    except Exception as e:
        print(f"Failed to load model: {e}")
        return

    env = SecurityOrchestratorEnv(scenario_generator=None)

    # Hand-crafted scenarios designed to trigger different feature flags
    test_cases = [
        {
            "name": "Clean Code (Safe)",
            "scenario": {
                "diff": "+ def test_function():\n+    return True\n",
                "message": "Add simple test function"
            }
        },
        {
            "name": "Minor Logging (Low Risk)",
            "scenario": {
                "diff": "+ console.log('Starting app...');\n+ print('App started')\n",
                "message": "Add startup logs"
            }
        },
        {
            "name": "Suspicious Code / Tech Debt (Medium Risk)",
            "scenario": {
                "diff": "+ // TODO: fix this later, hack to make it work\n",
                "message": "Quick hack for production"
            }
        },
        {
            "name": "Overprivileged / IAM Risk (High Risk)",
            "scenario": {
                "diff": "+ role = 'admin'\n+ resource = '*'\n+ mfa = false\n",
                "message": "Grant full admin access without MFA"
            }
        },
        {
            "name": "Injection Vulnerability (High Risk)",
            "scenario": {
                "diff": "+ eval(user_input)\n+ exec(command)\n+ db.execute('SELECT * FROM users WHERE name=' + sql)\n",
                "message": "Add dynamic user commands"
            }
        },
        {
            "name": "Hardcoded Secrets (Critical Risk)",
            "scenario": {
                "diff": "+ aws_access_token = 'AKIAIOSFODNN7EXAMPLE'\n+ db_password = 'supersecretpassword123'\n",
                "message": "Commit AWS token and password"
            }
        },
        {
            "name": "CI/CD Sabotage (Critical Risk)",
            "scenario": {
                "diff": "+ if (true) { fail('Build intentionally broken'); }\n",
                "message": "Force pipeline fail"
            }
        },
        {
            "name": "Maximum Threat (Everything Bad)",
            "scenario": {
                "diff": "+ password = 'secret_token'\n+ eval(sql)\n+ role = '*'\n+ admin = true\n+ mfa = false\n+ fail\n+ hack\n+ todo: fix",
                "message": "Complete destruction"
            }
        }
    ]

    action_map = {
        0: "Allow",
        1: "Quarantine",
        2: "Halt CI/CD",
        3: "Block User",
        4: "Manual Review Requested"
    }

    print("\n" + "="*70)
    print("RL Agent Outcome Matrix")
    print("="*70)

    found_actions = set()

    for tc in test_cases:
        obs = env._extract_features(tc["scenario"])
        action, _ = model.predict(obs, deterministic=True)
        decision = action_map.get(int(action), "Unknown")
        found_actions.add(decision)
        
        print(f"Scenario    : {tc['name']}")
        print(f"Features    : {obs}")
        print(f"RL Decision : {decision}")
        print("-" * 70)

    print("\nSummary of Actions Triggered:")
    for action_str in action_map.values():
        if action_str in found_actions:
            print(f"✅ {action_str}")
        else:
            print(f"❌ {action_str} (Not triggered by synthetic tests)")

if __name__ == "__main__":
    main()
