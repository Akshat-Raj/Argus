import gymnasium as gym
from gymnasium import spaces
import numpy as np
import random

class SecurityOrchestratorEnv(gym.Env):
    """
    Custom Environment that follows gym interface.
    This environment simulates the state the orchestrator sees (findings from subagents)
    and rewards the actions taken to mitigate them.
    """
    metadata = {"render_modes": ["console"]}

    def __init__(self, scenario_generator=None):
        super().__init__()
        
        # Action Space:
        # 0: Allow (Do nothing)
        # 1: Quarantine PR/Commit
        # 2: Halt CI/CD Build
        # 3: Block User / Revoke Access
        # 4: Request Manual Review
        self.action_space = spaces.Discrete(5)
        
        # Observation Space:
        # Simplified vector representation of subagent findings
        # [critical_vulns, high_vulns, medium_vulns, low_vulns, 
        #  secrets_leaked, ci_failures, mfa_disabled, overprivileged_keys]
        self.observation_space = spaces.Box(
            low=0, high=100, shape=(8,), dtype=np.float32
        )
        
        self.scenario_generator = scenario_generator
        self.current_state = None
        self.is_malicious = False

    def _extract_features(self, scenario: dict) -> np.ndarray:
        """
        Simulates the feature extraction that the subagents would perform on the real commit diff.
        Uses keyword heuristics to keep the RL loop fast without calling the LLM API on every step.
        """
        if not scenario:
            return np.zeros(8, dtype=np.float32)
            
        diff = scenario.get("diff", "").lower()
        message = scenario.get("message", "").lower()
        full_text = diff + " " + message
        
        critical = full_text.count("password") + full_text.count("secret") + full_text.count("token")
        high = full_text.count("eval(") + full_text.count("exec(") + full_text.count("sql")
        medium = full_text.count("todo: fix") + full_text.count("hack")
        low = full_text.count("console.log") + full_text.count("print(")
        secrets = 1 if critical > 0 else 0
        ci_fail = 1 if "fail" in full_text else 0
        mfa_disabled = 1 if "mfa" in full_text and "false" in full_text else 0
        overpriv = 1 if "admin" in full_text or "*" in full_text else 0
        
        state = [
            min(critical, 2),
            min(high, 5),
            min(medium, 10),
            min(low, 20),
            secrets,
            ci_fail,
            mfa_disabled,
            min(overpriv, 2)
        ]
        return np.array(state, dtype=np.float32)

    def _generate_scenario(self):
        if self.scenario_generator:
            scenario = self.scenario_generator.get_random_scenario()
            if scenario:
                state = self._extract_features(scenario)
                # Determine maliciousness based on found features (real vulnerabilities)
                self.is_malicious = True if (sum(state[:2]) > 0 or state[4] > 0) else False
                return state
                
        # Fallback to random if generator fails or isn't provided
        self.is_malicious = random.choice([True, False])
        
        if self.is_malicious:
            state = [
                random.randint(0, 2), # critical
                random.randint(0, 5), # high
                random.randint(0, 10), # medium
                random.randint(0, 20), # low
                random.randint(0, 1), # secrets
                random.randint(0, 1), # ci_fail
                random.randint(0, 1), # mfa_disabled
                random.randint(0, 2), # overpriv
            ]
            # Ensure at least one critical/high/secret
            if sum(state[0:2]) + state[4] == 0:
                state[0] = 1 
        else:
            state = [
                0, # critical
                0, # high
                random.randint(0, 3), # medium
                random.randint(0, 5), # low
                0, # secrets
                0, # ci_fail
                0, # mfa_disabled
                0, # overpriv
            ]
            
        return np.array(state, dtype=np.float32)

    def reset(self, seed=None, options=None):
        super().reset(seed=seed)
        self.current_state = self._generate_scenario()
        return self.current_state, {}

    def step(self, action):
        reward = 0
        terminated = True # Single step environment for simplicity
        truncated = False
        info = {}

        # 0: Allow, 1: Quarantine, 2: Halt, 3: Block, 4: Manual Review
        is_blocked = action in [1, 2, 3]
        is_allowed = action == 0
        is_manual = action == 4

        if self.is_malicious:
            if is_blocked:
                # True Positive
                reward = 10
            elif is_allowed:
                # False Negative
                reward = -20
            elif is_manual:
                # Developer intervention
                reward = -1
        else:
            if is_blocked:
                # False Positive
                reward = -10
            elif is_allowed:
                # True Negative
                reward = 1
            elif is_manual:
                # Wasting developer time on clean code
                reward = -5

        # In a full implementation, you would trigger eval_harness logic here
        # to calculate exact mitigation latencies, rollback successes, etc.,
        # and subtract them from the reward.
        
        return self.current_state, reward, terminated, truncated, info

    def render(self):
        print(f"State: {self.current_state}, Malicious: {self.is_malicious}")
