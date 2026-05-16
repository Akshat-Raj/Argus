import os
from stable_baselines3 import PPO, DQN
from rl_env import SecurityOrchestratorEnv
from scenario_generator import ScenarioGenerator

def train_models():
    # Cache 20 commits for fast RL looping
    print("Initializing Scenario Generator and fetching commits...")
    generator = ScenarioGenerator(cache_size=20)
    
    env = SecurityOrchestratorEnv(scenario_generator=generator)
    
    os.makedirs("models", exist_ok=True)
    
    print("Training PPO Model...")
    model_ppo = PPO("MlpPolicy", env, verbose=0)
    model_ppo.learn(total_timesteps=1000)
    model_ppo.save("models/ppo_security_agent")
    print("PPO Model saved.")
    
    print("Training DQN Model...")
    model_dqn = DQN("MlpPolicy", env, verbose=0)
    model_dqn.learn(total_timesteps=1000)
    model_dqn.save("models/dqn_security_agent")
    print("DQN Model saved.")

if __name__ == "__main__":
    train_models()
