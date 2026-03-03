
import asyncio
import os
import sys
import pandas as pd
import logging

# Ensure we can import from the examples directory for agl_tinker if needed
sys.path.append(os.path.join(os.path.dirname(__file__), "Implementation", "libs", "agent_lightning", "examples", "tinker"))

try:
    import agentlightning as agl
    from agl_tinker.train import Config, main as entrypoint
    from agl_tinker.env import AGLDatasetBuilder
except ImportError:
    # Fallback if agl_tinker is not easily importable or if structure differs
    import agentlightning as agl
    # We might need to mock or use basic AGL generic classes if tinker is too coupled
    print("Warning: agl_tinker not found. Using basic AGL setup.")

from Implementation.src.Agents.TierAnalystAgent import TierAnalystAgent

# Setup basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load Dataset
def load_dataset():
    df = pd.read_csv("Implementation/Data/dataset_subset.csv")
    return df.to_dict(orient="records")

@agl.rollout
def tier1_rollout(task: dict, llm: agl.LLM, rollout: agl.Rollout) -> None:
    """
    Agent Lightning Rollout for Tier 1 Analyst.
    """
    # Instantiate the agent
    # Note: In a real training loop, we might want to inject the 'llm' from AGL 
    # into the agent to allow the optimizer to control the prompt/model.
    # For now, we assume the agent uses its own internal configuration but we 
    # focus on the prompt optimization if possible, or just huge feedback loop.
    
    # However, AGL optimizes the 'llm' passed to this function.
    # We need to bridge the AGL LLM with our Agent's LLM usage.
    # Since TierAnalystAgent uses `_stream_with_config` which uses `self.client` (OpenAI/Mistral),
    # we might need to override it or use a callback.
    
    # For this proof-of-concept, we'll assume the agent is "black box" regarding implementation 
    # but we will monkey-patch the prompt or client if needed, or better, 
    # we treat the 'task' as the input flow.
    
    agent = TierAnalystAgent(tier=1)
    
    # Construct input for the agent
    alert_data = {
        "SourceIP": task.get("IPV4_SRC_ADDR"),
        "DestinationIP": task.get("IPV4_DST_ADDR"),
        "SourcePort": task.get("L4_SRC_PORT"),
        "DestinationPort": task.get("L4_DST_PORT"),
        "Protocol": task.get("PROTOCOL"),
        "Attack": task.get("Attack", "Unknown"), # Included for context, but agent shouldn't cheat
        "Label": task.get("Label") # Ground Truth
    }
    
    input_payload = {
        "alert_data": alert_data,
        "current_status": "Training Mode"
    }

    # Run Agent
    try:
        result = agent.process(input_payload)
        
        # Evaluation Metric: Accuracy
        # Tier 1 Output contains 'enriched_alert' and 'severity'/'escalate'
        # We compare if the agent correctly identified it as Malicious (Label=1) or Benign (Label=0)
        
        ground_truth_label = task.get("Label") # 0 or 1
        agent_prediction_score = 0.0
        
        # Heuristic for "Malicious" detection based on agent output
        is_malicious_pred = result.get("escalate", False) or result.get("severity") in ["High", "Critical"]
        
        if ground_truth_label == 1 and is_malicious_pred:
            reward = 1.0 # True Positive
        elif ground_truth_label == 0 and not is_malicious_pred:
            reward = 1.0 # True Negative
        else:
            reward = 0.0 # Miss or False Positive
            
        # Emit reward to AGL
        agl.emit_reward(reward)
        logger.info(f"Rollout {rollout.rollout_id}: GT={ground_truth_label}, Pred={is_malicious_pred}, Reward={reward}")

    except Exception as e:
        logger.error(f"Agent failed: {e}")
        agl.emit_reward(0.0)

def main():
    # Load Data
    data = load_dataset()
    train_data = data[:int(len(data)*0.8)]
    val_data = data[int(len(data)*0.8):]
    
    # convert to list of strings/dicts for AGL
    # AGL expects tasks to be serializable
    
    # Configuration
    config = Config(
        learning_rate=1e-5,
        dataset_builder=AGLDatasetBuilder(
            train_dataset=train_data,
            val_dataset=val_data,
            batch_size=4,
            group_size=2,
            n_epochs=1
        ),
        renderer_name="qwen3_instruct", # Using default from example, change if needed
        model_name="Qwen/Qwen3-30B-A3B-Instruct-2507", # Placeholder
        log_path="logs/tier1_opt",
        llm_proxy_port=8081 # Avoid 6050
    )
    
    # Run Trainer
    # Since we lack a dedicated 'Tinker' server, we use local execution pattern if supported
    # or just the rollout loop.
    
    print("Starting optimization loop...")
    # asyncio.run(entrypoint(config)) # This requires the full stack
    
    # Simplified Runner (Dry Run style)
    store = agl.LightningStoreThreaded(agl.InMemoryLightningStore())
    trainer = agl.Trainer(
        n_runners=1,
        store=store
    )
    trainer.fit(tier1_rollout, train_dataset=train_data, val_dataset=val_data)

if __name__ == "__main__":
    main()
