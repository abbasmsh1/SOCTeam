"""
Reinforcement-learning feedback pipeline for the IDS.

The IDS emits predictions; the multi-tier SOC agent analyses each alert and
(optionally) a human confirms/overrides via the Quarantine UI. Those signals
form a natural reward channel — this subpackage turns them into supervised
labels, buffers them, and periodically fine-tunes the ANN so it drifts toward
the agents' validated verdicts.

Modules
-------
experience_buffer: SQLite-backed replay buffer (state, action, reward, label).
reward:            Deterministic reward + relabel rules from agent output.
feedback:          Hook called from SOCWorkflow finalize + quarantine decisions.
trainer:           Offline fine-tuning loop. Saves new checkpoint + manifest.
policy:            Per-class confidence-threshold adaptation.
"""

from .experience_buffer import ExperienceBuffer  # noqa: F401
from .reward import RewardCalculator  # noqa: F401
from .feedback import FeedbackHook  # noqa: F401
from .policy import AdaptiveConfidencePolicy  # noqa: F401
