import logging
import structlog
import os
from pathlib import Path

# Setup structlog for JSON lines logging
LOG_FILE = Path(__file__).resolve().parents[1] / "audit_ledger.jsonl"

def setup_logger():
    # Only configure if not already configured to avoid duplicate handlers
    if structlog.is_configured():
        return structlog.get_logger()

    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer()
        ],
        logger_factory=structlog.WriteLoggerFactory(file=open(LOG_FILE, "a")),
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
    )
    return structlog.get_logger()

# Global logger instance
audit_logger = setup_logger()

def log_vulnerability(agent_name: str, action_taken: str, target_file: str, cve_id: str, reasoning: str, severity: str = "INFO"):
    """Helper to log a standardized vulnerability record."""
    audit_logger.info(
        "vulnerability_found",
        agent_name=agent_name,
        action_taken=action_taken,
        target_file=target_file,
        cve_id=cve_id,
        reasoning=reasoning,
        severity=severity
    )

def log_rl_decision(agent_name: str, action_taken: str, is_malicious: bool, reasoning: str):
    """Helper to log split-second decisions from the RL agent."""
    audit_logger.info(
        "rl_decision_made",
        agent_name=agent_name,
        action_taken=action_taken,
        is_malicious=is_malicious,
        reasoning=reasoning
    )
