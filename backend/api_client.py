"""
api_client.py — Claude API integration
Sends device data to Claude for AI analysis
"""

import os
import logging
from anthropic import Anthropic

logger = logging.getLogger(__name__)

client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

MODEL = "claude-opus-4-6"
MAX_TOKENS = 4096

# ─────────────────────────────────────────────
# System prompts per analysis type
# ─────────────────────────────────────────────

SYSTEM_PROMPTS = {
    "bgp": """You are a CCIE-level BGP expert. Analyze the provided BGP show command output.
Identify: neighbor state issues, prefix count anomalies, path selection problems, missing routes.
Format your response with clear sections: Summary, Issues Found, Recommendations.
Be specific — reference actual neighbor IPs, ASNs, and prefix counts from the data.""",

    "config_review": """You are a senior network security and design expert.
Review the provided Cisco IOS running configuration for:
- Security vulnerabilities (weak auth, unencrypted protocols, open ACLs)
- Best practice violations (missing logging, no SSH v2, etc.)
- Design issues or misconfigurations
Format: Executive Summary, Critical Issues, Warnings, Recommendations.""",

    "log_analysis": """You are a network operations expert specializing in fault detection.
Analyze the provided device logs and interface data.
Identify: interface flaps, errors, drops, CPU/memory issues, authentication failures, routing changes.
Format: Alert Summary (by severity), Root Cause Analysis, Recommended Actions.""",

    "config_gen": """You are a Cisco IOS configuration expert.
Generate clean, production-ready Cisco IOS configuration based on the requirements provided.
Include inline comments explaining each section.
Always include security hardening (SSH v2, service password-encryption, login local, etc.).""",
}

DEFAULT_SYSTEM = """You are an expert network engineer and AI assistant specializing in Cisco IOS.
Provide clear, actionable analysis and recommendations."""


def analyze(
    analysis_type: str,
    device_data: str,
    custom_input: str = "",
) -> str:
    """
    Send device data to Claude for analysis.

    Args:
        analysis_type: One of bgp, config_review, log_analysis, config_gen
        device_data: Raw output from show commands (or empty string)
        custom_input: Additional context or manual paste from user

    Returns:
        Claude's analysis as a string
    """
    system_prompt = SYSTEM_PROMPTS.get(analysis_type, DEFAULT_SYSTEM)

    # Build the user message
    parts = []
    if device_data:
        parts.append(f"## Device Data\n\n```\n{device_data}\n```")
    if custom_input:
        parts.append(f"## Additional Context\n\n{custom_input}")
    if not parts:
        parts.append("No device data provided. Please describe what you need help with.")

    user_message = "\n\n".join(parts)

    # Truncate if too large (Claude context limit safety)
    if len(user_message) > 180_000:
        user_message = user_message[:180_000] + "\n\n[... output truncated ...]"
        logger.warning(f"Device data truncated for {analysis_type} analysis")

    try:
        logger.info(f"Sending {analysis_type} analysis to Claude ({len(user_message)} chars)")
        response = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        )
        result = response.content[0].text
        logger.info(f"Claude responded with {len(result)} chars")
        return result

    except Exception as e:
        logger.error(f"Claude API error: {e}")
        raise RuntimeError(f"AI analysis failed: {e}")
