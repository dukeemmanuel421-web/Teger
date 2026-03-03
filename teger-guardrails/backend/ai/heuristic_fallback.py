from __future__ import annotations

import re

from ai.schema import Action, ThreatLevel

RULES = {
    "phishing": [r"http[s]?://", r"verify.*account", r"login.*expired", r"suspend(ed)?"],
    "social_engineering": [r"urgent", r"asap", r"confidential", r"don't call", r"ceo"],
    "invoice_fraud": [r"new bank", r"change.*account", r"updated invoice", r"remit to"],
    "account_takeover": [r"otp", r"mfa", r"code", r"password", r"2fa"],
    "payment_fraud": [r"wire", r"transfer", r"gift card", r"crypto", r"payroll"],
}


def _score_hits(text: str) -> tuple[dict[str, int], list[str]]:
    lower = text.lower()
    hits: dict[str, int] = {k: 0 for k in RULES}
    triggers: list[str] = []
    for category, patterns in RULES.items():
        for pattern in patterns:
            if re.search(pattern, lower):
                hits[category] += 1
                triggers.append(f"matched:{pattern}")
    return hits, triggers


def heuristic_analyze(sender: str, content: str, platform: str, metadata: dict | None = None) -> dict:
    combined = f"{sender}\n{platform}\n{content}\n{metadata or {}}"
    hits, triggers = _score_hits(combined)
    total_hits = sum(hits.values())

    if total_hits == 0:
        return {
            "risk_score": 8,
            "threat_level": ThreatLevel.LOW.value,
            "categories": ["benign"],
            "tactics": ["no_obvious_risk_signal"],
            "triggers": ["no_high_risk_keywords"],
            "reasoning_summary": "No significant fraud or phishing patterns were detected by fallback heuristics.",
            "recommended_action": Action.ALLOW.value,
            "user_message": "No major risk found. Continue normally.",
            "safe_next_steps": ["Proceed with normal verification controls."],
            "confidence": 0.62,
            "provider": "heuristic",
        }

    category_scores = sorted(hits.items(), key=lambda x: x[1], reverse=True)
    categories = [c for c, s in category_scores if s > 0][:3]
    weighted = min(100, total_hits * 16 + (10 if "invoice_fraud" in categories else 0))

    if weighted >= 80:
        level, action = ThreatLevel.CRITICAL.value, Action.BLOCK.value
    elif weighted >= 60:
        level, action = ThreatLevel.HIGH.value, Action.STEP_UP.value
    elif weighted >= 35:
        level, action = ThreatLevel.MEDIUM.value, Action.STEP_UP.value
    else:
        level, action = ThreatLevel.LOW.value, Action.ALLOW.value

    tactics = []
    if "social_engineering" in categories:
        tactics.append("urgency_and_authority_pressure")
    if "invoice_fraud" in categories:
        tactics.append("beneficiary_account_switch")
    if "account_takeover" in categories:
        tactics.append("credential_or_otp_harvest")
    if "phishing" in categories:
        tactics.append("link_based_lure")
    if "payment_fraud" in categories:
        tactics.append("transfer_redirection")

    return {
        "risk_score": weighted,
        "threat_level": level,
        "categories": categories or ["payment_fraud"],
        "tactics": tactics or ["suspicious_instruction_pattern"],
        "triggers": triggers[:8],
        "reasoning_summary": "Fallback heuristic found risk indicators commonly associated with fraud/social engineering.",
        "recommended_action": action,
        "user_message": "Potential scam detected. Verify beneficiary and intent before funds move.",
        "safe_next_steps": [
            "Call requester using a known number.",
            "Independently verify beneficiary account details.",
            "Require secondary approval for transfer release.",
        ],
        "confidence": 0.55,
        "provider": "heuristic",
    }
