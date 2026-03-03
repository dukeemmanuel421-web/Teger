from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, conlist


class ThreatLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Action(str, Enum):
    ALLOW = "ALLOW"
    STEP_UP = "STEP_UP"
    BLOCK = "BLOCK"


Category = Literal[
    "phishing",
    "social_engineering",
    "invoice_fraud",
    "account_takeover",
    "payment_fraud",
    "benign",
]


class AnalyzeRequest(BaseModel):
    sender: str = Field(..., max_length=512)
    content: str = Field(..., max_length=15000)
    platform: str = Field(..., max_length=128)
    metadata: dict | None = None


class AnalyzeOutput(BaseModel):
    risk_score: int = Field(..., ge=0, le=100)
    threat_level: ThreatLevel
    categories: conlist(Category, min_length=1)  # type: ignore[arg-type]
    tactics: list[str]
    triggers: list[str]
    reasoning_summary: str = Field(..., max_length=500)
    recommended_action: Action
    user_message: str = Field(..., max_length=500)
    safe_next_steps: list[str]
    confidence: float = Field(..., ge=0, le=1)
    provider: Literal["gemini", "heuristic"]
    event_id: str


class GuardDecisionRequest(BaseModel):
    analysis: AnalyzeOutput
    payment_intent: dict


class CreditInquiryRequest(BaseModel):
    accountNumber: str
    bankCode: str
    beneficiaryName: str | None = None
    amount: float | None = None
    narration: str | None = None
    reference: str | None = None
