from __future__ import annotations

import hashlib
import logging
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ai.gemini_provider import analyze_with_gemini
from ai.heuristic_fallback import heuristic_analyze
from ai.schema import AnalyzeOutput, AnalyzeRequest, CreditInquiryRequest, GuardDecisionRequest
from db.models import Event
from db.session import Base, SessionLocal, engine
from interswitch.client import InterswitchClient
from settings import settings

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("teger_guardrails")

rate_buckets: dict[str, deque[float]] = defaultdict(deque)
client = InterswitchClient()


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    logger.info("database initialized")
    yield


app = FastAPI(title=settings.app_name, lifespan=lifespan)

if settings.allow_origins == ["*"]:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
        allow_credentials=False,
    )
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allow_origins,
        allow_methods=["*"],
        allow_headers=["*"],
        allow_credentials=True,
    )


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def enforce_rate_limit(request: Request):
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    bucket = rate_buckets[ip]
    while bucket and now - bucket[0] > settings.rate_limit_window_seconds:
        bucket.popleft()
    if len(bucket) >= settings.rate_limit_requests:
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Try again shortly.")
    bucket.append(now)


def determine_db_mode() -> str:
    return "postgres" if settings.database_url else "sqlite"


@app.get("/health")
def health():
    return {
        "ok": True,
        "service": settings.app_name,
        "gemini": "configured" if settings.gemini_api_key else "missing",
        "interswitch_mode": settings.interswitch_mode,
        "db": determine_db_mode(),
    }


def persist_event(db: Session, req: AnalyzeRequest, output: dict, payment: dict | None = None) -> str:
    event_id = str(uuid.uuid4())
    payload = dict(output)
    content_hash = hashlib.sha256(req.content.encode()).hexdigest()

    event = Event(
        id=event_id,
        created_at=datetime.utcnow(),
        platform=req.platform,
        sender=req.sender,
        content_hash=content_hash,
        risk_score=payload["risk_score"],
        threat_level=payload["threat_level"],
        categories=payload["categories"],
        tactics=payload["tactics"],
        triggers=payload["triggers"],
        recommended_action=payload["recommended_action"],
        provider=payload["provider"],
        payload_json=payload,
        payment_json=payment,
        raw_content=req.content,
    )
    db.add(event)
    db.commit()
    return event_id


@app.post("/v1/analyze", response_model=AnalyzeOutput)
def analyze(req: AnalyzeRequest, request: Request, db: Session = Depends(get_db)):
    enforce_rate_limit(request)
    if len(req.content) > settings.max_content_chars:
        raise HTTPException(status_code=413, detail=f"content exceeds {settings.max_content_chars} characters")

    try:
        result = analyze_with_gemini(req.sender, req.content, req.platform, req.metadata)
    except Exception as exc:
        logger.warning("gemini unavailable, fallback activated: %s", exc)
        result = heuristic_analyze(req.sender, req.content, req.platform, req.metadata)

    try:
        validated = AnalyzeOutput(**{**result, "event_id": "placeholder"})
    except Exception as exc:
        logger.warning("provider result invalid, enforcing heuristic fallback: %s", exc)
        safe = heuristic_analyze(req.sender, req.content, req.platform, req.metadata)
        validated = AnalyzeOutput(**{**safe, "event_id": "placeholder"})

    event_id = persist_event(db, req, validated.model_dump(exclude={"event_id"}))
    payload = validated.model_dump()
    payload["event_id"] = event_id
    return payload


@app.post("/v1/payments/guard/credit-inquiry")
def credit_inquiry(payload: CreditInquiryRequest, request: Request):
    enforce_rate_limit(request)
    return client.credit_inquiry(payload.model_dump())


class GuardDecisionResponse(BaseModel):
    decision: str
    rationale: str
    required_checks: list[str]
    ui_actions: list[str]


@app.post("/v1/payments/guard/decision", response_model=GuardDecisionResponse)
def guard_decision(body: GuardDecisionRequest):
    risk = body.analysis.risk_score
    level = body.analysis.threat_level
    intent = body.payment_intent

    checks = ["beneficiary_name_match", "channel_reconfirmation"]
    ui_actions = ["show_risk_modal", "log_forensic_event"]

    if risk >= 80 or level == "CRITICAL":
        decision = "BLOCK"
        checks += ["fraud_team_override"]
        ui_actions += ["disable_submit", "alert_soc"]
        rationale = "Critical fraud indicators detected. Transfer must be blocked pending investigation."
    elif risk >= 45:
        decision = "STEP_UP"
        checks += ["out_of_band_callback", "dual_approval"]
        ui_actions += ["require_mfa", "present_step_up_checklist"]
        rationale = "Elevated risk requires additional verification before release of funds."
    else:
        decision = "ALLOW"
        ui_actions += ["allow_submit"]
        rationale = "Low risk profile. Proceed with standard controls."

    if float(intent.get("amount", 0) or 0) >= 100000:
        checks.append("high_value_payment_authorizer")

    return {
        "decision": decision,
        "rationale": rationale,
        "required_checks": sorted(set(checks)),
        "ui_actions": sorted(set(ui_actions)),
    }


@app.post("/v1/events")
def create_event(payload: dict, db: Session = Depends(get_db)):
    event_id = str(uuid.uuid4())
    event = Event(
        id=event_id,
        created_at=datetime.utcnow(),
        platform=payload.get("platform", "unknown"),
        sender=payload.get("sender", "unknown"),
        content_hash=payload.get("content_hash", "manual"),
        risk_score=int(payload.get("risk_score", 0)),
        threat_level=payload.get("threat_level", "LOW"),
        categories=payload.get("categories", ["benign"]),
        tactics=payload.get("tactics", []),
        triggers=payload.get("triggers", []),
        recommended_action=payload.get("recommended_action", "ALLOW"),
        provider=payload.get("provider", "heuristic"),
        payload_json=payload,
        payment_json=payload.get("payment_json"),
        raw_content=payload.get("content", ""),
    )
    db.add(event)
    db.commit()
    return {"ok": True, "event_id": event_id}


@app.get("/v1/events")
def list_events(
    db: Session = Depends(get_db),
    threat_level: str | None = None,
    category: str | None = None,
    q: str | None = None,
    from_: str | None = Query(None, alias="from"),
    to: str | None = None,
    limit: int = 20,
    offset: int = 0,
):
    stmt = select(Event).order_by(Event.created_at.desc()).offset(offset).limit(min(limit, 100))

    if threat_level:
        stmt = stmt.where(Event.threat_level == threat_level)
    if q:
        stmt = stmt.where(Event.raw_content.ilike(f"%{q}%"))
    if from_:
        stmt = stmt.where(Event.created_at >= datetime.fromisoformat(from_))
    if to:
        stmt = stmt.where(Event.created_at <= datetime.fromisoformat(to))

    rows = db.execute(stmt).scalars().all()
    events = []
    for row in rows:
        if category and category not in (row.categories or []):
            continue
        events.append(
            {
                "id": row.id,
                "created_at": row.created_at.isoformat() + "Z",
                "platform": row.platform,
                "sender": row.sender,
                "risk_score": row.risk_score,
                "threat_level": row.threat_level,
                "categories": row.categories,
                "recommended_action": row.recommended_action,
                "provider": row.provider,
                "payload": row.payload_json,
            }
        )

    return {"items": events, "next_offset": offset + len(events)}
