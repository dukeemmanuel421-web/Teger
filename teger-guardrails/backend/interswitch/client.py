from __future__ import annotations

import base64
import logging
from datetime import datetime

import httpx

from settings import settings

logger = logging.getLogger(__name__)


class InterswitchClient:
    def __init__(self) -> None:
        self.mode = settings.interswitch_mode

    def credit_inquiry(self, payload: dict) -> dict:
        if self.mode != "live":
            account = payload.get("accountNumber", "0000000000")
            return {
                "ok": True,
                "mode": "mock",
                "data": {
                    "responseCode": "00",
                    "accountNumber": account,
                    "bankCode": payload.get("bankCode"),
                    "beneficiaryName": payload.get("beneficiaryName") or f"Demo User {account[-4:]}",
                    "kycLevel": "TIER_3",
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                },
            }

        try:
            token = self.get_access_token()
            path = settings.interswitch_credit_inquiry_path
            base = (settings.interswitch_base_url or "").rstrip("/")
            with httpx.Client(timeout=10) as client:
                res = client.post(
                    f"{base}{path}",
                    json=payload,
                    headers={"Authorization": f"Bearer {token}"},
                )
                res.raise_for_status()
                return {"ok": True, "mode": "live", "data": res.json()}
        except Exception as exc:
            logger.exception("Live credit inquiry failed")
            return {
                "ok": False,
                "mode": "live",
                "data": {
                    "error": str(exc),
                    "hint": "Live Interswitch call failed. Set INTERSWITCH_MODE=mock for demo reliability.",
                },
            }

    def get_access_token(self) -> str:
        if not all([
            settings.interswitch_client_id,
            settings.interswitch_secret_key,
            settings.interswitch_token_url,
        ]):
            raise RuntimeError("Missing live Interswitch credentials/env vars")

        encoded = base64.b64encode(
            f"{settings.interswitch_client_id}:{settings.interswitch_secret_key}".encode()
        ).decode()
        with httpx.Client(timeout=10) as client:
            resp = client.post(
                settings.interswitch_token_url,
                data={"grant_type": "client_credentials"},
                headers={"Authorization": f"Basic {encoded}"},
            )
            resp.raise_for_status()
            data = resp.json()
            token = data.get("access_token")
            if not token:
                raise RuntimeError("No access_token in token response")
            return token
