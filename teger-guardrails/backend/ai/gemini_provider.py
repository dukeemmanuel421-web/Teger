from __future__ import annotations

import json
import logging

from google import genai
from google.genai import types

from ai.prompts import SYSTEM_PROMPT, build_user_prompt
from settings import settings

logger = logging.getLogger(__name__)


def analyze_with_gemini(sender: str, content: str, platform: str, metadata: dict | None = None) -> dict:
    if not settings.gemini_api_key:
        raise RuntimeError("GEMINI_API_KEY missing")

    client = genai.Client(api_key=settings.gemini_api_key)

    response = client.models.generate_content(
        model=settings.gemini_model,
        contents=build_user_prompt(sender, platform, content, metadata),
        config=types.GenerateContentConfig(
            temperature=0.1,
            response_mime_type="application/json",
            system_instruction=SYSTEM_PROMPT,
            max_output_tokens=700,
        ),
    )

    text = (response.text or "").strip()
    if not text:
        raise ValueError("Gemini returned empty response")

    try:
        data = json.loads(text)
        data["provider"] = "gemini"
        return data
    except json.JSONDecodeError as exc:
        logger.warning("Gemini invalid JSON: %s", text)
        raise ValueError("Gemini returned invalid JSON") from exc
