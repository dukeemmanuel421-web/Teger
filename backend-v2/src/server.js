import express from "express";
import cors from "cors";
import crypto from "crypto";
import { GoogleGenAI } from "@google/genai";
import admin from "firebase-admin";

const app = express();
app.use(express.json({ limit: "1mb" }));

// Hackathon-friendly CORS (we’ll tighten later)
app.use(cors({ origin: true }));

// --- Config ---
const PORT = process.env.PORT || 10000;
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const TEGER_SHARED_SECRET = process.env.TEGER_SHARED_SECRET || "";

// --- Basic auth guard (prevents random abuse) ---
function requireSecret(req, res, next) {
  if (!TEGER_SHARED_SECRET) return next(); // if not set, allow (not recommended)
  const secret = req.header("x-teger-secret");
  if (secret !== TEGER_SHARED_SECRET) {
    return res.status(401).json({ error: "unauthorized" });
  }
  next();
}

// --- Gemini client ---
if (!GEMINI_API_KEY) {
  console.warn("⚠️ GEMINI_API_KEY is not set. /api/analyze will fail until you add it on Render.");
}
const ai = new GoogleGenAI({ apiKey: GEMINI_API_KEY });

// --- Firestore (admin) ---
// For hackathon: if Firestore is in test mode, this is enough.
// If admin init fails on Render, we’ll switch to service-account JSON (next step).
let db = null;
try {
  admin.initializeApp({
    projectId: process.env.FIREBASE_PROJECT_ID
  });
  db = admin.firestore();
} catch (e) {
  console.warn("⚠️ Firestore init failed:", e?.message || e);
}

// --- Helpers ---
function sha256(str) {
  return crypto.createHash("sha256").update(str || "").digest("hex");
}

function normalizeDomain(email) {
  if (!email || !email.includes("@")) return "";
  return email.split("@").pop().toLowerCase().trim();
}

function safeJsonFromModelText(text) {
  const s = text.indexOf("{");
  const e = text.lastIndexOf("}");
  if (s === -1 || e === -1) return { error: true, raw: text };
  try {
    return JSON.parse(text.slice(s, e + 1));
  } catch {
    return { error: true, raw: text };
  }
}

// --- Routes ---
app.get("/health", (_, res) => res.json({ ok: true }));

app.post("/api/analyze", requireSecret, async (req, res) => {
  const payload = req.body || {};

  const subject = payload.subject || "";
  const senderName = payload.sender?.name || "";
  const senderEmail = payload.sender?.email || "";
  const bodyText = (payload.body_text || "").slice(0, 12000);
  const links = Array.isArray(payload.links) ? payload.links.slice(0, 30) : [];

  const prompt = `
You are an enterprise phishing/social-engineering analyst.
Analyze the message for phishing/social engineering risk.

Return ONLY valid JSON in this schema:
{
  "risk_score": number (0-100),
  "verdict": "safe" | "suspicious" | "likely_phishing",
  "cues": [
    { "type": string, "evidence": string, "explanation": string }
  ],
  "recommended_user_action": string[]
}

Guidelines:
- Be conservative: if uncertain, mark suspicious not safe.
- Look for urgency, authority impersonation, credential requests, payment changes,
  link mismatch, strange sender domain, abnormal tone, threatening language, fake invoices.

Message:
Subject: ${subject}
SenderName: ${senderName}
SenderEmail: ${senderEmail}
Body: ${bodyText}
Links: ${JSON.stringify(links)}
`;

  try {
    const model = "gemini-2.5-flash";

    const result = await ai.models.generateContent({
      model,
      contents: [{ role: "user", parts: [{ text: prompt }] }]
    });

    const text = result.text ?? "";
    const analysis = safeJsonFromModelText(text);

    // Telemetry (privacy-minimized)
    const domain = normalizeDomain(senderEmail);
    const event = {
      createdAt: Date.now(),
      platform: payload.platform || "gmail",
      domainHash: sha256(domain),
      verdict: analysis.verdict || "unknown",
      risk_score: analysis.risk_score ?? null,
      cue_types: Array.isArray(analysis.cues) ? analysis.cues.map(c => c.type).slice(0, 10) : []
    };

    if (db) {
      try {
        await db.collection("events").add(event);
      } catch (e) {
        // Don’t fail response if telemetry fails
        console.warn("Telemetry write failed:", e?.message || e);
      }
    }

    return res.json(analysis);
  } catch (e) {
    return res.status(500).json({
      error: true,
      message: e?.message || String(e)
    });
  }
});

app.listen(PORT, () => {
  console.log(`Teger backend listening on port ${PORT}`);
});
