const express = require("express");
const cors = require("cors");
const { RtcTokenBuilder, RtcRole } = require("agora-access-token");

const app = express();
app.use(cors());
app.use(express.json());

const APP_ID = (process.env.AGORA_APP_ID || "").trim();
const APP_CERTIFICATE = (process.env.AGORA_APP_CERTIFICATE || "").trim();
const DEFAULT_EXPIRE_SECONDS = Number.parseInt(process.env.TOKEN_EXPIRE_SECONDS || "3600", 10);

// ⚠️ Enable this ONLY for debugging
const DEBUG_MODE = (process.env.DEBUG_MODE || "false") === "true";

// Optional security key
const API_KEY = (process.env.TOKEN_API_KEY || "").trim();

function parseExpireSeconds(value, fallbackSeconds) {
  const n = typeof value === "string" ? Number.parseInt(value, 10) : Number(value);
  if (!Number.isFinite(n)) return fallbackSeconds;
  if (n < 60) return 60;
  if (n > 24 * 60 * 60) return 24 * 60 * 60;
  return n;
}

app.get("/health", (_, res) => res.json({ ok: true }));

function issueRtcToken(req, res) {
  try {
    if (!APP_ID || !APP_CERTIFICATE) {
      return res.status(500).json({
        error: "Server misconfigured: missing AGORA_APP_ID / AGORA_APP_CERTIFICATE",
      });
    }

    if (API_KEY) {
      const provided = (req.header("x-api-key") || "").trim();
      if (provided !== API_KEY) {
        return res.status(401).json({ error: "Unauthorized" });
      }
    }

    const input = Object.assign({}, req.query || {}, req.body || {});
    const channelName = String(input.channel_name || input.channelName || input.channel || "").trim();
    const uidStr = String(input.uid ?? "").trim();
    const userAccount = String(input.user_account || input.userAccount || "").trim();
    const expireSeconds = parseExpireSeconds(
      input.expire_seconds || input.expireSeconds,
      DEFAULT_EXPIRE_SECONDS
    );

    if (!channelName) return res.status(400).json({ error: "channel_name is required" });
    if (!uidStr && !userAccount) {
      return res.status(400).json({ error: "uid or user_account is required" });
    }

    const now = Math.floor(Date.now() / 1000);
    const privilegeExpire = now + expireSeconds;

    const role = RtcRole.PUBLISHER;

    let token;
    let uid = null;

    if (userAccount) {
      token = RtcTokenBuilder.buildTokenWithUserAccount(
        APP_ID,
        APP_CERTIFICATE,
        channelName,
        userAccount,
        role,
        privilegeExpire
      );
    } else {
      uid = Number(uidStr);
      if (!Number.isFinite(uid) || uid < 0) {
        return res.status(400).json({ error: "uid must be a non-negative number" });
      }

      token = RtcTokenBuilder.buildTokenWithUid(
        APP_ID,
        APP_CERTIFICATE,
        channelName,
        uid,
        role,
        privilegeExpire
      );
    }

    // ✅ BASE RESPONSE
    const response = {
      token,
      expireAt: privilegeExpire,
      channelName,
      uid,
      userAccount: userAccount || null,
      appId: APP_ID,
    };

    // ⚠️ DEBUG ONLY (never enable in production)
    // if (DEBUG_MODE) {
      response.appCertificate = APP_CERTIFICATE;
      response.generatedAt = now;
      response.expireInSeconds = expireSeconds;
    // }

    return res.json(response);
  } catch (e) {
    return res.status(500).json({ error: String(e) });
  }
}

app.get("/api/agora-rtc-token", issueRtcToken);
app.post("/api/agora-rtc-token", issueRtcToken);

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Agora token server running on :${port}`));
