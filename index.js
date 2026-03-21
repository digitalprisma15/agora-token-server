const express = require("express");
const cors = require("cors");
const { RtcTokenBuilder, RtcRole } = require("agora-access-token");

const app = express();
app.use(cors());
app.use(express.json());

const APP_ID = (process.env.AGORA_APP_ID || "").trim();
const APP_CERTIFICATE = (process.env.AGORA_APP_CERTIFICATE || "").trim();
const DEFAULT_EXPIRE_SECONDS = Number.parseInt(process.env.TOKEN_EXPIRE_SECONDS || "3600", 10);

// Optional security key (recommended)
const API_KEY = (process.env.TOKEN_API_KEY || "").trim();

function parseExpireSeconds(value, fallbackSeconds) {
  const n = typeof value === "string" ? Number.parseInt(value, 10) : Number(value);
  if (!Number.isFinite(n)) return fallbackSeconds;
  if (n < 60) return 60;
  if (n > 24 * 60 * 60) return 24 * 60 * 60;
  return n;
}

app.get("/health", (_, res) => res.json({ ok: true }));

app.get("/api/agora-rtc-token", (req, res) => {
  try {
    if (!APP_ID || !APP_CERTIFICATE) {
      return res.status(500).json({
        error: "Server misconfigured: missing AGORA_APP_ID / AGORA_APP_CERTIFICATE",
      });
    }

    // If TOKEN_API_KEY is set, enforce it
    if (API_KEY) {
      const provided = (req.header("x-api-key") || "").trim();
      if (provided !== API_KEY) {
        return res.status(401).json({ error: "Unauthorized" });
      }
    }

    const channelName = String(req.query.channel_name || "").trim();
    const uidStr = String(req.query.uid || "").trim();
    const userAccount = String(req.query.user_account || "").trim();
    const expireSeconds = parseExpireSeconds(req.query.expire_seconds, DEFAULT_EXPIRE_SECONDS);

    if (!channelName) return res.status(400).json({ error: "channel_name is required" });
    if (!uidStr && !userAccount) {
      return res.status(400).json({ error: "uid or user_account is required" });
    }

    const now = Math.floor(Date.now() / 1000);
    const privilegeExpire = now + expireSeconds;

    // Broadcaster role for audio/video call publishing
    const role = RtcRole.PUBLISHER;

    let token;
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
      const uid = Number(uidStr);
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

    return res.json({ token, expireAt: privilegeExpire });
  } catch (e) {
    return res.status(500).json({ error: String(e) });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Agora token server running on :${port}`));
