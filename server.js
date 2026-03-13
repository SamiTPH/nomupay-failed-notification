import express from "express";
import crypto from "crypto";
import nodemailer from "nodemailer";

const APP_VERSION = "1.1.0"; // NEW: version marker to force git change

const app = express();
const port = process.env.PORT || 3000;

console.log("Starting NomuPay webhook service v" + APP_VERSION);

// Accept raw body
app.use(express.text({ type: "*/*", limit: "2mb" }));

/*
ENVIRONMENT CHECK
*/
console.log("Environment variables check:");
console.log("SMTP_HOST:", process.env.SMTP_HOST ? "OK" : "MISSING");
console.log("SMTP_USER:", process.env.SMTP_USER ? "OK" : "MISSING");
console.log("ALERT_EMAIL_TO:", process.env.ALERT_EMAIL_TO ? "OK" : "MISSING");
console.log("WEBHOOK_SECRET_HEX:", process.env.WEBHOOK_SECRET_HEX ? "OK" : "MISSING");

/*
SMTP CONFIGURATION
*/
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: String(process.env.SMTP_SECURE).toLowerCase() === "true",
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

/*
VERIFY SMTP CONNECTION
*/
transporter.verify()
  .then(() => console.log("SMTP connection successful"))
  .catch(err => console.error("SMTP connection failed:", err.message));

/*
IN MEMORY DEDUPE
*/
const seen = new Set();

/*
DECRYPT PAYLOAD
*/
function decryptHexPayload(encryptedHex, secretHex, ivHex, authTagHex) {

  const key = Buffer.from(secretHex, "hex");
  const iv = Buffer.from(ivHex, "hex");
  const encrypted = Buffer.from(encryptedHex, "hex");
  const authTag = Buffer.from(authTagHex, "hex");

  console.log("Crypto debug:");
  console.log("Key length:", key.length);
  console.log("IV length:", iv.length);
  console.log("AuthTag length:", authTag.length);

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    iv,
    { authTagLength: 16 }
  );

  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final()
  ]);

  return decrypted.toString("utf8");
}
/*
PARSE WEBHOOK
*/
function parseIncomingWebhook(rawBody, headers) {

  try {

    const parsed = JSON.parse(rawBody);

    if (typeof parsed.payload === "object") {
      return parsed;
    }

    if (typeof parsed.payload === "string") {

      const ivHex =
        headers["x-initialization-vector"] ||
        headers["initialization-vector"] ||
        parsed.initializationVector ||
        parsed.iv;

      if (!ivHex) {
        throw new Error("Missing initialization vector");
      }

      const decrypted = decryptHexPayload(
        parsed.payload,
        process.env.WEBHOOK_SECRET_HEX,
        ivHex
      );

      return JSON.parse(decrypted);
    }

    return parsed;

  } catch {

    const ivHex =
      headers["x-initialization-vector"] ||
      headers["initialization-vector"];

    if (!ivHex) {
      throw new Error("Missing IV for encrypted payload");
    }

    const decrypted = decryptHexPayload(
      rawBody.trim(),
      process.env.WEBHOOK_SECRET_HEX,
      ivHex
    );

    return JSON.parse(decrypted);
  }
}

/*
CHECK SUCCESS RESULT
*/
function isSuccessResult(code) {
  return typeof code === "string" && code.startsWith("000.");
}

/*
HEALTH CHECK
*/
app.get("/", (_req, res) => {
  res.status(200).send(`NomuPay webhook listener running v${APP_VERSION}`);
});

/*
WEBHOOK ENDPOINT
*/
app.post("/webhooks/nomupay", async (req, res) => {

  const rawBody = req.body;

  const headers = Object.fromEntries(
    Object.entries(req.headers).map(([k, v]) => [
      k.toLowerCase(),
      Array.isArray(v) ? v[0] : v
    ])
  );

  res.status(200).send("OK");

  try {

    if (!process.env.WEBHOOK_SECRET_HEX) {
      console.error("WEBHOOK_SECRET_HEX not configured");
      return;
    }

    console.log("Incoming NomuPay webhook received");

    const webhook = parseIncomingWebhook(rawBody, headers);

    console.log("Decrypted webhook payload:");
    console.log(JSON.stringify(webhook, null, 2));

    if (webhook?.type !== "PAYMENT" || !webhook?.payload) {
      console.log("Webhook ignored (not payment event)");
      return;
    }

    const payment = webhook.payload;

    const paymentId = payment.id || "unknown";
    const resultCode = payment.result?.code || "";
    const resultDescription = payment.result?.description || "";
    const amount = payment.amount || "";
    const currency = payment.currency || "";

    const dedupeKey = `${paymentId}:${resultCode}`;

    if (seen.has(dedupeKey)) {
      console.log("Duplicate webhook skipped:", dedupeKey);
      return;
    }

    seen.add(dedupeKey);

    if (!isSuccessResult(resultCode) && process.env.ALERT_EMAIL_TO) {

      console.log("Payment failure detected, sending alert email");

      await transporter.sendMail({
        from: process.env.ALERT_EMAIL_FROM,
        to: process.env.ALERT_EMAIL_TO,
        subject: `NomuPay payment failed - ${paymentId}`,
        text: `
Payment failure detected.

Payment ID: ${paymentId}
Amount: ${amount} ${currency}
Result Code: ${resultCode}
Description: ${resultDescription}

Webhook Payload:
${JSON.stringify(webhook, null, 2)}
`
      });

      console.log("Alert email successfully sent");

    } else {
      console.log("Payment success detected, no email required");
    }

  } catch (error) {

    console.error("Webhook processing error:", error.message);
    console.error("Raw body:", rawBody);
    console.error("Headers:", headers);

  }

});

/*
START SERVER
*/
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});