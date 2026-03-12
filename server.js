import express from "express";
import crypto from "crypto";
import nodemailer from "nodemailer";

const app = express();
const port = process.env.PORT || 3000;

// OPPWA / Total Processing webhook payloads may arrive as JSON wrapper or plain text.
// Using text lets us handle both.
app.use(express.text({ type: "*/*", limit: "2mb" }));

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: String(process.env.SMTP_SECURE).toLowerCase() === "true",
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// First version: in-memory dedupe.
// Good enough for initial testing, later move to Postgres/Redis.
const seen = new Set();

function decryptHexPayload(encryptedHex, secretHex, ivHex) {
  const key = Buffer.from(secretHex, "hex");
  const iv = Buffer.from(ivHex, "hex");
  const encrypted = Buffer.from(encryptedHex, "hex");

  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final()
  ]);

  return decrypted.toString("utf8");
}

function parseIncomingWebhook(rawBody, headers) {
  // Two documented wrapper styles:
  // 1) JSON wrapper
  // 2) None (plain hex string)
  //
  // We handle both. If your exact account format differs slightly,
  // Railway logs will show what to adjust.

  let bodyText = rawBody;

  try {
    const parsed = JSON.parse(bodyText);

    // Expected JSON wrapper case:
    // {
    //   "payload": "<encrypted hex or decrypted object>",
    //   ...
    // }
    if (typeof parsed.payload === "object" && parsed.payload !== null) {
      return parsed; // already usable JSON
    }

    if (typeof parsed.payload === "string") {
      const ivHex =
        headers["x-initialization-vector"] ||
        headers["initialization-vector"] ||
        parsed.initializationVector ||
        parsed.iv;

      if (!ivHex) {
        throw new Error("Missing initialization vector for encrypted JSON wrapper");
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
    // Wrapper "None" case: raw body itself is encrypted hex string
    const ivHex =
      headers["x-initialization-vector"] ||
      headers["initialization-vector"];

    if (!ivHex) {
      throw new Error("Missing initialization vector for raw encrypted payload");
    }

    const decrypted = decryptHexPayload(
      bodyText.trim(),
      process.env.WEBHOOK_SECRET_HEX,
      ivHex
    );

    return JSON.parse(decrypted);
  }
}

function isSuccessResult(code) {
  // The example success result in the docs is 000.000.000.
  // Start by treating codes starting with 000. as success.
  return typeof code === "string" && code.startsWith("000.");
}

app.get("/", (_req, res) => {
  res.status(200).send("NomuPay webhook listener is running");
});

app.post("/webhooks/nomupay", async (req, res) => {
  const rawBody = req.body;
  const headers = Object.fromEntries(
    Object.entries(req.headers).map(([k, v]) => [k.toLowerCase(), Array.isArray(v) ? v[0] : v])
  );

  // Always acknowledge quickly to avoid retries/timeouts.
  res.status(200).send("OK");

  try {
    if (!process.env.WEBHOOK_SECRET_HEX) {
      console.error("Missing WEBHOOK_SECRET_HEX");
      return;
    }

    const webhook = parseIncomingWebhook(rawBody, headers);

    console.log("=== DECRYPTED NOMUPAY WEBHOOK ===");
    console.log(JSON.stringify(webhook, null, 2));

    if (webhook?.type !== "PAYMENT" || !webhook?.payload) {
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
      return;
    }
    seen.add(dedupeKey);

    if (!isSuccessResult(resultCode) && process.env.ALERT_EMAIL_TO) {
      await transporter.sendMail({
        from: process.env.ALERT_EMAIL_FROM,
        to: process.env.ALERT_EMAIL_TO,
        subject: `NomuPay payment failed - ${paymentId}`,
        text: [
          "A NomuPay payment webhook indicates a non-success result.",
          "",
          `Payment ID: ${paymentId}`,
          `Amount: ${amount} ${currency}`.trim(),
          `Result Code: ${resultCode}`,
          `Result Description: ${resultDescription}`,
          "",
          "Webhook:",
          JSON.stringify(webhook, null, 2)
        ].join("\n")
      });
    }
  } catch (error) {
    console.error("Webhook processing error:", error.message);
    console.error("Raw body:", rawBody);
    console.error("Headers:", headers);
  }
});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});