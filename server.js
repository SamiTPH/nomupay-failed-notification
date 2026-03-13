import express from "express";
import crypto from "crypto";
import nodemailer from "nodemailer";

const app = express();
const port = process.env.PORT || 3000;

// Accept raw text payloads (NomuPay may send encrypted hex)
app.use(express.text({ type: "*/*", limit: "2mb" }));

/*
SMTP EMAIL TRANSPORT
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
DEDUPLICATION (memory)
*/
const seen = new Set();

/*
AES DECRYPTION (NomuPay encrypted payloads)
*/
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

/*
PARSE INCOMING WEBHOOK
Handles:
- JSON payload
- encrypted payload wrapper
- raw encrypted payload
*/
function parseIncomingWebhook(rawBody, headers) {

  let bodyText = rawBody;

  try {

    const parsed = JSON.parse(bodyText);

    if (typeof parsed.payload === "object" && parsed.payload !== null) {
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
      bodyText.trim(),
      process.env.WEBHOOK_SECRET_HEX,
      ivHex
    );

    return JSON.parse(decrypted);
  }
}

/*
SUCCESS RESULT CHECK
*/
function isSuccessResult(code) {
  return typeof code === "string" && code.startsWith("000.");
}

/*
HEALTH CHECK
*/
app.get("/", (_req, res) => {
  res.status(200).send("NomuPay webhook listener running");
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

  // Respond immediately so NomuPay doesn't retry
  res.status(200).send("OK");

  try {

    if (!process.env.WEBHOOK_SECRET_HEX) {
      console.error("Missing WEBHOOK_SECRET_HEX");
      return;
    }

    console.log("=== RAW WEBHOOK BODY ===");
    console.log(rawBody);

    console.log("=== WEBHOOK HEADERS ===");
    console.log(headers);

    const webhook = parseIncomingWebhook(rawBody, headers);

    console.log("=== DECRYPTED WEBHOOK ===");
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
      console.log("Duplicate webhook ignored:", dedupeKey);
      return;
    }

    seen.add(dedupeKey);

    /*
    SEND EMAIL IF PAYMENT FAILED
    */
    if (!isSuccessResult(resultCode) && process.env.ALERT_EMAIL_TO) {

      console.log("Payment failure detected → sending email");

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
          "Full Webhook:",
          JSON.stringify(webhook, null, 2)
        ].join("\n")
      });

      console.log("Email sent successfully");

    } else {
      console.log("Payment success or email disabled");
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