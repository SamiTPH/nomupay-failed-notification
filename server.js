import express from "express";
import crypto from "crypto";
import nodemailer from "nodemailer";

const app = express();
const port = process.env.PORT || 3000;

console.log("Starting NomuPay webhook listener");

// accept encrypted hex body
app.use(express.text({ type: "*/*", limit: "5mb" }));

/*
EMAIL SETUP
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
DEDUPLICATION
*/
const seen = new Set();

/*
AES-256-GCM DECRYPTION
*/
function decryptHexPayload(encryptedHex, secretHex, ivHex, authTagHex) {

  const key = Buffer.from(secretHex, "hex");
  const iv = Buffer.from(ivHex, "hex");
  const encrypted = Buffer.from(encryptedHex, "hex");
  const authTag = Buffer.from(authTagHex, "hex");

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);

  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final()
  ]);

  return decrypted.toString("utf8");
}

/*
SUCCESS CHECK
*/
function isSuccessResult(code) {
  return typeof code === "string" && code.startsWith("000.");
}

/*
HEALTH CHECK
*/
app.get("/", (_req, res) => {
  res.status(200).send("NomuPay webhook service running");
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

  // acknowledge immediately
  res.status(200).send("OK");

  try {

    if (!process.env.WEBHOOK_SECRET_HEX) {
      console.error("Missing WEBHOOK_SECRET_HEX");
      return;
    }

    const ivHex = headers["x-initialization-vector"];
    const authTagHex = headers["x-authentication-tag"];

    if (!ivHex || !authTagHex) {
      console.error("Missing encryption headers");
      return;
    }

    const decrypted = decryptHexPayload(
      rawBody.trim(),
      process.env.WEBHOOK_SECRET_HEX,
      ivHex,
      authTagHex
    );

    const webhook = JSON.parse(decrypted);

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
      console.log("Duplicate webhook ignored:", dedupeKey);
      return;
    }

    seen.add(dedupeKey);

    /*
    EMAIL ALERT ON FAILURE
    */
    if (!isSuccessResult(resultCode) && process.env.ALERT_EMAIL_TO) {

      console.log("Payment failure detected → sending email");

      await transporter.sendMail({
        from: process.env.ALERT_EMAIL_FROM,
        to: process.env.ALERT_EMAIL_TO,
        subject: `NomuPay payment failed - ${paymentId}`,
        text: [
          "A NomuPay payment failed.",
          "",
          `Payment ID: ${paymentId}`,
          `Amount: ${amount} ${currency}`,
          `Result Code: ${resultCode}`,
          `Result Description: ${resultDescription}`,
          "",
          "Webhook Payload:",
          JSON.stringify(webhook, null, 2)
        ].join("\n")
      });

      console.log("Email sent successfully");

    } else {
      console.log("Payment successful, no email sent");
    }

  } catch (error) {

    console.error("Webhook processing error:", error.message);
    console.error("Raw body:", rawBody);

  }

});

/*
START SERVER
*/
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});