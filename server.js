import express from "express";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";

const app = express();
const port = process.env.PORT || 3000;

// Use the raw request body exactly as received.
// NomuPay signature verification depends on the original payload bytes.
app.use(
  express.raw({
    type: "application/json"
  })
);

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: String(process.env.SMTP_SECURE).toLowerCase() === "true",
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// First version dedupe store.
// Good enough for testing, but not persistent across restarts.
const seenNotifications = new Set();

function verifyDetachedJws(detachedToken, rawBodyBuffer, sharedKey) {
  const body = rawBodyBuffer.toString("utf8");
  const parts = detachedToken.split("..");

  if (parts.length !== 2) {
    throw new Error("Invalid detached JWS format");
  }

  const payload = Buffer.from(body, "utf8").toString("base64url");
  const reconstructedJws = `${parts[0]}.${payload}.${parts[1]}`;

  return jwt.verify(reconstructedJws, sharedKey, {
    algorithms: ["HS256"]
  });
}

function extractInfo(payload) {
  return {
    notificationId:
      payload?.notificationId ||
      payload?.id ||
      payload?.eventId ||
      payload?.reference ||
      null,
    status: payload?.status || payload?.payment?.status || null,
    paymentId: payload?.paymentId || payload?.payment?.id || null,
    merchantReference:
      payload?.merchantReference ||
      payload?.merchantPaymentReference ||
      payload?.payment?.merchantReference ||
      null,
    amount:
      payload?.amount?.value ||
      payload?.payment?.amount?.value ||
      payload?.amount ||
      null,
    currency:
      payload?.amount?.currency ||
      payload?.payment?.amount?.currency ||
      payload?.currency ||
      null,
    reasonCode:
      payload?.reason?.code || payload?.payment?.reason?.code || null,
    reasonDescription:
      payload?.reason?.description ||
      payload?.payment?.reason?.description ||
      null
  };
}

app.get("/", (_req, res) => {
  res.status(200).send("NomuPay webhook listener is running");
});

app.post("/webhooks/nomupay", async (req, res) => {
  try {
    const rawBody = req.body;
    const signatureHeader = req.headers["x-signature"];
    const sharedKey = process.env.WEBHOOK_SHARED_KEY;

    if (!sharedKey) {
      return res.status(500).send("Missing WEBHOOK_SHARED_KEY");
    }

    if (!signatureHeader) {
      return res.status(401).send("Missing X-Signature");
    }

    const detachedToken = Array.isArray(signatureHeader)
      ? signatureHeader[0]
      : signatureHeader;

    verifyDetachedJws(detachedToken, rawBody, sharedKey);

    const payload = JSON.parse(rawBody.toString("utf8"));
    const info = extractInfo(payload);

    const dedupeKey =
      info.notificationId ||
      `${info.paymentId || "unknown"}:${info.status || "unknown"}:${info.reasonCode || "none"}`;

    if (seenNotifications.has(dedupeKey)) {
      return res.status(200).send("Duplicate ignored");
    }

    seenNotifications.add(dedupeKey);

    if (info.status === "failed") {
      await transporter.sendMail({
        from: process.env.ALERT_EMAIL_FROM,
        to: process.env.ALERT_EMAIL_TO,
        subject: `NomuPay payment failed${info.paymentId ? ` - ${info.paymentId}` : ""}`,
        text: [
          "A NomuPay transaction failed.",
          "",
          `Status: ${info.status || ""}`,
          `Payment ID: ${info.paymentId || ""}`,
          `Merchant Reference: ${info.merchantReference || ""}`,
          `Amount: ${info.amount || ""} ${info.currency || ""}`.trim(),
          `Reason Code: ${info.reasonCode || ""}`,
          `Reason Description: ${info.reasonDescription || ""}`,
          "",
          "Raw payload:",
          JSON.stringify(payload, null, 2)
        ].join("\n")
      });
    }

    res.status(200).send("OK");
  } catch (error) {
    console.error("Webhook error:", error.message);
    res.status(400).send("Invalid webhook");
  }
});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});