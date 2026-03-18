import express from "express";
import crypto from "crypto";
import nodemailer from "nodemailer";
import axios from "axios";

const app = express();
const port = process.env.PORT || 3000;

console.log("Starting NomuPay webhook listener");

app.use(express.text({ type: "*/*", limit: "5mb" }));

/*
EMAIL PROVIDER SWITCH
*/
let transporter;

if (process.env.EMAIL_PROVIDER === "outlook") {

  console.log("Using Outlook SMTP");

  transporter = nodemailer.createTransport({
    host: process.env.OUTLOOK_HOST,
    port: Number(process.env.OUTLOOK_PORT),
    secure: process.env.OUTLOOK_SECURE === "true",
    auth: {
      user: process.env.OUTLOOK_USER,
      pass: process.env.OUTLOOK_PASS
    }
  });

} else {

  console.log("Using Resend SMTP");

  transporter = nodemailer.createTransport({
    host: process.env.RESEND_HOST,
    port: Number(process.env.RESEND_PORT),
    secure: process.env.RESEND_SECURE === "true",
    auth: {
      user: process.env.RESEND_USER,
      pass: process.env.RESEND_PASS
    }
  });

}

transporter.verify()
  .then(() => console.log("SMTP connected"))
  .catch(err => console.error("SMTP error:", err));

/*
DEDUPLICATION
*/
const seen = new Set();

/*
AES DECRYPTION
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
GET GRAPH TOKEN
*/
async function getGraphToken() {

  const url = `https://login.microsoftonline.com/${process.env.MS_TENANT_ID}/oauth2/v2.0/token`;

  const params = new URLSearchParams();

  params.append("client_id", process.env.MS_CLIENT_ID);
  params.append("client_secret", process.env.MS_CLIENT_SECRET);
  params.append("scope", "https://graph.microsoft.com/.default");
  params.append("grant_type", "client_credentials");

  const res = await axios.post(url, params);

  return res.data.access_token;
}

/*
LOG FAILED PAYMENT TO EXCEL
*/
async function logFailedPayment(data) {

  const token = await getGraphToken();

  const url =
`https://graph.microsoft.com/v1.0/users/sp_admin_tphgroup_me@tphgroup.me/drive/root:${process.env.EXCEL_FILE_PATH}:/workbook/tables/${process.env.EXCEL_TABLE_NAME}/rows/add`;

  const body = {
    values: [[
      data.timestamp,
      data.clientName,
      data.clientEmail,
      data.phone,
      data.reference,
      data.amount,
      data.currency,
      data.resultCode,
      data.resultDescription,
      data.paymentId
    ]]
  };

  await axios.post(url, body, {
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json"
    }
  });

  console.log("Excel row added");
}

/*
HEALTH CHECK
*/
app.get("/", (_req, res) => {
  res.status(200).send("NomuPay webhook service running");
});

/*
WEBHOOK
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

    const ivHex = headers["x-initialization-vector"];
    const authTagHex = headers["x-authentication-tag"];

    const decrypted = decryptHexPayload(
      rawBody.trim(),
      process.env.WEBHOOK_SECRET_HEX,
      ivHex,
      authTagHex
    );

    const webhook = JSON.parse(decrypted);

    console.log("=== DECRYPTED NOMUPAY WEBHOOK ===");
    console.log(JSON.stringify(webhook, null, 2));

    if (webhook?.type !== "PAYMENT" || !webhook?.payload) return;

    const payment = webhook.payload;

    const paymentId = payment.id || "unknown";
    const resultCode = payment.result?.code || "";
    const resultDescription = payment.result?.description || "";
    const amount = payment.amount || "";
    const currency = payment.currency || "";

    const merchantReference = payment.merchantTransactionId || "N/A";

    const clientName = payment.card?.holder || "Unknown";
    const clientPhone = payment.customer?.phone || "N/A";
    const clientEmail = payment.customer?.email || "N/A";

    const timestamp = payment.timestamp || "";

    const dedupeKey = `${paymentId}:${resultCode}`;

    if (seen.has(dedupeKey)) {
      console.log("Duplicate webhook ignored:", dedupeKey);
      return;
    }

    seen.add(dedupeKey);

    if (!isSuccessResult(resultCode)) {

      console.log("Payment failure detected → sending email");

      const emailBody = `
A client payment attempt has failed and requires follow-up.

CLIENT DETAILS
Client Name: ${clientName}
Phone: ${clientPhone}
Email: ${clientEmail}

Reference
${merchantReference}

PAYMENT
Amount: ${amount} ${currency}
Payment ID: ${paymentId}
Date: ${timestamp}

FAILURE
${resultDescription}
`;

      await transporter.sendMail({
        from: process.env.ALERT_EMAIL_FROM,
        to: process.env.ALERT_EMAIL_TO,
        subject: "⚠️ Payment Failed – Client Follow-Up Required",
        text: emailBody
      });

      console.log("Email sent");

      await logFailedPayment({
        timestamp,
        clientName,
        clientEmail,
        phone: clientPhone,
        reference: merchantReference,
        amount,
        currency,
        resultCode,
        resultDescription,
        paymentId
      });

    } else {

      console.log("Payment successful");

    }

  } catch (error) {

    console.error("Webhook processing error:", error.message);

  }

});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});