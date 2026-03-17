import express from "express";
import crypto from "crypto";
import nodemailer from "nodemailer";
import axios from "axios";

const app = express();
const port = process.env.PORT || 3000;

console.log("Starting NomuPay webhook listener");

app.use(express.text({ type: "*/*", limit: "5mb" }));

/*
EMAIL SETUP (RESEND)
*/
const transporter = nodemailer.createTransport({
  host: "smtp.resend.com",
  port: 465,
  secure: true,
  auth: {
    user: "resend",
    pass: process.env.SMTP_PASS
  }
});

transporter.verify()
  .then(() => console.log("Resend SMTP connected"))
  .catch(err => console.error("SMTP error:", err));

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
GET MICROSOFT GRAPH TOKEN
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

    const merchantReference = payment.merchantTransactionId || "N/A";

    const clientName = payment.card?.holder || "Unknown";
    const clientPhone = payment.customer?.phone || "N/A";
    const clientEmail = payment.customer?.email || "N/A";

    const cardType = `${payment.paymentBrand || ""} ${payment.card?.type || ""}`.trim();
    const last4 = payment.card?.last4Digits || "N/A";
    const bank = payment.card?.issuer?.bank || "Unknown";

    const timestamp = payment.timestamp || "";

    const dedupeKey = `${paymentId}:${resultCode}`;

    if (seen.has(dedupeKey)) {
      console.log("Duplicate webhook ignored:", dedupeKey);
      return;
    }

    seen.add(dedupeKey);

    /*
    EMAIL + EXCEL LOG ON FAILURE
    */
    if (!isSuccessResult(resultCode) && process.env.ALERT_EMAIL_TO) {

      console.log("Payment failure detected → sending email");

      const emailBody = `
A client payment attempt has failed and requires follow-up.

CLIENT DETAILS
Client Name: ${clientName}
Phone: ${clientPhone}
Email: ${clientEmail}

Internal Reference
${merchantReference}

PAYMENT DETAILS
Amount: ${amount} ${currency}
Payment ID: ${paymentId}
Date: ${timestamp}

CARD INFORMATION
Card Type: ${cardType}
Last 4 Digits: ${last4}
Bank: ${bank}

FAILURE REASON
${resultDescription}

ACTION REQUIRED
Please contact the client to retry the payment or arrange an alternative payment method.

NomuPay Webhook Notification System
`;

      await transporter.sendMail({
        from: process.env.ALERT_EMAIL_FROM,
        to: process.env.ALERT_EMAIL_TO,
        subject: `⚠️ Payment Failed – Client Follow-Up Required`,
        text: emailBody
      });

      console.log("Email sent successfully");

      /*
      LOG TO EXCEL
      */
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

      console.log("Payment successful, no email sent");

    }

  } catch (error) {

    console.error("Webhook processing error:", error.message);
    console.error("Raw body:", rawBody);

  }

});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});