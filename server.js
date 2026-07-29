import express from "express";
import crypto from "crypto";
import nodemailer from "nodemailer";
import axios from "axios";

const app = express();
const port = process.env.PORT || 3000;
const erpPaymentWebhookUrl =
  process.env.ERP_PAYMENT_WEBHOOK_URL ||
  process.env.PAYMENT_SUCCESS_WEBHOOK_URL ||
  "https://sancqfnrbodhlzsqqevb.supabase.co/functions/v1/stg-on-payment-success";

console.log("Starting NomuPay webhook listener");

app.use(express.text({ type: "*/*", limit: "5mb" }));

/*
EMAIL SETUP (RESEND)
*/
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,           // smtp.resend.com
  port: Number(process.env.SMTP_PORT || 465),

  // Resend uses SSL (port 465)
  secure: true,

  auth: {
    user: process.env.SMTP_USER,         // "resend"
    pass: process.env.SMTP_PASS          // API key
  }
});

/*
VERIFY CONNECTION
*/
transporter.verify()
  .then(() => console.log("Resend SMTP connected successfully"))
  .catch(err => console.error("SMTP error:", err));

/*
DEDUPLICATION
*/
const seen = new Set();

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
PAYMENT DATA EXTRACTION
*/
function extractPaymentDetails(payment) {

  const customerName = [
    payment.customer?.givenName,
    payment.customer?.surname
  ].filter(Boolean).join(" ");

  return {
    timestamp: payment.timestamp || "",
    clientName: payment.card?.holder || customerName || "Unknown",
    reference: payment.merchantTransactionId || "N/A",
    phone: payment.customer?.phone || payment.customer?.mobile || "N/A",
    email: payment.customer?.email || "N/A",
    amount: payment.amount || payment.presentationAmount || "",
    currency: payment.currency || payment.presentationCurrency || "",
    resultCode: payment.result?.code || "",
    resultDescription: payment.result?.description || "",
    paymentId: payment.id || "unknown",
    paymentBrand: payment.paymentBrand || "",
    paymentType: payment.paymentType || "",
    paymentMethod: payment.paymentMethod || "",
    shortId: payment.shortId || "",
    descriptor: payment.descriptor || "",
    ndc: payment.ndc || "",
    cardLast4Digits: payment.card?.last4Digits || ""
  };
}

/*
LOG FAILED PAYMENT TO EXCEL
*/
async function logFailedPayment(data) {

  try {
    const token = await getGraphToken();

    const url =
`https://graph.microsoft.com/v1.0/users/${process.env.EXCEL_USER}/drive/root:${process.env.EXCEL_FILE_PATH}:/workbook/tables/${process.env.EXCEL_TABLE_NAME}/rows/add`;

    const body = {
      values: [[
        data.timestamp,
        data.clientName,
        data.reference,
        data.phone,
        data.email,
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

    console.log("Excel row added successfully");

  } catch (err) {
    console.error("Excel logging failed:", err.response?.data || err.message);
  }
}

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
PAYMENT RESULT CLASSIFICATION
*/
function getPaymentResultStatus(code) {

  if (typeof code !== "string") {
    return "failure";
  }

  const successfulPaymentPatterns = [
    /^000\.000\./,
    /^000\.100\.1/,
    /^000\.[36]/,
    /^000\.400\.[1][12]0/,
    /^000\.400\.0[^3]/,
    /^000\.400\.100/
  ];

  const pendingPaymentPatterns = [
    /^000\.200/,
    /^800\.400\.5/,
    /^100\.400\.500/
  ];

  if (successfulPaymentPatterns.some(pattern => pattern.test(code))) {
    return "success";
  }

  if (pendingPaymentPatterns.some(pattern => pattern.test(code))) {
    return "pending";
  }

  return "failure";
}

/*
SEND FINAL PAYMENT RESULT TO ERP WEBHOOK
*/
async function pushPaymentToErp(data, status) {

  try {
    const headers = {
      "Content-Type": "application/json"
    };

    const authToken =
      process.env.ERP_PAYMENT_WEBHOOK_AUTH_TOKEN ||
      process.env.PAYMENT_SUCCESS_WEBHOOK_AUTH_TOKEN;

    if (authToken) {
      headers.Authorization = `Bearer ${authToken}`;
    }

    const body = {
      event: status === "success" ? "payment_success" : "payment_failure",
      status,
      timestamp: data.timestamp,
      clientName: data.clientName,
      reference: data.reference,
      phone: data.phone,
      email: data.email,
      amount: data.amount,
      currency: data.currency,
      resultCode: data.resultCode,
      resultDescription: data.resultDescription,
      paymentId: data.paymentId,
      paymentBrand: data.paymentBrand,
      paymentType: data.paymentType,
      paymentMethod: data.paymentMethod,
      shortId: data.shortId,
      descriptor: data.descriptor,
      ndc: data.ndc,
      cardLast4Digits: data.cardLast4Digits
    };

    const erpRes = await axios.post(erpPaymentWebhookUrl, body, {
      headers,
      timeout: 15000
    });

    console.log(
      `${status === "success" ? "Successful" : "Failed"} payment pushed to ERP webhook:`,
      erpRes.status
    );

  } catch (err) {
    console.error(
      `ERP webhook push failed for ${status} payment:`,
      err.response?.data || err.message
    );
  }
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
    const paymentDetails = extractPaymentDetails(payment);

    const dedupeKey = `${paymentDetails.paymentId}:${paymentDetails.resultCode}`;

    if (seen.has(dedupeKey)) {
      console.log("Duplicate webhook ignored:", dedupeKey);
      return;
    }

    seen.add(dedupeKey);

    const paymentStatus = getPaymentResultStatus(paymentDetails.resultCode);

    if (paymentStatus === "success") {
      console.log("Successful payment detected -> pushing to ERP webhook");
      await pushPaymentToErp(paymentDetails, paymentStatus);
      return;
    }

    if (paymentStatus === "pending") {
      console.log("Payment pending, no failure alert or ERP push sent");
      return;
    }

    console.log("Failed payment detected -> pushing to ERP webhook");
    await pushPaymentToErp(paymentDetails, paymentStatus);

    /*
    EMAIL + EXCEL ON FAILURE
    */
    if (process.env.ALERT_EMAIL_TO) {

      console.log("Payment failure detected -> sending email");

      const emailBody = `
A client payment attempt has failed and requires follow-up.

CLIENT DETAILS
Client Name: ${paymentDetails.clientName}
Phone: ${paymentDetails.phone}
Email: ${paymentDetails.email}

Reference
${paymentDetails.reference}

PAYMENT DETAILS
Amount: ${paymentDetails.amount} ${paymentDetails.currency}
Payment ID: ${paymentDetails.paymentId}
Date: ${paymentDetails.timestamp}

FAILURE REASON
${paymentDetails.resultDescription}

ACTION REQUIRED
Please contact the client to retry the payment.

TRACKING SHEET
${process.env.EXCEL_SHEET_LINK}

NomuPay Webhook Notification System
`;

      await transporter.sendMail({
        from: process.env.ALERT_EMAIL_FROM,
        to: process.env.ALERT_EMAIL_TO,
        subject: "Payment Failed - Action Required",
        text: emailBody
      });

      console.log("Email sent successfully");

      // LOG TO EXCEL
      await logFailedPayment(paymentDetails);

    } else {
      console.log("Payment failure detected, but ALERT_EMAIL_TO is not configured");
    }

  } catch (error) {
    console.error("Webhook processing error:", error.message);
    console.error("Raw body:", rawBody);
  }

});

/*
FIX FOR RAILWAY
*/
app.listen(port, "0.0.0.0", () => {
  console.log(`Server listening on port ${port}`);
});
