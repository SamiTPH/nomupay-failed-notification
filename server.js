import express from "express";
import nodemailer from "nodemailer";

const app = express();
const port = process.env.PORT || 3000;

// Accept JSON and plain text
app.use(express.json({ limit: "2mb" }));
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

app.get("/", (_req, res) => {
  res.status(200).send("NomuPay webhook listener is running");
});

app.post("/webhooks/nomupay", async (req, res) => {
  try {
    const body = typeof req.body === "string" ? req.body : JSON.stringify(req.body);

    console.log("=== NOMUPAY WEBHOOK RECEIVED ===");
    console.log("Headers:", JSON.stringify(req.headers, null, 2));
    console.log("Body:", body);

    // Always acknowledge first so NomuPay sees success
    res.status(200).send("OK");

    // Optional: if payload is already JSON and clearly indicates a failed payment,
    // send yourself an email. Safe to leave this in.
    try {
      const payload = typeof req.body === "string" ? JSON.parse(req.body) : req.body;

      const resultCode = payload?.payload?.result?.code || payload?.result?.code || "";
      const resultDescription =
        payload?.payload?.result?.description ||
        payload?.result?.description ||
        "";

      const paymentId = payload?.payload?.id || payload?.id || "";
      const amount = payload?.payload?.amount || payload?.amount || "";
      const currency = payload?.payload?.currency || payload?.currency || "";

      // OPPWA / Total Processing style success codes usually start with 000.
      const looksFailed = resultCode && !String(resultCode).startsWith("000.");

      if (looksFailed && process.env.ALERT_EMAIL_TO) {
        await transporter.sendMail({
          from: process.env.ALERT_EMAIL_FROM,
          to: process.env.ALERT_EMAIL_TO,
          subject: `NomuPay payment alert - ${paymentId || "unknown payment"}`,
          text: [
            "A NomuPay webhook was received that appears to be a failed or non-success payment.",
            "",
            `Payment ID: ${paymentId}`,
            `Amount: ${amount} ${currency}`.trim(),
            `Result Code: ${resultCode}`,
            `Result Description: ${resultDescription}`,
            "",
            "Payload:",
            JSON.stringify(payload, null, 2)
          ].join("\n")
        });
      }
    } catch (e) {
      console.log("Webhook body is not directly parseable JSON yet:", e.message);
    }
  } catch (error) {
    console.error("Webhook handling error:", error.message);

    // Still return 200 for endpoint validation/testing
    if (!res.headersSent) {
      res.status(200).send("OK");
    }
  }
});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});