// mailer.js
const sgMail = require('@sendgrid/mail');

if (!process.env.SENDGRID_API_KEY || !process.env.SENDGRID_FROM_EMAIL) {
  console.error("❌ Missing SendGrid API Key or From Email");
  process.exit(1);
}

// Set API key
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

/**
 * Send OTP email
 * @param {string} to - Recipient email
 * @param {string} otp - OTP code
 */
async function sendOTP(to, otp) {
  try {
    const msg = {
      to,
      from: process.env.SENDGRID_FROM_EMAIL,
      subject: 'Your OTP Code',
      text: `Your OTP is: ${otp}. It expires in 5 minutes.`,
    };
    await sgMail.send(msg);
    console.log(`✅ OTP sent to ${to}`);
  } catch (err) {
    console.error(`❌ Failed to send OTP to ${to}:`, err.message);
    throw err;
  }
}

module.exports = { sendOTP };