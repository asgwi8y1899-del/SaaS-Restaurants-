require('dotenv').config();
const { Resend } = require('resend');
const resend = new Resend(process.env.RESEND_API_KEY);

async function sendEmail(toEmail, subject, htmlContent) {
  try {
    await resend.emails.send({
      from: 'DineOS <onboarding@resend.dev>',
      to: toEmail,
      subject: subject,
      html: htmlContent
    });
    console.log('[RESEND] sent to ' + toEmail);
    return { success: true };
  } catch (error) {
    console.error('[RESEND FAILED]', error);
    return { success: false, error: error.message };
  }
}

async function sendOTPByEmail(toEmail, otpCode) {
  return sendEmail(toEmail, 'DineOS - رمز الدخول',
    '<h2>رمز التحقق: <strong>' + otpCode + '</strong></h2><p>صالح لمدة 10 دقائق.</p>');
}

module.exports = { sendOTPByEmail, sendEmail };
