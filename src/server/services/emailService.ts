import nodemailer from "nodemailer";

const EMAIL_CONFIG = {
  host: process.env.SMTP_HOST || "smtp.gmail.com",
  port: parseInt(process.env.SMTP_PORT || "587"),
  secure: false,
  auth: {
    user: process.env.SMTP_USER || "your-email@example.com",
    pass: process.env.SMTP_PASS || "your-password",
  },
};

const transporter = nodemailer.createTransport(EMAIL_CONFIG);

export async function sendVerificationEmail(
  email: string,
  otp: string,
  userName?: string,
) {
  const mailOptions = {
    from: `"Zendvo" <${EMAIL_CONFIG.auth.user}>`,
    to: email,
    subject: "Verify Your Email - Zendvo",
    html: generateEmailTemplate(otp, userName),
    text: `Your Zendvo verification code is: ${otp}\n\nThis code will expire in 10 minutes.\n\nIf you didn't request this code, please ignore this email.`,
  };

  try {
    if (process.env.NODE_ENV === "development") {
      console.log("=".repeat(50));
      console.log("📧 VERIFICATION EMAIL (Development Mode)");
      console.log("=".repeat(50));
      console.log(`To: ${email}`);
      console.log(`OTP Code: ${otp}`);
      console.log(`Expires: 10 minutes`);
      console.log("=".repeat(50));
      return {
        success: true,
        messageId: "dev-mode",
        message: "OTP logged to console (development mode)",
      };
    }

    const info = await transporter.sendMail(mailOptions);
    return {
      success: true,
      messageId: info.messageId,
      message: "Verification email sent successfully",
    };
  } catch (error) {
    console.error("Error sending verification email:", error);
    return {
      success: false,
      error: error instanceof Error ? error.message : "Unknown error",
      message: "Failed to send verification email",
    };
  }
}

export async function sendForgotPasswordEmail(
  email: string,
  token: string,
  userName?: string,
) {
  const resetLink = `${process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000"}/auth/reset-password?token=${token}`;
  const mailOptions = {
    from: `"Zendvo" <${EMAIL_CONFIG.auth.user}>`,
    to: email,
    subject: "Reset Your Password - Zendvo",
    html: generateForgotPasswordTemplate(resetLink, userName),
    text: `Reset your Zendvo password by clicking this link: ${resetLink}\n\nThis link will expire in 1 hour.\n\nIf you didn't request a password reset, please ignore this email.`,
  };

  try {
    if (process.env.NODE_ENV === "development") {
      console.log("=".repeat(50));
      console.log("📧 FORGOT PASSWORD EMAIL (Development Mode)");
      console.log("=".repeat(50));
      console.log(`To: ${email}`);
      console.log(`Reset Link: ${resetLink}`);
      console.log(`Expires: 1 hour`);
      console.log("=".repeat(50));
      return {
        success: true,
        messageId: "dev-mode",
        message: "Reset link logged to console (development mode)",
      };
    }

    const info = await transporter.sendMail(mailOptions);
    return {
      success: true,
      messageId: info.messageId,
      message: "Forgot password email sent successfully",
    };
  } catch (error) {
    console.error("Error sending forgot password email:", error);
    return {
      success: false,
      error: error instanceof Error ? error.message : "Unknown error",
      message: "Failed to send forgot password email",
    };
  }
}

export async function sendPasswordResetConfirmationEmail(
  email: string,
  userName?: string,
) {
  const mailOptions = {
    from: `"Zendvo" <${EMAIL_CONFIG.auth.user}>`,
    to: email,
    subject: "Password Changed - Zendvo",
    html: generatePasswordResetConfirmationTemplate(userName),
    text: `Your Zendvo password has been successfully changed.\n\nIf you did not perform this action, please contact support immediately.`,
  };

  try {
    if (process.env.NODE_ENV === "development") {
      console.log("=".repeat(50));
      console.log("📧 PASSWORD RESET CONFIRMATION (Development Mode)");
      console.log("=".repeat(50));
      console.log(`To: ${email}`);
      console.log("=".repeat(50));
      return {
        success: true,
        messageId: "dev-mode",
        message: "Reset confirmation logged to console (development mode)",
      };
    }

    const info = await transporter.sendMail(mailOptions);
    return {
      success: true,
      messageId: info.messageId,
      message: "Password reset confirmation email sent successfully",
    };
  } catch (error) {
    console.error("Error sending password reset confirmation email:", error);
    return {
      success: false,
      error: error instanceof Error ? error.message : "Unknown error",
      message: "Failed to send password reset confirmation email",
    };
  }
}

/**
 * Generate HTML email template with Zendvo branding
 */
function generateEmailTemplate(otp: string, userName?: string): string {
  return generateBaseTemplate({
    title: "Verify Your Email",
    userName,
    content: `
      <p style="margin: 0 0 20px; color: #4a5568; font-size: 16px; line-height: 1.6;">
        Thank you for signing up with Zendvo! To complete your registration, please verify your email address using the code below:
      </p>
      
      <!-- OTP Code Box -->
      <table width="100%" cellpadding="0" cellspacing="0" style="margin: 30px 0;">
        <tr>
          <td align="center" style="background-color: #f7fafc; border: 2px dashed #667eea; border-radius: 8px; padding: 30px;">
            <div style="font-size: 36px; font-weight: 700; color: #667eea; letter-spacing: 8px; font-family: 'Courier New', monospace;">
              ${otp}
            </div>
          </td>
        </tr>
      </table>
      
      <p style="margin: 20px 0; color: #4a5568; font-size: 14px; line-height: 1.6;">
        <strong>⏰ This code will expire in 10 minutes.</strong>
      </p>
    `,
  });
}

function generateForgotPasswordTemplate(
  resetLink: string,
  userName?: string,
): string {
  return generateBaseTemplate({
    title: "Reset Your Password",
    userName,
    content: `
      <p style="margin: 0 0 20px; color: #4a5568; font-size: 16px; line-height: 1.6;">
        We received a request to reset your password. Click the button below to choose a new one:
      </p>
      
      <!-- Reset Button -->
      <table width="100%" cellpadding="0" cellspacing="0" style="margin: 30px 0;">
        <tr>
          <td align="center">
            <a href="${resetLink}" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #ffffff; padding: 16px 32px; border-radius: 8px; text-decoration: none; font-weight: 600; font-size: 16px; display: inline-block; box-shadow: 0 4px 6px rgba(102, 126, 234, 0.25);">
              Reset Password
            </a>
          </td>
        </tr>
      </table>
      
      <p style="margin: 20px 0; color: #4a5568; font-size: 14px; line-height: 1.6;">
        <strong>⏰ This link will expire in 1 hour.</strong>
      </p>
      
      <p style="margin: 20px 0; color: #718096; font-size: 14px; line-height: 1.6;">
        If you're having trouble clicking the button, copy and paste this link into your browser:<br>
        <span style="word-break: break-all; color: #667eea;">${resetLink}</span>
      </p>
    `,
  });
}

function generatePasswordResetConfirmationTemplate(userName?: string): string {
  return generateBaseTemplate({
    title: "Password Changed",
    userName,
    content: `
      <p style="margin: 0 0 20px; color: #4a5568; font-size: 16px; line-height: 1.6;">
        This is a confirmation that your Zendvo password has been successfully changed.
      </p>
      
      <p style="margin: 20px 0; color: #4a5568; font-size: 16px; line-height: 1.6;">
        If you did not perform this action, please contact our security team immediately at support@zendvo.com.
      </p>

      <table width="100%" cellpadding="0" cellspacing="0" style="margin: 30px 0;">
        <tr>
          <td align="center">
            <a href="${process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000"}/auth/login" style="background-color: #f7fafc; border: 1px solid #e2e8f0; color: #4a5568; padding: 12px 24px; border-radius: 8px; text-decoration: none; font-weight: 500; font-size: 14px; display: inline-block;">
              Return to Login
            </a>
          </td>
        </tr>
      </table>
    `,
  });
}

function generateBaseTemplate({
  title,
  userName,
  content,
}: {
  title: string;
  userName?: string;
  content: string;
}): string {
  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title}</title>
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background-color: #f5f5f5;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f5f5f5; padding: 40px 20px;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
          <!-- Header -->
          <tr>
            <td style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 40px 20px; text-align: center;">
              <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: 700;">Zendvo</h1>
              <p style="margin: 10px 0 0; color: #ffffff; font-size: 16px; opacity: 0.9;">Gifting Made Magical</p>
            </td>
          </tr>
          
          <!-- Content -->
          <tr>
            <td style="padding: 40px 30px;">
              <h2 style="margin: 0 0 20px; color: #1a202c; font-size: 24px; font-weight: 600;">
                ${userName ? `Hi ${userName},` : "Hello!"}
              </h2>
              ${content}
              
              <p style="margin: 20px 0 0; color: #718096; font-size: 14px; line-height: 1.6;">
                If you didn't request this action, please ignore this email or contact our support team if you have concerns.
              </p>
            </td>
          </tr>
          
          <!-- Footer -->
          <tr>
            <td style="background-color: #f7fafc; padding: 30px; text-align: center; border-top: 1px solid #e2e8f0;">
              <p style="margin: 0 0 10px; color: #718096; font-size: 14px;">
                © ${new Date().getFullYear()} Zendvo. All rights reserved.
              </p>
              <p style="margin: 0; color: #a0aec0; font-size: 12px;">
                Transforming digital money transfers into memorable experiences
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
  `.trim();
}
