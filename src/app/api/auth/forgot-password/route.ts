import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { validateEmail, sanitizeInput } from "@/lib/validation";
import { isRateLimited } from "@/lib/rate-limiter";
import { sendForgotPasswordEmail } from "@/server/services/emailService";
// Use native crypto.randomUUID()

export async function POST(request: NextRequest) {
  try {
    // 1. Rate Limiting (max 3 forgot password requests per hour per IP)
    const ip =
      request.headers.get("x-forwarded-for")?.split(",")[0] || "127.0.0.1";
    if (isRateLimited(ip, 3)) {
      return NextResponse.json(
        {
          success: false,
          error: "Too many requests. Please try again later.",
        },
        { status: 429 },
      );
    }

    // 2. Parse and Validate Request Body
    const body = await request.json();
    const { email } = body;

    if (!email) {
      return NextResponse.json(
        { success: false, error: "Email is required" },
        { status: 400 },
      );
    }

    const sanitizedEmail = sanitizeInput(email);

    if (!validateEmail(sanitizedEmail)) {
      return NextResponse.json(
        { success: false, error: "Invalid email format" },
        { status: 400 },
      );
    }

    // 3. Check if user exists (Internally)
    const user = await prisma.user.findUnique({
      where: { email: sanitizedEmail },
    });

    // 4. If user exists, process reset
    if (user) {
      // Generate UUID token
      const token = crypto.randomUUID();
      const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

      // Store in database
      await prisma.passwordReset.create({
        data: {
          userId: user.id,
          token,
          expiresAt,
          ipAddress: ip,
        },
      });

      // Send email (Async - don't block response)
      sendForgotPasswordEmail(user.email, token, user.name || undefined).catch(
        (err) => console.error("[FORGOT_PASSWORD_EMAIL_ERROR]", err),
      );

      console.log(
        `[AUTH_AUDIT] Password reset requested for user: ${user.id} from IP: ${ip}`,
      );
    } else {
      console.log(
        `[AUTH_AUDIT] Password reset requested for non-existent email: ${sanitizedEmail} from IP: ${ip}`,
      );
    }

    // 5. Always return success for security
    return NextResponse.json(
      {
        success: true,
        message:
          "If an account exists with that email, a password reset link has been sent.",
      },
      { status: 200 },
    );
  } catch (error) {
    console.error("[FORGOT_PASSWORD_ERROR]", error);
    return NextResponse.json(
      { success: false, error: "Internal server error" },
      { status: 500 },
    );
  }
}
