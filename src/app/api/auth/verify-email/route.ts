import { NextResponse } from "next/server";
import { verifyOTP } from "@/server/services/otpService";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { userId, otp } = body;

    // Validate input
    if (!userId || !otp) {
      return NextResponse.json(
        { error: "userId and otp are required" },
        { status: 400 },
      );
    }

    // Validate OTP format (6-digit numeric)
    if (!/^\d{6}$/.test(otp)) {
      return NextResponse.json(
        { error: "Invalid OTP format. Must be 6 digits." },
        { status: 400 },
      );
    }

    // Verify OTP
    const result = await verifyOTP(userId, otp);

    if (!result.success) {
      // Determine appropriate status code
      let statusCode = 400;
      if (result.message?.includes("expired")) {
        statusCode = 400; // Bad Request - expired
      } else if (
        result.locked ||
        result.message?.includes("Maximum attempts")
      ) {
        statusCode = 429; // Too Many Requests - locked out
      }

      return NextResponse.json(
        {
          success: false,
          error: result.message,
          remainingAttempts: result.remainingAttempts,
        },
        { status: statusCode },
      );
    }

    return NextResponse.json({
      success: true,
      message: result.message,
    });
  } catch (error) {
    console.error("Error in verify-email:", error);
    return NextResponse.json(
      {
        error: "Internal server error",
        message: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500 },
    );
  }
}
