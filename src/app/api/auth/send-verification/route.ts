import { NextResponse } from "next/server";
import { generateOTP, storeOTP } from "@/server/services/otpService";
import { sendVerificationEmail } from "@/server/services/emailService";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { userId, email, name } = body;

    // Validate input
    if (!userId || !email) {
      return NextResponse.json(
        { error: "userId and email are required" },
        { status: 400 },
      );
    }

    // Check if user exists
    const user = await prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      return NextResponse.json({ error: "User not found" }, { status: 404 });
    }

    // Check if user is already verified
    if (user.status === "active") {
      return NextResponse.json(
        { message: "Email already verified" },
        { status: 200 },
      );
    }

    // Generate OTP
    const otp = generateOTP();

    // Store OTP in database
    await storeOTP(userId, otp);

    // Send verification email
    const emailResult = await sendVerificationEmail(email, otp, name);

    if (!emailResult.success) {
      console.error("Failed to send email:", emailResult.error);
      // Still return success since OTP is stored
      // In development, OTP is logged to console
    }

    return NextResponse.json({
      success: true,
      message: "Verification code sent successfully",
      expiresIn: "10 minutes",
    });
  } catch (error) {
    console.error("Error in send-verification:", error);
    return NextResponse.json(
      {
        error: "Internal server error",
        message: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500 },
    );
  }
}
