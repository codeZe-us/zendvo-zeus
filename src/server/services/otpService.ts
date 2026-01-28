import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";
import crypto from "crypto";

const prisma = new PrismaClient();

/**
 * Generate a cryptographically secure 6-digit OTP
 */
export function generateOTP(): string {
  const otp = crypto.randomInt(100000, 999999).toString();
  return otp;
}

/**
 * Store OTP in database with expiration (10 minutes)
 * @param userId - User ID to associate OTP with
 * @param otp - Plain text OTP to hash and store
 * @returns The created email verification record
 */
export async function storeOTP(userId: string, otp: string) {
  // Hash the OTP before storing
  const saltRounds = 10;
  const otpHash = await bcrypt.hash(otp, saltRounds);

  // Set expiration to 10 minutes from now
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

  // Invalidate any previous OTPs for this user
  await prisma.emailVerification.updateMany({
    where: {
      userId,
      isUsed: false,
    },
    data: {
      isUsed: true,
    },
  });

  // Create new OTP record
  const verification = await prisma.emailVerification.create({
    data: {
      userId,
      otpHash,
      expiresAt,
      attempts: 0,
      isUsed: false,
    },
  });

  return verification;
}

/**
 * Verify OTP against stored hash
 * @param userId - User ID to verify OTP for
 * @param otp - Plain text OTP submitted by user
 * @returns Object with success status and message
 */
export async function verifyOTP(userId: string, otp: string) {
  // Find the most recent unused OTP for this user
  const verification = await prisma.emailVerification.findFirst({
    where: {
      userId,
      isUsed: false,
    },
    orderBy: {
      createdAt: "desc",
    },
  });

  if (!verification) {
    return {
      success: false,
      message: "No verification code found. Please request a new one.",
    };
  }

  // Check if OTP has expired
  if (new Date() > verification.expiresAt) {
    return {
      success: false,
      message: "Verification code has expired. Please request a new one.",
    };
  }

  // Check if max attempts exceeded
  if (verification.attempts >= 5) {
    return {
      success: false,
      message: "Maximum attempts exceeded. Please request a new code.",
      locked: true,
    };
  }

  // Verify OTP using timing-safe comparison
  const isValid = await bcrypt.compare(otp, verification.otpHash);

  if (!isValid) {
    // Increment failed attempt counter
    await prisma.emailVerification.update({
      where: { id: verification.id },
      data: {
        attempts: verification.attempts + 1,
      },
    });

    const remainingAttempts = 5 - (verification.attempts + 1);
    return {
      success: false,
      message: `Invalid verification code. ${remainingAttempts} attempts remaining.`,
      remainingAttempts,
    };
  }

  // Mark OTP as used
  await prisma.emailVerification.update({
    where: { id: verification.id },
    data: {
      isUsed: true,
    },
  });

  // Update user status to active
  await prisma.user.update({
    where: { id: userId },
    data: {
      status: "active",
    },
  });

  return {
    success: true,
    message: "Email verified successfully!",
  };
}

/**
 * Clean up expired OTPs (should be run periodically)
 */
export async function cleanupExpiredOTPs() {
  const deleted = await prisma.emailVerification.deleteMany({
    where: {
      OR: [
        {
          expiresAt: {
            lt: new Date(),
          },
        },
        {
          createdAt: {
            lt: new Date(Date.now() - 24 * 60 * 60 * 1000), // Older than 24 hours
          },
        },
      ],
    },
  });

  console.log(`Cleaned up ${deleted.count} expired OTP records`);
  return deleted.count;
}
