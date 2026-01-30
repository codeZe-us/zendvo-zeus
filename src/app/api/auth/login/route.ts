import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import { comparePassword } from "@/lib/auth";
import { validateEmail, sanitizeInput } from "@/lib/validation";
import { isRateLimited } from "@/lib/rate-limiter";
import { generateAccessToken, generateRefreshToken } from "@/lib/tokens";

const MAX_LOGIN_ATTEMPTS = 5;
const LOCK_DURATION_MINUTES = 15;

export async function POST(request: NextRequest) {
  try {
    // 1. IP-based Rate Limiting (5 attempts per 15 mins)
    const ip =
      request.headers.get("x-forwarded-for")?.split(",")[0] || "127.0.0.1";
    if (isRateLimited(ip, 5, 15 * 60 * 1000)) {
      return NextResponse.json(
        {
          success: false,
          error: "Too many login attempts. Please try again later.",
        },
        { status: 429 },
      );
    }

    // 2. Parse and Validate Body
    const body = await request.json();
    const { email, password } = body;

    if (!email || !password) {
      return NextResponse.json(
        { success: false, error: "Email and password are required" },
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

    // 3. Retrieve User
    const user = (await prisma.user.findUnique({
      where: { email: sanitizedEmail },
    })) as any;

    if (!user) {
      // Use timing-safe delay or generic error to prevent enumeration
      return NextResponse.json(
        { success: false, error: "Invalid credentials" },
        { status: 401 },
      );
    }

    // 4. Check Account Lockout
    if (user.lockUntil && user.lockUntil > new Date()) {
      const remainingMinutes = Math.ceil(
        (user.lockUntil.getTime() - Date.now()) / (60 * 1000),
      );
      return NextResponse.json(
        {
          success: false,
          error: `Account is temporarily locked. Try again in ${remainingMinutes} minutes.`,
        },
        { status: 423 },
      );
    }

    // 5. Check User Status
    if (user.status === "unverified") {
      return NextResponse.json(
        {
          success: false,
          error: "Account is unverified. Please verify your email.",
        },
        { status: 403 },
      );
    }

    if (user.status === "suspended") {
      return NextResponse.json(
        { success: false, error: "Account is suspended." },
        { status: 403 },
      );
    }

    // 6. Verify Password
    const isPasswordValid = await comparePassword(password, user.passwordHash);

    if (!isPasswordValid) {
      // Increment login attempts
      const newAttempts = user.loginAttempts + 1;
      const data: any = { loginAttempts: newAttempts };

      if (newAttempts >= MAX_LOGIN_ATTEMPTS) {
        data.lockUntil = new Date(
          Date.now() + LOCK_DURATION_MINUTES * 60 * 1000,
        );
        data.loginAttempts = 0; // Reset after locking
      }

      await prisma.user.update({
        where: { id: user.id },
        data,
      });

      return NextResponse.json(
        {
          success: false,
          error: "Invalid credentials",
          details:
            newAttempts >= MAX_LOGIN_ATTEMPTS
              ? "Account locked due to too many failed attempts."
              : undefined,
        },
        { status: 401 },
      );
    }

    // 7. Successful Login
    // Generate Tokens
    const payload = { userId: user.id, email: user.email, role: user.role };
    const accessToken = generateAccessToken(payload);
    const refreshToken = generateRefreshToken(payload);

    // Update User Activity and Store Refresh Token in Transaction
    await prisma.$transaction([
      prisma.user.update({
        where: { id: user.id },
        data: {
          lastLogin: new Date(),
          loginAttempts: 0,
          lockUntil: null,
        } as any,
      }),
      prisma.refreshToken.create({
        data: {
          userId: user.id,
          token: refreshToken,
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
          deviceInfo: request.headers.get("user-agent"),
        } as any,
      }),
    ]);

    console.log(
      `[AUTH_AUDIT] Successful login for user: ${user.id} from IP: ${ip}`,
    );

    // 8. Return Response
    return NextResponse.json(
      {
        success: true,
        data: {
          accessToken,
          refreshToken,
          user: {
            id: user.id,
            email: user.email,
            name: user.name,
            role: user.role,
            status: user.status,
            lastLogin: new Date(),
          },
        },
      },
      { status: 200 },
    );
  } catch (error) {
    console.error("[LOGIN_ERROR]", error);
    return NextResponse.json(
      { success: false, error: "Internal server error" },
      { status: 500 },
    );
  }
}
