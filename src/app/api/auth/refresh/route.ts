import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
import {
  verifyRefreshToken,
  generateAccessToken,
  generateRefreshToken,
} from "@/lib/tokens";

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { refreshToken } = body;

    if (!refreshToken) {
      return NextResponse.json(
        { success: false, error: "Refresh token is required" },
        { status: 400 },
      );
    }

    // 1. Verify Token Signature and Payload
    const payload = verifyRefreshToken(refreshToken);
    if (!payload) {
      return NextResponse.json(
        { success: false, error: "Invalid refresh token" },
        { status: 401 },
      );
    }

    // 2. Check Database for token
    const storedToken = (await prisma.refreshToken.findUnique({
      where: { token: refreshToken },
    })) as any;

    if (!storedToken) {
      return NextResponse.json(
        { success: false, error: "Token not found" },
        { status: 401 },
      );
    }

    // 3. Check for Revocation or Expiration
    if (storedToken.revokedAt) {
      return NextResponse.json(
        { success: false, error: "Token has been revoked" },
        { status: 401 },
      );
    }

    if (new Date() > storedToken.expiresAt) {
      return NextResponse.json(
        { success: false, error: "Token has expired" },
        { status: 401 },
      );
    }

    // 4. Token Rotation: Generate new tokens and replace the old one
    const newPayload = {
      userId: payload.userId,
      email: payload.email,
      role: payload.role,
    };
    const newAccessToken = generateAccessToken(newPayload);
    const newRefreshToken = generateRefreshToken(newPayload);

    await prisma.$transaction([
      // Delete old token (or mark as revoked, but rotation usually replaces)
      prisma.refreshToken.delete({
        where: { id: storedToken.id },
      }),
      // Create new token
      prisma.refreshToken.create({
        data: {
          userId: payload.userId,
          token: newRefreshToken,
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
          deviceInfo: storedToken.deviceInfo,
        } as any,
      }),
    ]);

    return NextResponse.json(
      {
        success: true,
        data: {
          accessToken: newAccessToken,
          refreshToken: newRefreshToken,
        },
      },
      { status: 200 },
    );
  } catch (error) {
    console.error("[REFRESH_TOKEN_ERROR]", error);
    return NextResponse.json(
      { success: false, error: "Internal server error" },
      { status: 500 },
    );
  }
}
