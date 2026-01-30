import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

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

    // Revoke/Delete the refresh token in the database
    // Using delete is cleaner for rotation/logout unless audit history of tokens is specifically needed
    try {
      await prisma.refreshToken.delete({
        where: { token: refreshToken },
      });
    } catch (e) {
      // If token not found, it might already be gone (logout success either way)
    }

    return NextResponse.json(
      { success: true, message: "Logged out successfully" },
      { status: 200 },
    );
  } catch (error) {
    console.error("[LOGOUT_ERROR]", error);
    return NextResponse.json(
      { success: false, error: "Internal server error" },
      { status: 500 },
    );
  }
}
