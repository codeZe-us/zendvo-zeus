import { NextRequest } from "next/server";
import { POST } from "@/app/api/auth/reset-password/route";
import { prisma } from "@/lib/prisma";
import { hashPassword } from "@/lib/auth";
import { sendPasswordResetConfirmationEmail } from "@/server/services/emailService";

// Mock dependencies
jest.mock("@/lib/prisma", () => ({
  prisma: {
    passwordReset: {
      findUnique: jest.fn(),
      update: jest.fn(),
    },
    user: {
      update: jest.fn(),
    },
    refreshToken: {
      deleteMany: jest.fn(),
    },
    $transaction: jest.fn((promises) => Promise.all(promises)),
  },
}));

jest.mock("@/lib/auth", () => ({
  hashPassword: jest.fn().mockResolvedValue("hashed-password"),
}));

jest.mock("@/server/services/emailService", () => ({
  sendPasswordResetConfirmationEmail: jest
    .fn()
    .mockResolvedValue({ success: true }),
}));

describe("POST /api/auth/reset-password", () => {
  const validToken = "550e8400-e29b-41d4-a716-446655440000";
  const validPassword = "NewStrongP@ss123";

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("should reset password successfully with valid token and password", async () => {
    const mockRequest = {
      id: "reset-1",
      userId: "user-123",
      expiresAt: new Date(Date.now() + 10000),
      usedAt: null,
      user: { id: "user-123", email: "test@example.com", name: "Test User" },
    };

    (prisma.passwordReset.findUnique as jest.Mock).mockResolvedValue(
      mockRequest,
    );

    const request = new NextRequest(
      "http://localhost/api/auth/reset-password",
      {
        method: "POST",
        body: JSON.stringify({ token: validToken, password: validPassword }),
      },
    );

    const response = await POST(request);
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data.success).toBe(true);
    expect(prisma.$transaction).toHaveBeenCalled();
    expect(sendPasswordResetConfirmationEmail).toHaveBeenCalledWith(
      "test@example.com",
      "Test User",
    );
  });

  it("should return 400 for invalid token format", async () => {
    const request = new NextRequest(
      "http://localhost/api/auth/reset-password",
      {
        method: "POST",
        body: JSON.stringify({
          token: "invalid-token",
          password: validPassword,
        }),
      },
    );

    const response = await POST(request);
    const data = await response.json();

    expect(response.status).toBe(400);
    expect(data.error).toBe("Invalid token format");
  });

  it("should return 400 for weak password", async () => {
    const request = new NextRequest(
      "http://localhost/api/auth/reset-password",
      {
        method: "POST",
        body: JSON.stringify({ token: validToken, password: "weak" }),
      },
    );

    const response = await POST(request);
    const data = await response.json();

    expect(response.status).toBe(400);
    expect(data.error).toBe("Password too weak");
  });

  it("should return 400 if token is expired", async () => {
    const mockRequest = {
      id: "reset-1",
      userId: "user-123",
      expiresAt: new Date(Date.now() - 10000),
      usedAt: null,
    };

    (prisma.passwordReset.findUnique as jest.Mock).mockResolvedValue(
      mockRequest,
    );

    const request = new NextRequest(
      "http://localhost/api/auth/reset-password",
      {
        method: "POST",
        body: JSON.stringify({ token: validToken, password: validPassword }),
      },
    );

    const response = await POST(request);
    const data = await response.json();

    expect(response.status).toBe(400);
    expect(data.error).toBe("Token has expired");
  });

  it("should return 400 if token has already been used", async () => {
    const mockRequest = {
      id: "reset-1",
      userId: "user-123",
      expiresAt: new Date(Date.now() + 10000),
      usedAt: new Date(),
    };

    (prisma.passwordReset.findUnique as jest.Mock).mockResolvedValue(
      mockRequest,
    );

    const request = new NextRequest(
      "http://localhost/api/auth/reset-password",
      {
        method: "POST",
        body: JSON.stringify({ token: validToken, password: validPassword }),
      },
    );

    const response = await POST(request);
    const data = await response.json();

    expect(response.status).toBe(400);
    expect(data.error).toBe("Token has already been used");
  });
});
