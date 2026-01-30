import { NextRequest } from "next/server";
import { POST } from "@/app/api/auth/login/route";
import { prisma } from "@/lib/prisma";
import { comparePassword } from "@/lib/auth";
import { isRateLimited } from "@/lib/rate-limiter";

// Mock dependencies
jest.mock("@/lib/prisma", () => ({
  prisma: {
    user: {
      findUnique: jest.fn(),
      update: jest.fn(),
    },
    refreshToken: {
      create: jest.fn(),
    },
    $transaction: jest.fn((promises) => Promise.all(promises)),
  },
}));

jest.mock("@/lib/auth", () => ({
  comparePassword: jest.fn(),
}));

jest.mock("@/lib/rate-limiter", () => ({
  isRateLimited: jest.fn(() => false),
}));

jest.mock("@/lib/tokens", () => ({
  generateAccessToken: jest.fn(() => "mock-access-token"),
  generateRefreshToken: jest.fn(() => "mock-refresh-token"),
}));

describe("POST /api/auth/login", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("should login successfully with correct credentials", async () => {
    (prisma.user.findUnique as jest.Mock).mockResolvedValue({
      id: "user-123",
      email: "test@example.com",
      passwordHash: "hashed-pw",
      status: "active",
      role: "user",
      loginAttempts: 0,
      lockUntil: null,
    });
    (comparePassword as jest.Mock).mockResolvedValue(true);

    const request = new NextRequest("http://localhost/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        email: "test@example.com",
        password: "Password123!",
      }),
    });

    const response = await POST(request);
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data.success).toBe(true);
    expect(data.data.accessToken).toBe("mock-access-token");
  });

  it("should return 401 for incorrect password and increment attempts", async () => {
    (prisma.user.findUnique as jest.Mock).mockResolvedValue({
      id: "user-123",
      email: "test@example.com",
      passwordHash: "hashed-pw",
      status: "active",
      loginAttempts: 0,
    });
    (comparePassword as jest.Mock).mockResolvedValue(false);

    const request = new NextRequest("http://localhost/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        email: "test@example.com",
        password: "wrong-password",
      }),
    });

    const response = await POST(request);
    expect(response.status).toBe(401);
    expect(prisma.user.update).toHaveBeenCalled();
  });

  it("should lock account after 5 failed attempts", async () => {
    (prisma.user.findUnique as jest.Mock).mockResolvedValue({
      id: "user-123",
      email: "test@example.com",
      passwordHash: "hashed-pw",
      status: "active",
      loginAttempts: 4,
    });
    (comparePassword as jest.Mock).mockResolvedValue(false);

    const request = new NextRequest("http://localhost/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        email: "test@example.com",
        password: "wrong-password",
      }),
    });

    await POST(request);

    expect(prisma.user.update).toHaveBeenCalledWith({
      where: { id: "user-123" },
      data: expect.objectContaining({
        lockUntil: expect.any(Date),
      }),
    });
  });

  it("should return 423 if account is locked", async () => {
    const lockUntil = new Date(Date.now() + 10 * 60 * 1000);
    (prisma.user.findUnique as jest.Mock).mockResolvedValue({
      id: "user-123",
      email: "test@example.com",
      lockUntil,
    });

    const request = new NextRequest("http://localhost/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        email: "test@example.com",
        password: "Password123!",
      }),
    });

    const response = await POST(request);
    expect(response.status).toBe(423);
  });

  it("should return 403 if account is unverified", async () => {
    (prisma.user.findUnique as jest.Mock).mockResolvedValue({
      id: "user-123",
      email: "test@example.com",
      status: "unverified",
    });

    const request = new NextRequest("http://localhost/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        email: "test@example.com",
        password: "Password123!",
      }),
    });

    const response = await POST(request);
    expect(response.status).toBe(403);
    const data = await response.json();
    expect(data.error).toContain("verify your email");
  });
});
