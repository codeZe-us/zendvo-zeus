import { NextRequest } from "next/server";
import { POST } from "@/app/api/auth/forgot-password/route";
import { prisma } from "@/lib/prisma";
import { isRateLimited } from "@/lib/rate-limiter";
import { sendForgotPasswordEmail } from "@/server/services/emailService";

// Mock dependencies
jest.mock("@/lib/prisma", () => ({
  prisma: {
    user: {
      findUnique: jest.fn(),
    },
    passwordReset: {
      create: jest.fn(),
    },
  },
}));

jest.mock("@/lib/rate-limiter", () => ({
  isRateLimited: jest.fn(),
}));

jest.mock("@/server/services/emailService", () => ({
  sendForgotPasswordEmail: jest.fn().mockResolvedValue({ success: true }),
}));

describe("POST /api/auth/forgot-password", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (isRateLimited as jest.Mock).mockReturnValue(false);
  });

  it("should process forgot password successfully for existing user", async () => {
    (prisma.user.findUnique as jest.Mock).mockResolvedValue({
      id: "user-123",
      email: "test@example.com",
      name: "Test User",
    });
    (prisma.passwordReset.create as jest.Mock).mockResolvedValue({});

    const request = new NextRequest(
      "http://localhost/api/auth/forgot-password",
      {
        method: "POST",
        body: JSON.stringify({ email: "test@example.com" }),
      },
    );

    const response = await POST(request);
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data.success).toBe(true);
    expect(prisma.passwordReset.create).toHaveBeenCalled();
    expect(sendForgotPasswordEmail).toHaveBeenCalled();
  });

  it("should return success even if user does not exist (security)", async () => {
    (prisma.user.findUnique as jest.Mock).mockResolvedValue(null);

    const request = new NextRequest(
      "http://localhost/api/auth/forgot-password",
      {
        method: "POST",
        body: JSON.stringify({ email: "missing@example.com" }),
      },
    );

    const response = await POST(request);
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data.success).toBe(true);
    expect(prisma.passwordReset.create).not.toHaveBeenCalled();
    expect(sendForgotPasswordEmail).not.toHaveBeenCalled();
  });

  it("should return 400 for invalid email format", async () => {
    const request = new NextRequest(
      "http://localhost/api/auth/forgot-password",
      {
        method: "POST",
        body: JSON.stringify({ email: "invalid-email" }),
      },
    );

    const response = await POST(request);
    const data = await response.json();

    expect(response.status).toBe(400);
    expect(data.error).toBe("Invalid email format");
  });

  it("should return 429 if rate limited", async () => {
    (isRateLimited as jest.Mock).mockReturnValue(true);

    const request = new NextRequest(
      "http://localhost/api/auth/forgot-password",
      {
        method: "POST",
        body: JSON.stringify({ email: "test@example.com" }),
      },
    );

    const response = await POST(request);
    const data = await response.json();

    expect(response.status).toBe(429);
    expect(data.error).toBe("Too many requests. Please try again later.");
  });
});
