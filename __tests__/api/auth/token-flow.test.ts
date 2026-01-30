import { NextRequest } from "next/server";
import { POST as refreshPOST } from "@/app/api/auth/refresh/route";
import { POST as logoutPOST } from "@/app/api/auth/logout/route";
import { prisma } from "@/lib/prisma";
import { verifyRefreshToken } from "@/lib/tokens";

// Mock dependencies
jest.mock("@/lib/prisma", () => ({
  prisma: {
    refreshToken: {
      findUnique: jest.fn(),
      delete: jest.fn(),
      create: jest.fn(),
    },
    $transaction: jest.fn((promises) => Promise.all(promises)),
  },
}));

jest.mock("@/lib/tokens", () => ({
  verifyRefreshToken: jest.fn(),
  generateAccessToken: jest.fn(() => "new-access-token"),
  generateRefreshToken: jest.fn(() => "new-refresh-token"),
}));

describe("Token Flow Tests", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe("POST /api/auth/refresh", () => {
    it("should refresh token successfully for valid token", async () => {
      (verifyRefreshToken as jest.Mock).mockReturnValue({
        userId: "1",
        email: "a@b.com",
        role: "user",
      });
      (prisma.refreshToken.findUnique as jest.Mock).mockResolvedValue({
        id: "tok-1",
        expiresAt: new Date(Date.now() + 10000),
        revokedAt: null,
      });

      const request = new NextRequest("http://localhost/api/auth/refresh", {
        method: "POST",
        body: JSON.stringify({ refreshToken: "valid-token" }),
      });

      const response = await refreshPOST(request);
      const data = await response.json();

      expect(response.status).toBe(200);
      expect(data.data.accessToken).toBe("new-access-token");
      expect(prisma.refreshToken.create).toHaveBeenCalled();
    });

    it("should return 401 for expired token", async () => {
      (verifyRefreshToken as jest.Mock).mockReturnValue({ userId: "1" });
      (prisma.refreshToken.findUnique as jest.Mock).mockResolvedValue({
        expiresAt: new Date(Date.now() - 10000),
      });

      const request = new NextRequest("http://localhost/api/auth/refresh", {
        method: "POST",
        body: JSON.stringify({ refreshToken: "expired-token" }),
      });

      const response = await refreshPOST(request);
      expect(response.status).toBe(401);
    });
  });

  describe("POST /api/auth/logout", () => {
    it("should logout successfully", async () => {
      const request = new NextRequest("http://localhost/api/auth/logout", {
        method: "POST",
        body: JSON.stringify({ refreshToken: "token-to-delete" }),
      });

      const response = await logoutPOST(request);
      expect(response.status).toBe(200);
      expect(prisma.refreshToken.delete).toHaveBeenCalled();
    });
  });
});
