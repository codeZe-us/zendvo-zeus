import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { verifyAccessToken } from "@/lib/tokens";

// Define restricted paths that require authentication
const PROTECTED_ROUTES = [
  "/api/user",
  "/api/auth/logout",
  "/api/auth/reset-password", // Although token is checked in route, middleware can be a first layer
];

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Check if the current route is protected
  const isProtected = PROTECTED_ROUTES.some((route) =>
    pathname.startsWith(route),
  );

  if (!isProtected) {
    return NextResponse.next();
  }

  // 1. Get token from Authorization header
  const authHeader = request.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return NextResponse.json(
      {
        success: false,
        error: "Unauthorized: Missing or invalid token format",
      },
      { status: 401 },
    );
  }

  const token = authHeader.split(" ")[1];

  // 2. Verify Token
  const payload = verifyAccessToken(token);

  if (!payload) {
    return NextResponse.json(
      {
        success: false,
        error: "Unauthorized: Invalid or expired access token",
      },
      { status: 401 },
    );
  }

  // 3. Attach user info to headers so routes can access it
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-user-id", payload.userId);
  requestHeaders.set("x-user-email", payload.email);
  requestHeaders.set("x-user-role", payload.role);

  return NextResponse.next({
    request: {
      headers: requestHeaders,
    },
  });
}

// See "Matching Paths" below to learn more
export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - api/auth/login
     * - api/auth/register
     * - api/auth/forgot-password
     * - api/auth/refresh
     * - static files (_next/static, public, etc.)
     */
    "/api/:path*",
  ],
};
