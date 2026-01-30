-- AlterTable
ALTER TABLE "RefreshToken" ADD COLUMN "deviceInfo" TEXT;
ALTER TABLE "RefreshToken" ADD COLUMN "revokedAt" DATETIME;

-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_User" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "email" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "name" TEXT,
    "role" TEXT NOT NULL DEFAULT 'user',
    "status" TEXT NOT NULL DEFAULT 'unverified',
    "loginAttempts" INTEGER NOT NULL DEFAULT 0,
    "lockUntil" DATETIME,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    "lastLogin" DATETIME
);
INSERT INTO "new_User" ("createdAt", "email", "id", "lastLogin", "name", "passwordHash", "status", "updatedAt") SELECT "createdAt", "email", "id", "lastLogin", "name", "passwordHash", "status", "updatedAt" FROM "User";
DROP TABLE "User";
ALTER TABLE "new_User" RENAME TO "User";
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;
