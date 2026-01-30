import { prisma } from "@/lib/prisma";

/**
 * Deletes password reset tokens that are older than 24 hours.
 * This can be run as a cron job or manual script.
 */
export async function cleanupExpiredTokens() {
  try {
    const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

    const result = await prisma.passwordReset.deleteMany({
      where: {
        OR: [
          { expiresAt: { lt: new Date() } }, // Already expired
          { createdAt: { lt: twentyFourHoursAgo } }, // Older than 24 hours
          { usedAt: { not: null } }, // Already used
        ],
      },
    });

    console.log(
      `[CLEANUP_JOB] Deleted ${result.count} expired/used password reset tokens.`,
    );
    return result.count;
  } catch (error) {
    console.error("[CLEANUP_JOB_ERROR]", error);
    throw error;
  }
}

// If running directly via CLI
if (require.main === module) {
  cleanupExpiredTokens()
    .then(() => process.exit(0))
    .catch(() => process.exit(1));
}
