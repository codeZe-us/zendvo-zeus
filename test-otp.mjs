/**
 * Test script for OTP verification flow
 * Run with: node --loader ts-node/esm test-otp.mjs
 * Or simply: node test-otp.mjs (if using .mjs extension)
 */

const BASE_URL = "http://localhost:3000";

// Test user data
const testUser = {
  userId: "test-user-123",
  email: "test@example.com",
  name: "Test User",
};

async function testOTPFlow() {
  console.log("🧪 Starting OTP Flow Test\n");
  console.log("=".repeat(60));

  try {
    // Step 1: Send verification code
    console.log("\n📤 Step 1: Sending verification code...");
    const sendResponse = await fetch(`${BASE_URL}/api/auth/send-verification`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(testUser),
    });

    const sendData = await sendResponse.json();
    console.log("Response:", sendData);

    if (!sendResponse.ok) {
      throw new Error(`Send verification failed: ${JSON.stringify(sendData)}`);
    }

    console.log("✅ Verification code sent successfully!");
    console.log("\n⚠️  Check your console for the OTP code (development mode)");
    console.log("=".repeat(60));

    // Prompt for OTP (in real scenario, get from console logs)
    console.log("\n📝 Enter the OTP from the console logs above:");
    console.log("   (In production, this would come from email)");

    // For automated testing, you would need to:
    // 1. Create a test user in the database first
    // 2. Extract OTP from logs or database
    // 3. Verify with that OTP

    console.log("\n💡 Manual Testing Steps:");
    console.log("   1. Look for the OTP in the terminal running 'npm run dev'");
    console.log("   2. Use the following curl command to verify:");
    console.log(`\n   curl -X POST ${BASE_URL}/api/auth/verify-email \\`);
    console.log(`     -H "Content-Type: application/json" \\`);
    console.log(
      `     -d '{"userId": "${testUser.userId}", "otp": "YOUR_OTP_HERE"}'`,
    );

    console.log("\n📋 Test Resend (Rate Limited to 3/hour):");
    console.log(`   curl -X POST ${BASE_URL}/api/auth/resend-verification \\`);
    console.log(`     -H "Content-Type: application/json" \\`);
    console.log(`     -d '${JSON.stringify(testUser)}'`);
  } catch (error) {
    console.error("\n❌ Test failed:", error.message);
    process.exit(1);
  }
}

// Run the test
testOTPFlow();
