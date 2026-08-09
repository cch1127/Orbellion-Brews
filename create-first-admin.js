/**
 * One-time script to create the FIRST admin account.
 *
 * Every account after this one is created from the app's "Manage People" tab
 * by an existing admin — but the very first admin has to come from somewhere,
 * and only server-side Admin SDK code (not the browser, not Firestore rules)
 * is trusted to create accounts. This script fills that one gap.
 *
 * Run it ONCE, locally, then you never need it again (unless you want to
 * create a second initial admin some other way).
 *
 * ---- Setup ----
 * 1. In the Firebase console: Project settings → Service accounts →
 *    "Generate new private key". Save the downloaded JSON file somewhere
 *    safe, e.g. ./service-account.json (do NOT commit it to git).
 * 2. npm install firebase-admin   (in this same folder, or reuse functions/node_modules)
 * 3. Run:
 *      GOOGLE_APPLICATION_CREDENTIALS=./service-account.json \
 *      node create-first-admin.js "adminuser" "Guild Admin" "a-strong-password"
 */

const admin = require("firebase-admin");

const [, , username, displayName, password] = process.argv;

if (!username || !displayName || !password) {
  console.error(
    'Usage: node create-first-admin.js "<username>" "<displayName>" "<password>"'
  );
  process.exit(1);
}
if (password.length < 6) {
  console.error("Password must be at least 6 characters.");
  process.exit(1);
}

admin.initializeApp({
  credential: admin.credential.applicationDefault(),
});

const LOGIN_DOMAIN = "orbellionbrews.local";
const email =
  username.trim().toLowerCase().replace(/[^a-z0-9._-]/g, "") +
  "@" +
  LOGIN_DOMAIN;

(async () => {
  try {
    const userRecord = await admin.auth().createUser({
      email,
      password,
      displayName,
    });

    await admin.auth().setCustomUserClaims(userRecord.uid, {
      role: "admin",
      displayName,
    });

    await admin.firestore().collection("users").doc(userRecord.uid).set({
      username: username.trim(),
      displayName,
      role: "admin",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      createdBy: "bootstrap-script",
    });

    console.log(`Created first admin: ${displayName} (Login ID: ${username})`);
    process.exit(0);
  } catch (err) {
    console.error("Failed to create admin:", err.message);
    process.exit(1);
  }
})();
