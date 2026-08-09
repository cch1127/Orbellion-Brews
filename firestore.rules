const { onCall, HttpsError } = require("firebase-functions/v2/https");
const admin = require("firebase-admin");

admin.initializeApp();

const LOGIN_DOMAIN = "orbellionbrews.local";
function usernameToEmail(username) {
  return (
    username
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9._-]/g, "") + "@" + LOGIN_DOMAIN
  );
}

/**
 * Callable function: createMember({ username, displayName, password, role })
 *
 * Only callable by an existing admin (checked via the caller's `role` custom
 * claim). Creates a new Firebase Auth account for the person, stamps it with
 * a `role` ('member' | 'admin') and `displayName` custom claim, and mirrors
 * a lightweight profile into Firestore's `users` collection so the admin
 * panel can list everyone (Admin SDK is the only thing that can list Auth
 * users directly, so the client reads this mirror instead).
 *
 * There is deliberately no self-registration path — accounts only come from
 * this function, and only an admin can call it.
 */
exports.createMember = onCall(async (request) => {
  if (!request.auth) {
    throw new HttpsError("unauthenticated", "Sign in before adding people.");
  }
  if (request.auth.token.role !== "admin") {
    throw new HttpsError(
      "permission-denied",
      "Only an admin account can add people."
    );
  }

  const { username, displayName, password, role } = request.data || {};

  if (!username || !displayName || !password) {
    throw new HttpsError(
      "invalid-argument",
      "username, displayName, and password are all required."
    );
  }
  if (password.length < 6) {
    throw new HttpsError(
      "invalid-argument",
      "Password must be at least 6 characters."
    );
  }
  const finalRole = role === "admin" ? "admin" : "member";

  const email = usernameToEmail(username);

  let userRecord;
  try {
    userRecord = await admin.auth().createUser({
      email,
      password,
      displayName,
    });
  } catch (err) {
    if (err.code === "auth/email-already-exists") {
      throw new HttpsError("already-exists", "That Login ID is already taken.");
    }
    throw new HttpsError("internal", "Could not create the account: " + err.message);
  }

  await admin.auth().setCustomUserClaims(userRecord.uid, {
    role: finalRole,
    displayName,
  });

  await admin.firestore().collection("users").doc(userRecord.uid).set({
    username: username.trim(),
    displayName,
    role: finalRole,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    createdBy: request.auth.uid,
  });

  return { success: true, uid: userRecord.uid };
});

/**
 * Callable function: removeMember({ uid })
 *
 * Admin-only. Deletes the person's Firebase Auth account (so they can no
 * longer sign in) and their profile doc in Firestore's `users` collection.
 * Does not touch anything they've already created — items, orders, and
 * updatedBy/createdBy stamps referencing their old uid are left as-is,
 * since deleting those would erase real ledger history.
 */
exports.removeMember = onCall(async (request) => {
  if (!request.auth) {
    throw new HttpsError("unauthenticated", "Sign in before removing people.");
  }
  if (request.auth.token.role !== "admin") {
    throw new HttpsError(
      "permission-denied",
      "Only an admin account can remove people."
    );
  }

  const { uid } = request.data || {};
  if (!uid) {
    throw new HttpsError("invalid-argument", "uid is required.");
  }
  if (uid === request.auth.uid) {
    throw new HttpsError(
      "failed-precondition",
      "You can't remove your own account. Have another admin do it."
    );
  }

  try {
    await admin.auth().deleteUser(uid);
  } catch (err) {
    if (err.code !== "auth/user-not-found") {
      throw new HttpsError("internal", "Could not delete the account: " + err.message);
    }
    // Already gone from Auth — still clean up the Firestore profile below.
  }

  await admin.firestore().collection("users").doc(uid).delete();

  return { success: true };
});
