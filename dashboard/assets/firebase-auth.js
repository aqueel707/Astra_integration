// dashboard/assets/firebase-auth.js
// Firebase email/password auth — writes token directly to dcc.Store via
// dash_clientside.set_props (no relay input; that hop was the bug).
import { initializeApp } from "https://www.gstatic.com/firebasejs/12.13.0/firebase-app.js";
import {
  getAuth,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signOut,
  onAuthStateChanged,
  setPersistence,
  browserSessionPersistence,
  sendEmailVerification,
  sendPasswordResetEmail,
} from "https://www.gstatic.com/firebasejs/12.13.0/firebase-auth.js";

const firebaseConfig = {
  apiKey: "AIzaSyCYuwpkNOHR50HGVvtRpW7G4t3Ulc8xYvY",
  authDomain: "astra-cyber.firebaseapp.com",
  projectId: "astra-cyber",
  storageBucket: "astra-cyber.firebasestorage.app",
  messagingSenderId: "790303580957",
  appId: "1:790303580957:web:8eaccc58e68d49dc9977f4",
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);

setPersistence(auth, browserSessionPersistence).catch((e) =>
  console.error("[astra-auth] setPersistence failed:", e)
);

function setToken(token) {
  try {
    if (window.dash_clientside && typeof window.dash_clientside.set_props === "function") {
      window.dash_clientside.set_props("auth-token", { data: token || null });
    } else {
      console.warn("[astra-auth] dash_clientside not ready, retrying...");
      setTimeout(function () { setToken(token); }, 120);
    }
  } catch (e) {
    console.error("[astra-auth] setToken failed:", e);
  }
}

function showError(msg) {
  var el = document.getElementById("auth-error");
  if (el) el.textContent = msg || "";
  var note = document.getElementById("auth-notice");
  if (note && msg) { note.textContent = ""; note.classList.remove("is-visible"); }
}

// Success/《info》channel. Errors are red and terse; this is for the states that
// are not failures — "we sent you a link", "reset email on its way".
function showNotice(msg) {
  var el = document.getElementById("auth-notice");
  if (el) {
    el.textContent = msg || "";
    el.classList.toggle("is-visible", !!msg);
  }
  if (msg) showErrorRaw("");
}

function showErrorRaw(msg) {
  var el = document.getElementById("auth-error");
  if (el) el.textContent = msg || "";
}

// The API refuses providers outside this list (api/email_allowlist.py) AFTER
// the Firebase account already exists, which leaves an inert account behind.
// Checking here means the user finds out before that happens.
var ALLOWED_DOMAINS = [
  "gmail.com", "googlemail.com", "duck.com",
  "proton.me", "protonmail.com", "protonmail.ch", "pm.me",
  "tutamail.com", "tuta.com", "tutanota.com", "tutanota.de", "keemail.me",
  "icloud.com", "me.com", "mac.com",
];

function providerAllowed(email) {
  var at = String(email || "").lastIndexOf("@");
  if (at < 0) return false;
  return ALLOWED_DOMAINS.indexOf(email.slice(at + 1).trim().toLowerCase()) !== -1;
}

function friendly(code, fallback) {
  switch (code) {
    case "auth/invalid-email": return "That email address is invalid.";
    case "auth/missing-password": return "Enter a password.";
    case "auth/weak-password": return "Password is too weak - use at least 6 characters.";
    case "auth/email-already-in-use": return "An account with that email already exists. Try signing in.";
    case "auth/invalid-credential":
    case "auth/wrong-password":
    case "auth/user-not-found": return "Incorrect email or password.";
    case "auth/too-many-requests": return "Too many attempts. Wait a moment and try again.";
    case "auth/network-request-failed": return "Network error reaching Firebase. Check your connection.";
    default: return fallback || "Authentication failed. Please try again.";
  }
}

onAuthStateChanged(auth, async (user) => {
  if (!user) { setToken(""); return; }

  // An unverified password account gets a valid Firebase token that the API
  // then refuses with 403 on every request (api/firebase_auth.py). Handing it
  // to the app produced a dashboard where nothing loaded and nothing said why.
  if (!user.emailVerified && isPasswordUser(user)) {
    setToken("");
    showUnverified(user.email);
    return;
  }

  try { setToken(await user.getIdToken(false)); }
  catch (e) { console.error("[astra-auth] getIdToken failed:", e); setToken(""); }
});

function isPasswordUser(user) {
  // Federated providers prove the address themselves; only password signups
  // need the verification round-trip. Mirrors _assert_email_verified server-side.
  var providers = (user.providerData || []).map(function (p) { return p.providerId; });
  return providers.length === 0 || providers.indexOf("password") !== -1;
}

function showUnverified(email) {
  showErrorRaw("");
  showNotice(
    "Check " + (email || "your inbox") + " for a verification link, then sign in again. " +
    "Not there? Use \u2018Resend verification\u2019 below."
  );
  var resend = document.getElementById("auth-resend");
  if (resend) resend.classList.add("is-visible");
}

async function doSignIn() {
  showError("");
  var email = (document.getElementById("login-email") || {}).value || "";
  var password = (document.getElementById("login-password") || {}).value || "";
  if (!email || !password) { showError("Enter both email and password."); return; }
  try {
    var cred = await signInWithEmailAndPassword(auth, email, password);
    setToken(await cred.user.getIdToken(false));
  } catch (e) {
    showError(friendly(e && e.code, "Sign-in failed."));
    console.error("[astra-auth] signIn:", e && e.code, e);
  }
}

async function doSignUp() {
  showError("");
  var email = (document.getElementById("signup-email") || {}).value || "";
  var password = (document.getElementById("signup-password") || {}).value || "";
  if (!email || !password) { showError("Enter an email and a password."); return; }
  if (password.length < 6) { showError("Password must be at least 6 characters."); return; }
  if (!providerAllowed(email)) {
    showError("That email provider isn\u2019t supported. Use Gmail, DuckDuckGo, Proton, Tuta or iCloud.");
    return;
  }
  try {
    var cred = await createUserWithEmailAndPassword(auth, email, password);
    // Send the link BEFORE signing out, while the credential is still live.
    try { await sendEmailVerification(cred.user); }
    catch (e) { console.error("[astra-auth] sendEmailVerification:", e); }
    await signOut(auth);
    showNotice("Account created. We sent a verification link to " + email +
               " \u2014 open it, then sign in.");
    return;
  } catch (e) {
    showError(friendly(e && e.code, "Could not create account."));
    console.error("[astra-auth] signUp:", e && e.code, e);
  }
}

document.addEventListener("click", async (ev) => {
  if (ev.target.closest("#login-submit")) { ev.preventDefault(); await doSignIn(); return; }
  if (ev.target.closest("#signup-submit")) { ev.preventDefault(); await doSignUp(); return; }
  if (ev.target.closest("#logout-btn")) {
    ev.preventDefault();
    try { await signOut(auth); } catch (e) { console.error("[astra-auth] signOut:", e); }
    setToken("");
    return;
  }
  if (ev.target.closest("#auth-resend")) {
    ev.preventDefault();
    var u = auth.currentUser;
    if (u) {
      try { await sendEmailVerification(u); showNotice("Verification link sent again to " + u.email + "."); }
      catch (e) { showError("Could not resend just yet - wait a minute and try again."); }
    } else {
      showError("Sign in first, then resend the verification link.");
    }
    return;
  }
  if (ev.target.closest("#auth-forgot")) {
    ev.preventDefault();
    var addr = (document.getElementById("login-email") || {}).value || "";
    if (!addr) { showError("Enter your email address first, then choose Reset password."); return; }
    try { await sendPasswordResetEmail(auth, addr); showNotice("Password reset link sent to " + addr + "."); }
    catch (e) { showError(friendly(e && e.code, "Could not send a reset link.")); }
    return;
  }
  var toggle = ev.target.closest(".auth-reveal");
  if (toggle) {
    ev.preventDefault();
    var input = document.getElementById(toggle.getAttribute("data-for"));
    if (input) {
      var showing = input.type === "text";
      input.type = showing ? "password" : "text";
      toggle.textContent = showing ? "Show" : "Hide";
      toggle.setAttribute("aria-label", showing ? "Show password" : "Hide password");
    }
    return;
  }

  var tab = ev.target.closest(".auth-tab");
  if (tab) {
    ev.preventDefault();
    var mode = tab.getAttribute("data-mode");
    document.querySelectorAll(".auth-tab").forEach(function (t) {
      t.classList.toggle("is-active", t.getAttribute("data-mode") === mode);
    });
    var si = document.getElementById("auth-panel-signin");
    var su = document.getElementById("auth-panel-signup");
    if (si) si.style.display = mode === "signin" ? "" : "none";
    if (su) su.style.display = mode === "signup" ? "" : "none";
    showError("");
    showNotice("");
    var r = document.getElementById("auth-resend");
    if (r) r.classList.remove("is-visible");
  }
});

document.addEventListener("keydown", (ev) => {
  if (ev.key !== "Enter") return;
  if (ev.target.closest("#auth-panel-signin")) { ev.preventDefault(); doSignIn(); }
  else if (ev.target.closest("#auth-panel-signup")) { ev.preventDefault(); doSignUp(); }
});
