/**
 * DUTCO SICKLEAVE SYSTEM — backend (Firebase Cloud Functions v2)
 *
 * - setupAdmin    : one-time creation of the first admin account
 * - createUser / updateUser / deleteUser : admin-only user management
 * - analyzeLeave  : HR users upload an employee's certificate; Claude reads it,
 *                   date / name / duplicate / tampering checks run, and the
 *                   result is stored server-side (users can never write results)
 * - purgeExpired  : runs daily, deletes records + images older than 30 days
 */
const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { onSchedule } = require("firebase-functions/v2/scheduler");
const { setGlobalOptions } = require("firebase-functions/v2");
const { defineSecret } = require("firebase-functions/params");
const admin = require("firebase-admin");
const crypto = require("crypto");

admin.initializeApp();
const db = admin.firestore();
const bucket = admin.storage().bucket();

const ANTHROPIC_API_KEY = defineSecret("ANTHROPIC_API_KEY");
const REGION = "europe-west1";
setGlobalOptions({ region: REGION, maxInstances: 10 });

// ---------- Settings ----------
const RETENTION_DAYS = 30;
const DAILY_LIMIT_PER_USER = 150;         // analyses per HR user per day
const MAX_FILE_BYTES = 10 * 1024 * 1024;  // 10 MB
const CLAUDE_MODEL = "claude-sonnet-5-5";
const EMAIL_DOMAIN = "dutco-sls.local";   // usernames are mapped to this fake domain
const DUBAI_OFFSET_MS = 4 * 60 * 60 * 1000;

// ---------- Helpers ----------
const usernameToEmail = (u) => `${u}@${EMAIL_DOMAIN}`;
const USERNAME_RE = /^[a-z0-9._-]{3,30}$/;

function requireAuth(req) {
  if (!req.auth) throw new HttpsError("unauthenticated", "Please sign in.");
  return req.auth;
}
function requireAdmin(req) {
  const a = requireAuth(req);
  if (a.token.role !== "admin") throw new HttpsError("permission-denied", "Admins only.");
  return a;
}
function cleanStr(v, max = 120) {
  return typeof v === "string" ? v.trim().slice(0, max) : "";
}
function dubaiToday() {
  const d = new Date(Date.now() + DUBAI_OFFSET_MS);
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
}
function parseISO(s) {
  if (typeof s !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return null;
  const [y, m, d] = s.split("-").map(Number);
  const t = Date.UTC(y, m - 1, d);
  const chk = new Date(t);
  if (chk.getUTCFullYear() !== y || chk.getUTCMonth() !== m - 1 || chk.getUTCDate() !== d) return null;
  return t;
}
const DAY = 86400000;

function nameTokens(s) {
  return (s || "")
    .toLowerCase()
    .replace(/[^a-z\u0600-\u06ff\s]/g, " ")
    .split(/\s+/)
    .filter((t) => t.length >= 3 && !["bin", "bint", "abu", "al", "el"].includes(t));
}
function namesMatch(a, b) {
  const A = new Set(nameTokens(a));
  const B = nameTokens(b);
  if (!A.size || !B.length) return null; // cannot tell
  return B.some((t) => A.has(t));
}

// ---------- First-time setup ----------
exports.setupAdmin = onCall(async (req) => {
  const username = cleanStr(req.data?.username, 30).toLowerCase();
  const password = String(req.data?.password || "");
  const fullName = cleanStr(req.data?.fullName, 80) || "Administrator";
  if (!USERNAME_RE.test(username)) throw new HttpsError("invalid-argument", "Username: 3-30 chars, a-z 0-9 . _ -");
  if (password.length < 8) throw new HttpsError("invalid-argument", "Password must be at least 8 characters.");

  const setupRef = db.doc("config/setup");
  await db.runTransaction(async (tx) => {
    const s = await tx.get(setupRef);
    if (s.exists) throw new HttpsError("failed-precondition", "System is already set up.");
    tx.set(setupRef, { done: true, at: admin.firestore.FieldValue.serverTimestamp() });
  });

  try {
    const u = await admin.auth().createUser({ email: usernameToEmail(username), password, displayName: fullName });
    await admin.auth().setCustomUserClaims(u.uid, { role: "admin" });
    await db.doc(`users/${u.uid}`).set({
      username, fullName, role: "admin", active: true,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    return { ok: true };
  } catch (e) {
    await setupRef.delete(); // allow retry
    throw new HttpsError("internal", e.message || "Setup failed.");
  }
});

// ---------- User management (admin) ----------
exports.createUser = onCall(async (req) => {
  const me = requireAdmin(req);
  const username = cleanStr(req.data?.username, 30).toLowerCase();
  const password = String(req.data?.password || "");
  const fullName = cleanStr(req.data?.fullName, 80);
  const employeeId = cleanStr(req.data?.employeeId, 40);
  const role = req.data?.role === "admin" ? "admin" : "employee";
  if (!USERNAME_RE.test(username)) throw new HttpsError("invalid-argument", "Username: 3-30 chars, a-z 0-9 . _ -");
  if (password.length < 8) throw new HttpsError("invalid-argument", "Password must be at least 8 characters.");
  if (!fullName) throw new HttpsError("invalid-argument", "Full name is required.");

  let u;
  try {
    u = await admin.auth().createUser({ email: usernameToEmail(username), password, displayName: fullName });
  } catch (e) {
    if (e.code === "auth/email-already-exists") throw new HttpsError("already-exists", "Username already taken.");
    throw new HttpsError("internal", e.message);
  }
  await admin.auth().setCustomUserClaims(u.uid, { role });
  await db.doc(`users/${u.uid}`).set({
    username, fullName, employeeId, role, active: true,
    createdAt: admin.firestore.FieldValue.serverTimestamp(), createdBy: me.uid,
  });
  return { ok: true, uid: u.uid };
});

exports.updateUser = onCall(async (req) => {
  const me = requireAdmin(req);
  const uid = cleanStr(req.data?.uid, 128);
  if (!uid) throw new HttpsError("invalid-argument", "Missing user.");
  const ref = db.doc(`users/${uid}`);
  const snap = await ref.get();
  if (!snap.exists) throw new HttpsError("not-found", "User not found.");

  const authUpdate = {};
  const docUpdate = {};
  if (typeof req.data.password === "string" && req.data.password) {
    if (req.data.password.length < 8) throw new HttpsError("invalid-argument", "Password must be at least 8 characters.");
    authUpdate.password = req.data.password;
  }
  if (typeof req.data.active === "boolean") {
    if (uid === me.uid && !req.data.active) throw new HttpsError("failed-precondition", "You cannot disable your own account.");
    authUpdate.disabled = !req.data.active;
    docUpdate.active = req.data.active;
  }
  if (typeof req.data.fullName === "string" && req.data.fullName.trim()) {
    docUpdate.fullName = cleanStr(req.data.fullName, 80);
    authUpdate.displayName = docUpdate.fullName;
  }
  if (req.data.role === "admin" || req.data.role === "employee") {
    if (uid === me.uid && req.data.role !== "admin") throw new HttpsError("failed-precondition", "You cannot remove your own admin role.");
    await admin.auth().setCustomUserClaims(uid, { role: req.data.role });
    docUpdate.role = req.data.role;
  }
  if (Object.keys(authUpdate).length) await admin.auth().updateUser(uid, authUpdate);
  if (authUpdate.disabled || authUpdate.password || docUpdate.role) await admin.auth().revokeRefreshTokens(uid);
  if (Object.keys(docUpdate).length) await ref.update(docUpdate);
  return { ok: true };
});

exports.deleteUser = onCall(async (req) => {
  const me = requireAdmin(req);
  const uid = cleanStr(req.data?.uid, 128);
  if (!uid) throw new HttpsError("invalid-argument", "Missing user.");
  if (uid === me.uid) throw new HttpsError("failed-precondition", "You cannot delete your own account.");
  await admin.auth().deleteUser(uid).catch(() => {});
  await db.doc(`users/${uid}`).delete();
  const toks = await db.collection("pushTokens").where("uid", "==", uid).get();
  await Promise.all(toks.docs.map((d) => d.ref.delete()));
  return { ok: true }; // their verification logs stay until the 30-day purge
});

// ---------- Claude analysis ----------
const PROMPT = `You are a document-forensics assistant for an HR department in the United Arab Emirates.
The attached file is supposed to be a UAE medical SICK LEAVE certificate (from DHA Dubai, DOH Abu Dhabi, MOHAP / Emirates Health Services (Sharjah, Ajman, Umm Al Quwain, Ras Al Khaimah, Fujairah), Sharjah Health Authority, or a licensed private facility in the UAE).

Read it carefully and reply with ONLY one JSON object, no other text, with exactly these keys:
{
  "is_sick_leave_document": boolean,
  "issuing_authority": "DHA" | "DOH" | "MOHAP" | "EHS" | "SHA" | "OTHER_UAE" | "NON_UAE" | "UNKNOWN",
  "emirate": string,
  "reference_number": string,          // sick leave / certificate / attestation number exactly as printed, "" if none
  "dha_barcode": string,               // DHA documents only: the "Barcode Number" printed near the bottom, digits/letters exactly, "" if none
  "dha_pin": string,                   // DHA documents only: the "PIN" printed next to the barcode number, exactly, "" if none
  "patient_name": string,              // as printed
  "patient_name_english": string,      // English transliteration if printed in Arabic
  "patient_id": string,                // Emirates ID / MRN / passport, as printed
  "facility_name": string,
  "doctor_name": string,
  "issue_date": "YYYY-MM-DD" | "",
  "leave_start": "YYYY-MM-DD" | "",
  "leave_end": "YYYY-MM-DD" | "",
  "stated_days": number | null,         // number of days written on the certificate
  "has_qr_code": boolean,
  "is_attested": boolean,              // true ONLY if the certificate shows it is ATTESTED / officially verified by a UAE health authority (see rules)
  "attestation_evidence": string,      // what proves the attestation (e.g. "MOHAP e-attestation footer with attestation no. 12345 and QR"), "" if none
  "verification_url": string,          // any web address printed on the certificate for checking it online (copy exactly, e.g. "https://www.doh.gov.ae/..."), "" if none
  "has_stamp_or_seal": boolean,
  "has_signature": boolean,
  "image_quality": "good" | "poor" | "unreadable",
  "tampering_signs": [ { "severity": "high" | "medium" | "low", "description": string } ],
  "summary": string                     // one short English sentence
}

Rules:
- UAE certificates write dates as DD/MM/YYYY. Convert to YYYY-MM-DD. Convert Hijri dates to Gregorian if only Hijri is shown.
- Look closely for manipulation, especially in DATES, NUMBER OF DAYS, NAMES and the REFERENCE NUMBER: digits in a different font, size, weight, colour or baseline; misaligned or overwritten characters; white boxes or smudges behind text; inconsistent background/compression around specific fields; pixelation differences; mismatched Arabic vs English values on the same certificate; text that looks typed onto a scanned page; logos or seals that look pasted; a template with blank or placeholder fields; a screenshot of an editing app.
- If Arabic and English sections show different dates or days, that is a HIGH severity sign.
- Only report signs you can actually see. Normal photo blur, glare or folds are not tampering. Do not invent problems.
- If the file is not a sick leave certificate at all, set is_sick_leave_document to false.
- ATTESTATION: set is_attested to true when the certificate shows that a UAE health authority attested it OR officially issued it through its e-system. Any ONE of these is enough:
  * an attestation stamp, e-attestation block or footer (e.g. "Attested", "Certified", "مصدق", "تم التصديق", "توثيق"), or an attestation / certification number;
  * an online verification link, verification code or QR printed on the certificate that belongs to a UAE health authority or government system (e.g. doh.gov.ae, tamm.abudhabi, dha.gov.ae, mohap.gov.ae, ehs.gov.ae, malaffi.ae, seha.ae, any *.gov.ae), typically with the authority's official reference number;
  * a DHA e-certificate with "Barcode Number" and "PIN" for online verification.
  A clinic or hospital's own stamp, signature or logo ALONE, with nothing from the list above, is NOT attestation. Always copy any verification link into verification_url.`;

async function callClaude(base64, mediaType) {
  const block = mediaType === "application/pdf"
    ? { type: "document", source: { type: "base64", media_type: "application/pdf", data: base64 } }
    : { type: "image", source: { type: "base64", media_type: mediaType, data: base64 } };

  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": ANTHROPIC_API_KEY.value(),
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: CLAUDE_MODEL,
      max_tokens: 6000,
      messages: [{ role: "user", content: [block, { type: "text", text: PROMPT }] }],
    }),
  });
  if (!res.ok) {
    const t = await res.text();
    console.error("Claude API error", res.status, t.slice(0, 500));
    throw new HttpsError("unavailable", "The reading service is busy. Please try again in a minute.");
  }
  const json = await res.json();
  const text = (json.content || []).filter((c) => c.type === "text").map((c) => c.text).join("\n");
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  const fail = (why) => {
    console.error("Claude reply not usable:", why, "stop_reason:", json.stop_reason,
      "usage:", JSON.stringify(json.usage || {}), "text:", text.slice(0, 300), "...", text.slice(-300));
    return new HttpsError("internal", "Could not read the certificate. Try a clearer photo.");
  };
  if (start < 0 || end < 0) throw fail("no JSON");
  try {
    return JSON.parse(text.slice(start, end + 1));
  } catch (e) {
    throw fail("bad JSON: " + e.message);
  }
}

function idDigits(s) { return String(s || "").replace(/\D/g, ""); }

const { dhaVerify } = require("./dha");

async function officialCheck(x) {
  if (x.issuing_authority !== "DHA") return null;
  const barcode = cleanStr(x.dha_barcode, 40).replace(/\s+/g, "");
  const pin = cleanStr(x.dha_pin, 20).replace(/\s+/g, "");
  if (!barcode || !pin) return { source: "DHA", status: "no_code" };
  const r = await dhaVerify(barcode, pin);
  return { source: "DHA", barcode, ...r };
}

// A verification link printed on the certificate. Official = a UAE government / health-authority site.
const OFFICIAL_HOST_RE = /(^|\.)(gov\.ae|abudhabi|abudhabi\.ae|tamm\.abudhabi|malaffi\.ae|seha\.ae)$/i;
function verificationLink(raw) {
  let t = cleanStr(raw, 400).replace(/\s+/g, "");
  if (!t) return null;
  if (!/^https?:\/\//i.test(t)) t = "https://" + t;
  try {
    const u = new URL(t);
    if (!/^https?:$/.test(u.protocol) || !u.hostname.includes(".")) return null;
    const host = u.hostname.toLowerCase().replace(/^www\./, "");
    return { url: u.href, host, official: OFFICIAL_HOST_RE.test(host) };
  } catch { return null; }
}

function runChecks(x, subject, dup, official, attested, vlink) {
  const flags = [];
  const red = (code, msg) => flags.push({ level: "red", code, message: msg });
  const amber = (code, msg) => flags.push({ level: "amber", code, message: msg });
  const green = (code, msg) => flags.push({ level: "green", code, message: msg });

  if (vlink) {
    if (vlink.official) green("OFFICIAL_LINK", `Has an official verification link (${vlink.host}). Open it to confirm the record.`);
    else amber("UNOFFICIAL_LINK", `The verification link points to ${vlink.host}, which is not a UAE government site. Check it carefully.`);
  }

  if (official) {
    if (official.status === "verified") green("OFFICIAL_VERIFIED", `Found on ${official.source}'s official verification service (barcode ${official.barcode}). Make sure the name and dates match the official record.`);
    else if (official.status === "not_found") red("OFFICIAL_NOT_FOUND", `${official.source}'s official verification service has NO record of this barcode and PIN.`);
    else if (official.status === "no_code") amber("OFFICIAL_NO_CODE", `${official.source} barcode / PIN could not be read, so the official check was not done. Verify on the portal.`);
    else amber("OFFICIAL_UNAVAILABLE", `${official.source}'s official verification service did not respond. Verify on the portal.`);
  }

  if (!x.is_sick_leave_document) red("NOT_SICK_LEAVE", "The file is not a sick leave certificate.");
  if (x.image_quality === "unreadable") amber("UNREADABLE", "The image is unreadable — ask the employee for a clearer copy.");

  if (x.issuing_authority === "NON_UAE") red("NON_UAE", "Issued outside the UAE (needs MOFA attestation) — not accepted.");
  if (x.issuing_authority === "UNKNOWN") amber("UNKNOWN_AUTHORITY", "Issuing health authority could not be identified.");
  if (!x.reference_number) amber("NO_REFERENCE", "No sick leave reference number found.");
  if (!x.has_stamp_or_seal && !x.has_qr_code) amber("NO_SEAL_QR", "No stamp, seal or QR code visible.");

  const today = dubaiToday();
  const s = parseISO(x.leave_start);
  const e = parseISO(x.leave_end);
  const i = parseISO(x.issue_date);
  if (!s || !e) amber("DATES_MISSING", "Leave start/end dates could not be read.");
  if (s && e) {
    if (s > e) red("DATES_REVERSED", "Leave end date is before the start date.");
    const days = Math.round((e - s) / DAY) + 1;
    if (typeof x.stated_days === "number" && x.stated_days > 0 && days > 0 && x.stated_days !== days) {
      red("DAYS_MISMATCH", `Certificate says ${x.stated_days} day(s) but the dates cover ${days} day(s).`);
    }
    if (s > today + DAY) amber("FUTURE_START", "Leave starts in the future.");
    if (today - e > 30 * DAY) amber("LATE_SUBMISSION", "Leave ended more than 30 days ago.");
    if (days > 30) amber("LONG_LEAVE", "Leave longer than 30 days needs medical committee approval.");
  }
  if (i) {
    if (i > today + DAY) red("FUTURE_ISSUE", "Issue date is in the future.");
    if (e && i > e + DAY) amber("ISSUED_AFTER", "Certificate was issued after the leave ended (backdated).");
    if (s && s - i > 7 * DAY) amber("ISSUED_EARLY", "Certificate issued more than a week before the leave starts.");
  }

  // Optional: compare with the employee HR entered for this certificate
  if (subject.name) {
    const nm = namesMatch(subject.name, `${x.patient_name} ${x.patient_name_english}`);
    if (nm === false) red("NAME_MISMATCH", `Patient name on the certificate does not match the employee "${subject.name}".`);
  }
  const subjDigits = idDigits(subject.id);
  const certDigits = idDigits(x.patient_id);
  if (subjDigits.length >= 6 && certDigits.length >= 6 && subjDigits !== certDigits) {
    red("ID_MISMATCH", "Emirates ID / ID number on the certificate does not match the one entered.");
  }

  for (const t of Array.isArray(x.tampering_signs) ? x.tampering_signs : []) {
    const msg = cleanStr(t.description, 300);
    if (!msg) continue;
    if (t.severity === "high") red("TAMPERING", `Tampering: ${msg}`);
    else if (t.severity === "medium") amber("POSSIBLE_TAMPERING", `Possible edit: ${msg}`);
  }

  if (dup) {
    const when = dup.createdAt ? new Date(dup.createdAt.toMillis() + DUBAI_OFFSET_MS).toISOString().slice(0, 10).split("-").reverse().join("/") : "earlier";
    const differentPerson = subject.name && dup.subjectName && namesMatch(subject.name, dup.subjectName) === false;
    if (differentPerson) red("DUPLICATE_OTHER", `This reference number was already used for another employee ("${dup.subjectName}") on ${when}.`);
    else amber("ALREADY_CHECKED", `This certificate was already checked on ${when}${dup.checkedBy ? ` by @${dup.checkedBy}` : ""}${dup.subjectName ? ` for "${dup.subjectName}"` : ""}.`);
  }

  // Forgery always wins. Otherwise a certificate that is not attested is rejected
  // until the employee attests it (company policy), whatever the other checks say.
  let verdict;
  if (flags.some((f) => f.level === "red")) verdict = "FORGED";
  else if (!attested) {
    verdict = "UNATTESTED";
    flags.unshift({ level: "purple", code: "NOT_ATTESTED", message: "NOT ATTESTED: this sick leave has not been attested by a UAE health authority. Ask the employee to attest it (MOHAP / TAMM / DHA) before proceeding." });
  } else verdict = flags.some((f) => f.level === "amber") ? "REVIEW" : "GENUINE";
  return { verdict, flags };
}

exports.analyzeLeave = onCall(
  { secrets: [ANTHROPIC_API_KEY], timeoutSeconds: 180, memory: "512MiB" },
  async (req) => {
    const auth = requireAuth(req);
    const path = cleanStr(req.data?.path, 300);
    if (!path.startsWith(`uploads/${auth.uid}/`)) throw new HttpsError("permission-denied", "Invalid file.");
    // The employee whose leave this is (entered by the HR user, optional)
    const subject = { name: cleanStr(req.data?.employeeName, 80), id: cleanStr(req.data?.employeeId, 40) };

    const userRef = db.doc(`users/${auth.uid}`);
    const userSnap = await userRef.get();
    if (!userSnap.exists || userSnap.data().active === false) throw new HttpsError("permission-denied", "Account disabled.");
    const user = userSnap.data();

    // Daily limit per HR user (Dubai day)
    const dayKey = new Date(Date.now() + DUBAI_OFFSET_MS).toISOString().slice(0, 10);
    await db.runTransaction(async (tx) => {
      const u = (await tx.get(userRef)).data() || {};
      const count = u.dayKey === dayKey ? (u.dayCount || 0) : 0;
      if (count >= DAILY_LIMIT_PER_USER) throw new HttpsError("resource-exhausted", "Daily limit reached.");
      tx.update(userRef, { dayKey, dayCount: count + 1 });
    });

    const file = bucket.file(path);
    const [meta] = await file.getMetadata().catch(() => [null]);
    if (!meta) throw new HttpsError("not-found", "Upload not found.");
    const size = Number(meta.size || 0);
    const type = meta.contentType || "";
    const okTypes = ["image/jpeg", "image/png", "image/webp", "image/gif", "application/pdf"];
    if (!okTypes.includes(type)) throw new HttpsError("invalid-argument", "Use a JPG, PNG, WEBP or PDF file.");
    if (size > MAX_FILE_BYTES) throw new HttpsError("invalid-argument", "File is larger than 10 MB.");

    const [buf] = await file.download();
    const x = await callClaude(buf.toString("base64"), type);

    // Has this reference number been checked before (by anyone)?
    let dup = null;
    let refKey = null;
    const refNorm = cleanStr(x.reference_number || x.dha_barcode, 80).toUpperCase().replace(/[^A-Z0-9]/g, "");
    const official = await officialCheck(x);
    // Company policy: only attested certificates are accepted.
    const vlink = verificationLink(x.verification_url);
    const attested = !!x.is_attested || (official && official.status === "verified") || (vlink && vlink.official);
    if (refNorm.length >= 4) {
      refKey = crypto.createHash("sha256").update(`${x.issuing_authority}|${refNorm}`).digest("hex").slice(0, 40);
      const r = await db.doc(`refs/${refKey}`).get();
      if (r.exists) dup = r.data();
    }

    const { verdict, flags } = runChecks(x, subject, dup, official, attested, vlink);
    const now = admin.firestore.Timestamp.now();
    const expiresAt = admin.firestore.Timestamp.fromMillis(now.toMillis() + RETENTION_DAYS * DAY);

    const extracted = {
      authority: cleanStr(x.issuing_authority, 20),
      emirate: cleanStr(x.emirate, 40),
      reference: cleanStr(x.reference_number, 80),
      patientName: cleanStr(x.patient_name, 120),
      patientNameEn: cleanStr(x.patient_name_english, 120),
      patientId: cleanStr(x.patient_id, 40),
      facility: cleanStr(x.facility_name, 120),
      doctor: cleanStr(x.doctor_name, 120),
      issueDate: cleanStr(x.issue_date, 10),
      start: cleanStr(x.leave_start, 10),
      end: cleanStr(x.leave_end, 10),
      statedDays: typeof x.stated_days === "number" ? x.stated_days : null,
      hasQr: !!x.has_qr_code,
      attested: !!attested,
      attestationEvidence: cleanStr(x.attestation_evidence, 200),
      verificationUrl: vlink && vlink.official ? vlink.url : "",
      verificationHost: vlink ? vlink.host : "",
      hasSeal: !!x.has_stamp_or_seal,
      hasSignature: !!x.has_signature,
      quality: cleanStr(x.image_quality, 12),
      summary: cleanStr(x.summary, 300),
    };

    const checkRef = db.collection("checks").doc();
    await checkRef.set({
      // who checked (the HR user)
      uid: auth.uid,
      username: user.username,
      fullName: user.fullName,
      // whose sick leave it is
      subjectName: subject.name || extracted.patientNameEn || extracted.patientName,
      subjectId: subject.id,
      subjectEntered: !!subject.name,
      filePath: path,
      contentType: type,
      createdAt: now,
      expiresAt,
      verdict,
      flags,
      extracted,
      official: official ? { source: official.source, status: official.status, barcode: official.barcode || "", details: cleanStr(official.details || "", 1500), note: cleanStr(official.note || "", 200) } : null,
      refKey,
      model: CLAUDE_MODEL,
      adminDecision: null,
      adminNote: "",
    });
    if (refKey && !dup) {
      await db.doc(`refs/${refKey}`).set({
        uid: auth.uid, checkedBy: user.username, subjectName: subject.name || extracted.patientNameEn || extracted.patientName,
        checkId: checkRef.id, createdAt: now,
      });
    }

    if (verdict === "FORGED") {
      await alertAdminsForged(subject.name || extracted.patientNameEn || extracted.patientName, user.username).catch((e) => console.error("push", e));
    }

    // HR users see the full result, including the reasons.
    return {
      id: checkRef.id,
      verdict,
      flags: flags.map((f) => ({ level: f.level, message: f.message })),
      official: official ? { source: official.source, status: official.status } : null,
      attested: !!attested,
      verificationUrl: vlink && vlink.official ? vlink.url : "",
      authority: extracted.authority,
      reference: extracted.reference,
      patientName: extracted.patientNameEn || extracted.patientName,
      facility: extracted.facility,
      start: extracted.start,
      end: extracted.end,
      statedDays: extracted.statedDays,
      issueDate: extracted.issueDate,
    };
  }
);


// ---------- Push notifications ----------
const tokenId = (t) => crypto.createHash("sha256").update(t).digest("hex").slice(0, 40);

exports.savePushToken = onCall(async (req) => {
  const auth = requireAuth(req);
  const token = cleanStr(req.data?.token, 4096);
  if (token.length < 20) throw new HttpsError("invalid-argument", "Invalid token.");
  await db.doc(`pushTokens/${tokenId(token)}`).set({
    uid: auth.uid, token, device: cleanStr(req.data?.device, 200),
    updatedAt: admin.firestore.FieldValue.serverTimestamp(),
  });
  return { ok: true };
});

async function pushTo(uids, title, body) {
  const tokens = [];
  if (uids === "all") {
    (await db.collection("pushTokens").limit(2000).get()).forEach((d) => tokens.push(d.data().token));
  } else {
    for (let i = 0; i < uids.length; i += 30) {
      const s = await db.collection("pushTokens").where("uid", "in", uids.slice(i, i + 30)).get();
      s.forEach((d) => tokens.push(d.data().token));
    }
  }
  let sent = 0, failed = 0;
  for (let i = 0; i < tokens.length; i += 500) {
    const batch = tokens.slice(i, i + 500);
    const res = await admin.messaging().sendEachForMulticast({
      tokens: batch,
      notification: { title, body },
      webpush: {
        notification: { title, body, icon: "/icon-192.png", badge: "/icon-192.png" },
        fcmOptions: { link: "https://dutco-sickleave.web.app/" },
      },
    });
    sent += res.successCount; failed += res.failureCount;
    await Promise.all(res.responses.map((r, j) => {
      const code = r.error?.code || "";
      if (!r.success && /not-registered|invalid-registration|invalid-argument/.test(code)) {
        return db.doc(`pushTokens/${tokenId(batch[j])}`).delete().catch(() => {});
      }
      return null;
    }));
  }
  return { devices: tokens.length, sent, failed };
}

exports.sendNotification = onCall(async (req) => {
  const me = requireAdmin(req);
  const title = cleanStr(req.data?.title, 60);
  const body = cleanStr(req.data?.body, 300);
  const target = cleanStr(req.data?.target, 128) || "all";
  if (!title || !body) throw new HttpsError("invalid-argument", "Title and message are required.");
  const r = await pushTo(target === "all" ? "all" : [target], title, body);
  const sender = (await db.doc(`users/${me.uid}`).get()).data() || {};
  await db.collection("notifications").add({
    title, body, target, sentBy: sender.username || "", ...r,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  });
  return r;
});

async function alertAdminsForged(subjectName, checkedBy) {
  const admins = await db.collection("users").where("role", "==", "admin").get();
  const uids = admins.docs.map((d) => d.id);
  if (!uids.length) return;
  await pushTo(uids, "Forged sick leave detected", `${subjectName || "An employee"}'s certificate was flagged as FORGED (checked by @${checkedBy}).`);
}

// ---------- 30-day retention ----------
exports.purgeExpired = onSchedule({ schedule: "every day 03:00", timeZone: "Asia/Dubai" }, async () => {
  const now = admin.firestore.Timestamp.now();
  let total = 0;
  for (;;) {
    const snap = await db.collection("checks").where("expiresAt", "<=", now).limit(200).get();
    if (snap.empty) break;
    for (const d of snap.docs) {
      const c = d.data();
      if (c.filePath) await bucket.file(c.filePath).delete().catch(() => {});
      if (c.refKey) {
        const r = await db.doc(`refs/${c.refKey}`).get();
        if (r.exists && r.data().checkId === d.id) await r.ref.delete();
      }
      await d.ref.delete();
      total++;
    }
  }
  // Orphan uploads (uploaded but never analyzed) older than 30 days
  const cutoff = Date.now() - RETENTION_DAYS * DAY;
  const [files] = await bucket.getFiles({ prefix: "uploads/" });
  for (const f of files) {
    if (new Date(f.metadata.timeCreated).getTime() < cutoff) await f.delete().catch(() => {});
  }
  console.log(`Purged ${total} expired record(s).`);
});
