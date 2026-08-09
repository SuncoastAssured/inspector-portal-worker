// Assured Inspector — Homeowner Portal Worker
// ============================================================
//
// Inspector's first server-side component. Modeled directly on Assured
// Handyman's real, proven multi-tenant status-worker.js — the same
// core trust primitive (verify a license token's RSA signature
// server-side, with the same public key and algorithm the app already
// uses client-side; a company_id supplied as a bare parameter is NEVER
// enough to write data on its own, only a verified token's own
// embedded company_id is trusted), the same tenant-scoped KV key
// pattern, and the same public-read/license-gated-write shape already
// proven out on Handyman's invoice pay-page endpoint.
//
// Deliberately does NOT carry over Handyman's crew time tracking,
// work-order routing, or inventory-by-location endpoints — Inspector
// has no crew/seat concept (one flat license per business), so none of
// that applies here.
//
// ONE ENDPOINT PAIR, ONE JOB:
//
// GET  /report?id=<unguessable>&biz=<companyId>  — public, no login.
//   Returns a deliberately narrow slice of a completed inspection:
//   property name, visit date, condition score, pass/fail summary,
//   a curated set of photos, company branding. NEVER the full raw
//   checklist (item-by-item notes), vendor contacts, or pricing —
//   stripped server-side even if a caller's write payload includes
//   them, never just trusted to have been left out client-side.
//
// POST /report  — requires a valid, verified license token (same
//   verification the app itself already performs). The app calls this
//   only when the inspector explicitly taps "Publish to portal" on a
//   completed report — never automatically, matching every other
//   consent-gated feature already in this app (AI features, EULA,
//   data-warning notice all work the same way: nothing sends data off
//   the device without an explicit, visible action first).
//
// The company_id in a verified write always comes from INSIDE the
// signed token, never from a client-supplied field — this is the
// single most important property of this file, stated once here and
// worth restating: a request cannot claim to be a different company's
// data just by changing a parameter.

const REPORT_TTL_SECONDS = 60 * 60 * 24 * 365; // 1 year — a home-watch client may reference this for insurance purposes long after the visit

// Same public key already embedded in Inspector's own app.js
// (LICENSE_PUBLIC_KEY_PEM, stripped of its PEM headers/newlines down to
// the raw base64 SPKI body — verified to decode to a valid 2048-bit RSA
// key before this file was written, not assumed). Must stay in sync if
// the keypair is ever rotated — the private key itself never appears
// anywhere in this file or on any server, exactly as with Inspector's
// existing offline license-generator.html.
const LICENSE_PUBLIC_KEY_B64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuNr5k4HdDy94X3FRBGOPwklm4z8rs8zgZiLJKXbGto+fq6N26lBaJGdvtptbrYBTA1VqZG3pGdbjY6l8H7c9y6k+WBUPi7tSllJhDbN/H0YRYYZYsLinSI49/K08ttSmnFdnyDpWePGC4ia9AbacJD66b6BGYuMMGXB68i7lWuJyTGTewzfpVLtwVdyznKNJraWXWEgccfUWJ21LYCNawHX5VdRJIlGKdXsuTwKvlSiiApgxBc8XxcszQrkxZApuIlrXZJzSRTI/KWJlQ057c6P5mHwZAOZtUZH00i1WwOsNIKIJy22Oi+Yz9ENSAXIT7k3tmszdsgC3IzMGHi7YtwIDAQAB";

// Byte-for-byte identical to app.js's own LICENSE_GRACE_DAYS — confirmed
// directly against the live source before writing this file, not
// assumed to match. If Inspector's grace periods are ever changed,
// change this constant the same day, the same reasoning already
// documented for keeping the Apps Script fulfillment script's copy in
// sync with the client-side enforcement.
const LICENSE_GRACE_DAYS = { monthly: 3, annual: 7 };
const LICENSE_GRACE_DAYS_DEFAULT = 7;

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-License-Token",
  };
}
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders() },
  });
}

function tenantKey(companyId, key) {
  return `tenant:${companyId}:${key}`;
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function importLicensePublicKey() {
  return crypto.subtle.importKey(
    "spki",
    base64ToBytes(LICENSE_PUBLIC_KEY_B64),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
}

// The core trust boundary of this entire file — verifies a license
// token's signature independently, with the same algorithm and public
// key app.js already uses, and checks it isn't expired past its grace
// period. Returns the verified payload on success, or null on ANY
// failure. Callers must treat null as "reject the request" — never as
// "fall back to trusting a client-supplied field instead."
//
// Deliberately does NOT check revocation here, for the same reason
// Handyman's Worker doesn't: that would mean an outbound network call
// to the revocation endpoint on every single write. Revocation stays
// enforced client-side (the app's own gate) for now — server-side
// revocation enforcement here is a real, separate future step, not
// silently assumed to be covered.
async function verifyLicenseFull(token) {
  if (!token || typeof token !== "string" || !token.includes(".")) return null;
  const [payloadB64, sigB64] = token.split(".");
  if (!payloadB64 || !sigB64) return null;

  let payload, payloadStr;
  try {
    payloadStr = atob(payloadB64);
    payload = JSON.parse(payloadStr);
  } catch {
    return null;
  }

  try {
    const pubKey = await importLicensePublicKey();
    const sigBytes = base64ToBytes(sigB64);
    const payloadBytes = new TextEncoder().encode(payloadStr);
    const signatureOk = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", pubKey, sigBytes, payloadBytes);
    if (!signatureOk) return null;
  } catch {
    return null;
  }

  if (!payload.company_id || !payload.expiration_date) return null; // no company_id — pre-portal-era license, not eligible yet (see the patch doc)

  const expiresAt = new Date(`${payload.expiration_date}T23:59:59`);
  const now = new Date();
  const graceDays = LICENSE_GRACE_DAYS[payload.plan] != null ? LICENSE_GRACE_DAYS[payload.plan] : LICENSE_GRACE_DAYS_DEFAULT;
  const graceEndsAt = new Date(expiresAt.getTime() + graceDays * 24 * 60 * 60 * 1000);
  if (now > graceEndsAt) return null; // expired, even accounting for grace

  return {
    companyId: String(payload.company_id).slice(0, 60),
    clientName: payload.client_name ? String(payload.client_name).slice(0, 100) : null,
  };
}

async function verifyLicenseAndGetCompanyId(token) {
  const full = await verifyLicenseFull(token);
  return full ? full.companyId : null;
}

// Reads the license token from wherever the request put it — the
// X-License-Token header for the write, matching Handyman's own
// convention exactly.
async function getVerifiedCompanyId(request, body) {
  const headerToken = request.headers.get("X-License-Token");
  if (headerToken) return verifyLicenseAndGetCompanyId(headerToken);
  if (body && body.licenseToken) return verifyLicenseAndGetCompanyId(body.licenseToken);
  return null;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders() });
    }

    // ---------------- Publish a report (write) ----------------
    // The one write endpoint in this whole file. Requires a verified
    // license token — the company_id used to store this record always
    // comes from inside that verified token, never from the request
    // body, no matter what the body claims.
    if (request.method === "POST" && url.pathname === "/report") {
      let body;
      try {
        body = await request.json();
      } catch {
        return jsonResponse({ error: "Invalid JSON" }, 400);
      }
      const companyId = await getVerifiedCompanyId(request, body);
      if (!companyId) return jsonResponse({ error: "Unauthorized" }, 401);

      const { reportId, propertyName, visitDate, conditionScore, passCount, failCount, totalCount, photos, companyName, companyLogo } = body || {};
      if (!reportId || !visitDate) {
        return jsonResponse({ error: "reportId and visitDate are required" }, 400);
      }

      // Deliberately narrow — the same discipline as Handyman's invoice
      // endpoint stripping cost fields even if a caller sends them.
      // Never carries the raw item-by-item checklist, notes, vendor
      // contacts, or anything else not meant for the client's eyes.
      const cleanPhotos = Array.isArray(photos)
        ? photos.slice(0, 12).map((p) => ({
            url: p && p.url ? String(p.url).slice(0, 2000) : null, // expects an already-hosted URL (e.g. from the PDF's own image handling), not a raw data URL — keeps KV record sizes sane
            caption: p && p.caption ? String(p.caption).slice(0, 200) : "",
          })).filter((p) => p.url)
        : [];

      const record = {
        propertyName: propertyName ? String(propertyName).slice(0, 150) : null,
        visitDate: String(visitDate).slice(0, 20),
        conditionScore: conditionScore != null ? Math.max(0, Math.min(100, parseInt(conditionScore, 10) || 0)) : null,
        passCount: passCount != null ? parseInt(passCount, 10) || 0 : null,
        failCount: failCount != null ? parseInt(failCount, 10) || 0 : null,
        totalCount: totalCount != null ? parseInt(totalCount, 10) || 0 : null,
        photos: cleanPhotos,
        companyName: companyName ? String(companyName).slice(0, 100) : null,
        companyLogo: companyLogo ? String(companyLogo).slice(0, 500000) : null, // a small logo data URL is fine; a full-size report photo set is not — that's what `photos[].url` is for
        publishedAt: Date.now(),
      };
      await env.PORTAL_KV.put(tenantKey(companyId, `report:${String(reportId).slice(0, 100)}`), JSON.stringify(record), {
        expirationTtl: REPORT_TTL_SECONDS,
      });
      return jsonResponse({ ok: true });
    }

    // ---------------- View a report (public read) ----------------
    // Same shape as Handyman's /invoice and /status endpoints: an
    // unguessable ID plus a company_id to locate the right tenant, no
    // login needed. A client viewing their own home's report has no
    // account here, the same way a client paying an invoice through
    // Handyman's Worker doesn't.
    if (request.method === "GET" && url.pathname === "/report") {
      const id = url.searchParams.get("id");
      const companyId = url.searchParams.get("biz");
      if (!id || !companyId) return jsonResponse({ error: "Missing id or biz" }, 400);

      const record = await env.PORTAL_KV.get(tenantKey(companyId, `report:${id}`), "json");
      if (!record) return jsonResponse({ error: "Not found" }, 404);

      return jsonResponse(record);
    }

    return jsonResponse({ error: "Not found" }, 404);
  },
};
