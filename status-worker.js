// Assured Handyman — status sync + submission log Worker
// MULTI-TENANT VERSION — one shared deployment serves every customer.
// ============================================================
//
// WHY THIS FILE CHANGED SHAPE: originally one Worker per customer, each
// with its own shared secret. Moving to one central Worker for everyone
// meant every record needed a real tenant boundary — see
// Multi-Tenant-Architecture-Scoping.md for the full reasoning. The
// short version: every KV key is now prefixed `tenant:<companyId>:...`,
// and every write that used to trust a shared secret now verifies the
// requester's actual signed license token instead — the Worker
// independently checks the same RSA signature the app itself checks,
// using the same public key, and trusts nothing else about who's
// asking. This is the single most important property of this file:
// a company_id supplied as a bare parameter is NEVER enough to write
// data — it has to come from inside a signature that verifies.
//
// THREE TOKEN ROLES (added: "portal", alongside "owner" and "crew") —
// a real, signed license token now carries one of three roles:
//   - "owner": full access, including crew-roster writes
//   - "crew": full read/write access to everything EXCEPT crew-roster
//     writes (same as before this change — unchanged)
//   - "portal": a deliberately narrow Portal Access Key, scoped to
//     EXACTLY two endpoints (GET /statuses, GET /submissions) and
//     nothing else in this entire file. Added specifically so a Jobs
//     Portal admin — who may not be an employee of the business at
//     all — never needs to hold a credential capable of activating a
//     paid Assured Handyman app instance or writing anything. See
//     verifyLicenseAndGetCompanyId vs. verifyPortalReadCompanyId
//     below for the actual enforcement; every write endpoint and
//     every other read in this file uses the former, which explicitly
//     rejects role:"portal".
//
// A FOURTH ACCESS PATTERN, not a token role — GET /my-jobs is public
// and unauthenticated ENTIRELY BY NECESSITY: a real customer has no
// license of any kind and never will. Added so a customer who isn't
// the business's employee can check their own job status without a
// private per-job link, by supplying their own name + phone number
// together (matched against what's already on file for their job, not
// treated as a password). This is a deliberately different, weaker
// guarantee than the trackingId-based /status lookup elsewhere in this
// file (that one's effectively unguessable; a name+phone pair is not),
// mitigated by requiring an exact match on both fields together, a
// stricter dedicated rate limit than any other endpoint, and a
// response that discloses only status/date/company name — nothing an
// admin-only view would show. Revisit this endpoint's design first if
// this business ever wants real customer accounts.
//
// TWO TRUST LEVELS, same as before, now tenant-aware:
//
// STATUS SYNC (/update, /status, /statuses) — /update requires a valid
// license token (company_id is taken from the verified token, not
// trusted from the request). /status (single lookup) is public by
// design, same as always — a tracking ID is unguessable, and now also
// needs the company_id to locate the right tenant's record (carried in
// the tracking link itself, same pattern already used for the Worker
// URL). /statuses (the FULL admin list) requires a valid license token.
//
// SUBMISSION LOG (/submission, /submissions) — /submission stays a
// public write, same reasoning as always: a "secret" embedded in
// public Jobs Portal code was never a real secret. It now also
// requires a company_id (supplied by the Portal, since the Portal
// knows which company it represents) so a submission lands in the
// right tenant's bucket — this is NOT authenticated, matching the
// pre-existing threat model exactly (anyone could always fake a
// submission; that hasn't changed). Reading the list back requires a
// valid license token.
//
// CATALOG (/catalog) and AVAILABILITY (/availability) — reads are
// public (they mirror what a Jobs Portal visitor already sees), scoped
// by a company_id query param. Writes require a valid license token.
//
// INVOICE PAY PAGE (/invoice) — a deliberate, disclosed expansion of
// what this Worker shares (see PROJECT_HANDOFF.md Section 2). Reads
// are public by design, same shape as status tracking: an unguessable
// payTrackingId plus a company_id to locate the tenant, no login
// needed, since a client paying an invoice has no account here. What
// gets exposed is intentionally narrow: invoice number, company name,
// total due, paid status, however the handyman wants to get paid —
// either a one-off checkout link (paymentLink) or their own linked
// PayPal/Venmo/Cash App/Zelle handles (paymentOptions) — and, if this
// invoice requires one, the deposit amount and whether it's been
// received (depositAmount/depositReceived). Never the itemized line
// items, materials, or anything else about the invoice — those stay
// private to the app. Writes require a valid license token, same as
// every other write endpoint.
//
// CREW TIME TRACKING (/time-entry, /time-entries) — the one endpoint
// pair in this whole file with NO public read at all. Labor hours are
// internal business data, not something an unguessable ID alone should
// expose the way a client's own invoice or job status can. Both
// reading and writing require a valid license token. This is also the
// one deliberate exception to "devices don't sync" for this kind of
// data (same category of decision as the pay page was for payment
// info): a crew member's own device writes their clock-in/clock-out,
// and the lead handyman's device reads back every crew member's
// entries for this tenant — cross-device visibility, on purpose, for
// this one specific thing. No TTL on these records, same as invoices
// and the catalog — real records, not ephemeral state.
//
// CREW LICENSE ROSTER (/crew-seat, /crew-seats, /crew-seat-status) —
// Phase 1 of real crew licensing. This Worker can never mint a new
// signed license (the private key lives only in the offline license
// generator, on purpose) — what it CAN do is track which
// already-issued seats are currently active vs. revoked, so a Lead can
// self-serve fire/reassign crew without contacting the reseller for
// every change. Writing to the roster (/crew-seat, and reading the
// full list via /crew-seats) requires a license token whose signed
// payload has role:"owner" — a valid Crew Member token is NOT enough,
// this is the one place in the file where token validity alone doesn't
// grant access. Checking a single seat's status (/crew-seat-status) is
// public, same "unguessable ID is the real access control" reasoning
// as status tracking — this is what a crew member's own device pings
// to check whether it's been revoked.
//
// WORK-ORDER ROUTING (/routed-job, /routed-jobs) — Phase 2 of crew
// licensing, built on top of Phase 1's real crew identities. Carries a
// deliberately narrow slice of a work order to a crew member's own
// device: client name/phone, address, schedule, and services/materials
// WITHOUT pricing — confirmed explicitly, no cost data crosses this
// endpoint at all, even if a caller's payload includes it (stripped
// server-side, not just trusted to be absent). Any valid license token
// can read the full company-wide list or write a routed job — same
// permission shape as time entries, not a stricter one invented just
// for this. No TTL; a job is explicitly deleted (unassigned or done)
// rather than left to expire.
//
// INVENTORY BY LOCATION (/inventory-item, /inventory-items) — Phase 3
// of crew licensing. The one dataset in this whole file that's meant
// to be genuinely cross-device EDITABLE, not just cross-device
// readable — a crew member adjusts their own truck's count from their
// own device, the Lead adjusts the warehouse from theirs, each needs
// to see the other's numbers. Last-write-wins on a conflicting edit to
// the same item — accepted, not solved, same as this project's other
// shared-storage limitations. Any valid license token can read or
// write, same permission shape as time entries and routed jobs.
//
// RATE LIMITING — /submission is the one endpoint that stays open to
// literally anyone, which means it's also the one endpoint that could
// be used to exhaust shared quota affecting every tenant at once on a
// multi-tenant Worker. Uses Cloudflare's native Rate Limiting binding
// (not a KV-based counter — that would burn through the very tight
// 1,000-writes/day KV quota just to police itself).
//
// The ONLY server-side piece in this whole system. Everything else —
// every contact, invoice, work order, price, photo — stays on each
// handyman's own device, exactly as it always has.

const STATUS_TTL_SECONDS = 60 * 60 * 24 * 90; // 90 days
const SUBMISSION_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days
const MAX_SUBMISSIONS_RETURNED = 50;
const MAX_STATUSES_RETURNED = 100;
const MAX_TIME_ENTRIES_RETURNED = 500;
const INVOICE_TTL_SECONDS = 60 * 60 * 24 * 180; // 180 days

// Same public key embedded in the app (app.js: LICENSE_PUBLIC_KEY_B64).
// Must stay in sync if the keypair is ever rotated — the private key
// itself never appears anywhere in this file or any server.
const LICENSE_PUBLIC_KEY_B64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwsExbY+9LuAcp7oDoSbN8GAWjNW6AFN14xQdTt64n9y3khFInrrTCUsxvu6gp0JoYS/B2OQA9yjXiERZU/66xtnSyFP+0+9+lv/Mf5FUVNQ6OkXqKd4aPHuaaZ/oVjOVJpp21JkRDzw090AVlFmP119MGru/iwjkSWMzKqar+dysQDHhqd+39uRIJllsU4gtTWCFqGIX0FgO0wTZS6Imw5df1S/a1m9PJDSQPEvuWO7Q3EDiNPaac82RVZDsKrrY0qtFG2/5xmi2kvkipGVr9M9a79njgTKY+SLd36uXSJIlz2EUIbt3YW2dOMKoBOZTpDmXwiSfOe1TqJbPIj+btwIDAQAB";
const LICENSE_GRACE_DAYS = { monthly: 3, annual: 7 };
const LICENSE_GRACE_DAYS_DEFAULT = 7;

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-License-Token"
  };
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders() }
  });
}

// Every KV record in this multi-tenant Worker lives under this prefix.
// Nothing reads or writes a bare, unprefixed key anymore.
function tenantKey(companyId, key) {
  return `tenant:${companyId}:${key}`;
}

// Some Worker secret bindings (Secrets Store) hand back an object with
// an async .get() method rather than a plain string — a real bug this
// project hit once already (Session 64). Resolved defensively here so
// it can never silently fail to match again, regardless of which
// binding type gets configured. Kept even though this file no longer
// uses a shared secret for tenant auth, in case a future endpoint
// (e.g. an admin-only maintenance route) needs one.
async function resolveSecret(binding) {
  if (!binding) return null;
  if (typeof binding === "string") return binding;
  if (typeof binding.get === "function") return await binding.get();
  return null;
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

// The core trust boundary of this entire file. Verifies a license
// token's signature independently (same algorithm, same public key the
// app itself uses) and checks it isn't expired past its grace period.
// Returns the verified company_id on success, or null on ANY failure —
// callers must treat null as "reject the request," never as "fall back
// to trusting a client-supplied company_id instead." Deliberately does
// NOT check revocation here — that would mean an outbound network call
// to the revocation endpoint on every single write, which is both slow
// and works against the "don't hammer KV/external services on the hot
// path" discipline this project already follows. Revocation stays
// enforced client-side (the app's own gate) for now; server-side
// revocation enforcement is a real, separate future step, not silently
// assumed to be covered here.
// The core trust boundary of this entire file. Verifies a license
// token's signature independently (same algorithm, same public key the
// app itself uses) and checks it isn't expired past its grace period.
// Returns the full verified payload on success, or null on ANY
// failure — callers must treat null as "reject the request," never as
// "fall back to trusting client-supplied fields instead." Deliberately
// does NOT check revocation here — that would mean an outbound network
// call to the revocation endpoint on every single write, which is both
// slow and works against the "don't hammer KV/external services on the
// hot path" discipline this project already follows. Revocation stays
// enforced client-side (the app's own gate, plus the crew-seat status
// added for Phase 1 of crew licensing) for now.
async function verifyLicenseFull(token) {
  if (!token || typeof token !== "string" || !token.includes(".")) return null;
  const [payloadB64, sigB64] = token.split(".");
  if (!payloadB64 || !sigB64) return null;

  let payload, payloadStr;
  try {
    payloadStr = atob(payloadB64);
    payload = JSON.parse(payloadStr);
  } catch (e) {
    return null;
  }

  try {
    const pubKey = await importLicensePublicKey();
    const sigBytes = base64ToBytes(sigB64);
    const payloadBytes = new TextEncoder().encode(payloadStr);
    const signatureOk = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", pubKey, sigBytes, payloadBytes);
    if (!signatureOk) return null;
  } catch (e) {
    return null;
  }

  if (!payload.company_id || !payload.expiration_date) return null;

  const expiresAt = new Date(`${payload.expiration_date}T23:59:59`);
  const now = new Date();
  const graceDays = LICENSE_GRACE_DAYS[payload.plan] != null ? LICENSE_GRACE_DAYS[payload.plan] : LICENSE_GRACE_DAYS_DEFAULT;
  const graceEndsAt = new Date(expiresAt.getTime() + graceDays * 24 * 60 * 60 * 1000);
  if (now > graceEndsAt) return null; // expired, even accounting for grace

  return {
    companyId: String(payload.company_id).slice(0, 60),
    pairingCode: payload.pairing_code ? String(payload.pairing_code).slice(0, 40) : null,
    // "portal" is a real, distinct third role (added alongside the
    // Portal Access Key fix) — a credential scoped to Jobs Portal
    // read-only admin views, deliberately NOT recognized anywhere a
    // real license activation is checked (that check lives in the app
    // itself, not here — see app.js's checkLicenseGate). Anything
    // genuinely unrecognized still safely defaults to "crew", same as
    // before.
    role: payload.role === "owner" ? "owner" : payload.role === "portal" ? "portal" : "crew",
    clientName: payload.client_name ? String(payload.client_name).slice(0, 100) : null
  };
}

// General-purpose verifier used by every write endpoint and every
// non-public read in this file. Deliberately excludes role:"portal" —
// a Portal Access Key can read submissions/statuses (see
// verifyPortalReadCompanyId below) and NOTHING else. This is the
// actual security boundary: a Portal Access Key handed to someone who
// only manages the Jobs Portal (who may not even work for the
// business) must never be able to write an invoice, adjust inventory,
// touch the crew roster, or anything else a "crew" token can do.
async function verifyLicenseAndGetCompanyId(token) {
  const full = await verifyLicenseFull(token);
  if (!full) return null;
  if (full.role === "portal") return null;
  return full.companyId;
}

// Read-only verifier for the two Jobs-Portal-admin views (Open Work
// Orders, Recent Requests) ONLY. Accepts owner, crew, OR portal roles
// — a portal-role token is scoped to exactly these two reads and
// nothing in the rest of this file, enforced by every other call site
// continuing to use verifyLicenseAndGetCompanyId above, not this one.
async function verifyPortalReadCompanyId(token) {
  const full = await verifyLicenseFull(token);
  return full ? full.companyId : null;
}

async function getVerifiedPortalReadCompanyId(request, body) {
  const headerToken = request.headers.get("X-License-Token");
  if (headerToken) return verifyPortalReadCompanyId(headerToken);
  if (body && body.licenseToken) return verifyPortalReadCompanyId(body.licenseToken);
  return null;
}

// Same shape as verifyLicenseAndGetCompanyId, but additionally requires
// the token's own role to be "owner" — used to gate crew-roster writes
// (only the Lead's own device should be able to revoke/reassign seats).
// Returns null for a genuinely invalid token OR a valid-but-crew-role
// token — callers can't distinguish the two from the return value
// alone, which is intentional: "unauthorized" shouldn't leak *why*.
async function verifyOwnerAndGetCompanyId(token) {
  const full = await verifyLicenseFull(token);
  if (!full || full.role !== "owner") return null;
  return full.companyId;
}

// Reads the license token from wherever the request put it — the
// X-License-Token header for GET/DELETE, or a licenseToken field in a
// JSON POST body — and resolves it to a verified company_id, or null.
async function getVerifiedCompanyId(request, body) {
  const headerToken = request.headers.get("X-License-Token");
  if (headerToken) return verifyLicenseAndGetCompanyId(headerToken);
  if (body && body.licenseToken) return verifyLicenseAndGetCompanyId(body.licenseToken);
  return null;
}

async function getVerifiedOwnerCompanyId(request, body) {
  const headerToken = request.headers.get("X-License-Token");
  if (headerToken) return verifyOwnerAndGetCompanyId(headerToken);
  if (body && body.licenseToken) return verifyOwnerAndGetCompanyId(body.licenseToken);
  return null;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders() });
    }

    // ---------------- Status sync ----------------
    // Public read — the tracking ID is still the real access control
    // (16 random bytes, unguessable), same as before. Now also needs
    // the company_id to locate the right tenant's copy of the record —
    // carried in the tracking link itself (the &biz= param), same
    // pattern already used for the Worker URL (&w=).
    if (request.method === "GET" && url.pathname === "/status") {
      const id = url.searchParams.get("id");
      const companyId = url.searchParams.get("biz");
      if (!id || !companyId) return jsonResponse({ error: "Missing id or biz" }, 400);

      const record = await env.STATUS_KV.get(tenantKey(companyId, `status:${id}`), "json");
      if (!record) return jsonResponse({ error: "Not found" }, 404);

      return jsonResponse({
        status: record.status,
        scheduledDate: record.scheduledDate || null,
        companyName: record.companyName || null,
        serviceType: record.serviceType || null,
        description: record.description || null,
        updatedAt: record.updatedAt
      });
    }

    if (request.method === "POST" && url.pathname === "/update") {
      let body;
      try {
        body = await request.json();
      } catch (e) {
        return jsonResponse({ error: "Invalid JSON" }, 400);
      }
      const companyId = await getVerifiedCompanyId(request, body);
      if (!companyId) return jsonResponse({ error: "Unauthorized" }, 401);

      const { trackingId, status, scheduledDate, companyName, clientName, clientPhone, assignedTo, serviceType, description } = body || {};
      if (!trackingId || !status) {
        return jsonResponse({ error: "trackingId and status are required" }, 400);
      }
      const record = {
        status: String(status).slice(0, 60),
        scheduledDate: scheduledDate ? String(scheduledDate).slice(0, 20) : null,
        companyName: companyName ? String(companyName).slice(0, 100) : null,
        clientName: clientName ? String(clientName).slice(0, 100) : null,
        // Digits-only, normalized once here at write time rather than at
        // every read — the new public /my-jobs lookup below matches on
        // this. Never echoed back by any endpoint a client can reach;
        // it exists only to be matched against, not displayed.
        clientPhone: clientPhone ? String(clientPhone).replace(/\D/g, "").slice(0, 20) : null,
        // Added alongside the Jobs Portal's dedicated work-orders-by-
        // crew-member view — same disclosed-expansion pattern already
        // used for clientName above (see this file's own header). The
        // public /status lookup a client uses to check their own job
        // still never echoes this back, only the admin-only /statuses
        // listing does.
        assignedTo: assignedTo ? String(assignedTo).slice(0, 100) : null,
        // serviceType/description added Session 107 — the client's own
        // job title/description, safe to echo straight back to them: it's
        // either their own selection from the request form or their own
        // typed text, not internal business notes.
        serviceType: serviceType ? String(serviceType).slice(0, 150) : null,
        description: description ? String(description).slice(0, 500) : null,
        updatedAt: Date.now()
      };

      await env.STATUS_KV.put(tenantKey(companyId, `status:${String(trackingId).slice(0, 64)}`), JSON.stringify(record), {
        expirationTtl: STATUS_TTL_SECONDS
      });
      return jsonResponse({ ok: true });
    }

    // Admin-only — every currently-tracked job for THIS tenant, for the
    // Jobs Portal's "Open Work Orders" screen. Requires a valid license
    // token; the company_id it resolves to is what scopes the list —
    // there is no way to request another tenant's list even by editing
    // the request, since the company_id is never taken from anywhere
    // the caller directly controls.
    if (request.method === "GET" && url.pathname === "/statuses") {
      // Uses the portal-read verifier deliberately — this is one of
      // exactly two endpoints a scoped Portal Access Key can reach.
      const companyId = await getVerifiedPortalReadCompanyId(request, null);
      if (!companyId) return jsonResponse({ error: "Unauthorized" }, 401);

      const prefix = tenantKey(companyId, "status:");
      const list = await env.STATUS_KV.list({ prefix, limit: MAX_STATUSES_RETURNED });
      const results = await Promise.all(
        list.keys.map(async (k) => {
          const record = await env.STATUS_KV.get(k.name, "json");
          return record ? { trackingId: k.name.slice(prefix.length), ...record } : null;
        })
      );
      const statuses = results.filter(Boolean).sort((a, b) => b.updatedAt - a.updatedAt);
      return jsonResponse({ statuses });
    }

    // ---------------- Client self-lookup by name + phone ----------------
    // Public, unauthenticated by design — a real customer has no license
    // token and never will, so this can't be gated the way /statuses is.
    // The privacy boundary here is BOTH name AND phone matching exactly,
    // not either alone: a phone number by itself is guessable (unlike the
    // random trackingId /status uses), so requiring the paired name too
    // meaningfully raises the bar without needing a real login system.
    // RATE LIMITED, and more conservatively than /submission — this
    // endpoint's whole purpose is comparing caller-supplied values
    // against stored ones, which makes it the more natural target for
    // exactly the kind of repeated-guessing abuse rate limiting exists
    // to blunt. Uses its own separate binding so a burst of legitimate
    // form submissions elsewhere can never eat into this budget or vice
    // versa. Response is deliberately narrow — status, date, company
    // name only. No assignedTo, no clientPhone echoed back, nothing a
    // customer doesn't need to see their own job's status.
    if (request.method === "GET" && url.pathname === "/my-jobs") {
      if (env.MY_JOBS_RATE_LIMITER) {
        const ip = request.headers.get("CF-Connecting-IP") || "unknown";
        const { success } = await env.MY_JOBS_RATE_LIMITER.limit({ key: ip });
        if (!success) {
          return jsonResponse({ error: "Too many requests — please try again shortly" }, 429);
        }
      }

      const companyId = url.searchParams.get("biz");
      const nameParam = (url.searchParams.get("name") || "").trim().toLowerCase();
      const phoneParam = (url.searchParams.get("phone") || "").replace(/\D/g, "");
      if (!companyId || !nameParam || !phoneParam) {
        return jsonResponse({ error: "biz, name, and phone are all required" }, 400);
      }

      const prefix = tenantKey(companyId, "status:");
      const list = await env.STATUS_KV.list({ prefix, limit: MAX_STATUSES_RETURNED });
      const results = await Promise.all(
        list.keys.map(async (k) => {
          const record = await env.STATUS_KV.get(k.name, "json");
          return record ? { trackingId: k.name.slice(prefix.length), ...record } : null;
        })
      );
      // trackingId disclosed here as of Session 107 — a deliberate, narrow
      // expansion of this endpoint's response, not an accident. It's the
      // SAME unguessable ID /status already requires to read this exact
      // record, so a customer who already passed the name+phone check gets
      // handed the key to the fuller track.html detail view for their own
      // job, rather than a dead-end headline. Nothing new is exposed that
      // /status wouldn't already reveal to anyone holding this ID.
      const matches = results
        .filter(Boolean)
        .filter((r) =>
          r.clientName && r.clientName.trim().toLowerCase() === nameParam &&
          r.clientPhone && r.clientPhone === phoneParam
        )
        .map((r) => ({
          trackingId: r.trackingId,
          status: r.status,
          scheduledDate: r.scheduledDate,
          companyName: r.companyName,
          serviceType: r.serviceType || null,
          updatedAt: r.updatedAt
        }))
        .sort((a, b) => b.updatedAt - a.updatedAt);

      return jsonResponse({ jobs: matches });
    }

    // ---------------- Invoice pay page ----------------
    // Same shape as status tracking: unguessable ID plus a company_id
    // to locate the tenant, no login needed.
    if (request.method === "GET" && url.pathname === "/invoice") {
      const id = url.searchParams.get("id");
      const companyId = url.searchParams.get("biz");
      if (!id || !companyId) return jsonResponse({ error: "Missing id or biz" }, 400);
      const record = await env.STATUS_KV.get(tenantKey(companyId, `invoice:${id}`), "json");
      if (!record) return jsonResponse({ error: "Not found" }, 404);
      return jsonResponse({
        invoiceNumber: record.invoiceNumber,
        companyName: record.companyName,
        totalDue: record.totalDue,
        paymentLink: record.paymentLink || null,
        paymentOptions: record.paymentOptions || null,
        qrCodeDataUrl: record.qrCodeDataUrl || null,
        paid: !!record.paid,
        depositAmount: record.depositAmount || null,
        depositReceived: !!record.depositReceived,
        updatedAt: record.updatedAt
      });
    }

    if (request.method === "POST" && url.pathname === "/invoice") {
      let body;
      try {
        body = await request.json();
      } catch (e) {
        return jsonResponse({ error: "Invalid JSON" }, 400);
      }
      const companyId = await getVerifiedCompanyId(request, body);
      if (!companyId) return jsonResponse({ error: "Unauthorized" }, 401);

      const { payTrackingId, invoiceNumber, companyName, totalDue, paymentLink, paymentOptions, qrCodeDataUrl, paid, depositAmount, depositReceived } = body || {};
      if (!payTrackingId || !invoiceNumber) {
        return jsonResponse({ error: "payTrackingId and invoiceNumber are required" }, 400);
      }
      // paymentOptions carries the handyman's own linked payment
      // accounts (PayPal/Venmo/Cash App/Zelle) — same trust level as
      // paymentLink, capped the same way, only the 4 known keys kept
      // so an unexpected field can't quietly grow storage over time.
      let cleanedPaymentOptions = null;
      if (paymentOptions && typeof paymentOptions === "object") {
        const allowedKeys = ["paypal", "venmo", "cashapp", "zelle"];
        cleanedPaymentOptions = {};
        for (const key of allowedKeys) {
          const val = paymentOptions[key];
          if (val) cleanedPaymentOptions[key] = String(val).slice(0, 200);
        }
        if (Object.keys(cleanedPaymentOptions).length === 0) cleanedPaymentOptions = null;
      }
      const record = {
        invoiceNumber: String(invoiceNumber).slice(0, 30),
        companyName: companyName ? String(companyName).slice(0, 100) : null,
        totalDue: totalDue ? String(totalDue).slice(0, 20) : null,
        paymentLink: paymentLink ? String(paymentLink).slice(0, 500) : null,
        paymentOptions: cleanedPaymentOptions,
        qrCodeDataUrl: qrCodeDataUrl ? String(qrCodeDataUrl).slice(0, 500000) : null,
        paid: !!paid,
        depositAmount: depositAmount ? parseFloat(depositAmount) || null : null,
        depositReceived: !!depositReceived,
        updatedAt: Date.now()
      };
      await env.STATUS_KV.put(tenantKey(companyId, `invoice:${String(payTrackingId).slice(0, 64)}`), JSON.stringify(record), {
        expirationTtl: INVOICE_TTL_SECONDS
      });
      return jsonResponse({ ok: true });
    }

    // ---------------- Catalog sync ----------------
    // Public read, scoped by company_id query param — mirrors what that
    // company's Jobs Portal visitors already see anyway.
    if (request.method === "GET" && url.pathname === "/catalog") {
      const companyId = url.searchParams.get("biz");
      if (!companyId) return jsonResponse({ error: "Missing biz" }, 400);
      const record = await env.STATUS_KV.get(tenantKey(companyId, "catalog:categories"), "json");
      return jsonResponse({ categories: (record && record.categories) || [] });
    }

    if (request.method === "POST" && url.pathname === "/catalog") {
      let body;
      try {
        body = await request.json();
      } catch (e) {
        return jsonResponse({ error: "Invalid JSON" }, 400);
      }
      const companyId = await getVerifiedCompanyId(request, body);
      if (!companyId) return jsonResponse({ error: "Unauthorized" }, 401);

      const categories = Array.isArray(body && body.categories) ? body.categories : null;
      if (!categories) return jsonResponse({ error: "categories array is required" }, 400);

      const cleaned = categories.slice(0, 50).map((c) => ({
        name: String(c.name || "").slice(0, 100),
        icon: String(c.icon || "fa-screwdriver-wrench").slice(0, 60),
        bg: String(c.bg || "bg-slate-500/15").slice(0, 60),
        text: String(c.text || "text-slate-300").slice(0, 60)
      })).filter((c) => c.name);

      await env.STATUS_KV.put(tenantKey(companyId, "catalog:categories"), JSON.stringify({ categories: cleaned, updatedAt: Date.now() }));
      return jsonResponse({ ok: true });
    }

    // ---------------- Offered time windows ----------------
    if (request.method === "GET" && url.pathname === "/availability") {
      const companyId = url.searchParams.get("biz");
      if (!companyId) return jsonResponse({ error: "Missing biz" }, 400);
      const record = await env.STATUS_KV.get(tenantKey(companyId, "availability:windows"), "json");
      return jsonResponse({ windows: (record && record.windows) || [] });
    }

    if (request.method === "POST" && url.pathname === "/availability") {
      let body;
      try {
        body = await request.json();
      } catch (e) {
        return jsonResponse({ error: "Invalid JSON" }, 400);
      }
      const companyId = await getVerifiedCompanyId(request, body);
      if (!companyId) return jsonResponse({ error: "Unauthorized" }, 401);

      const windows = Array.isArray(body && body.windows) ? body.windows : null;
      if (!windows) return jsonResponse({ error: "windows array is required" }, 400);

      const cleaned = windows.slice(0, 30).map((w) => ({
        id: String(w.id || "").slice(0, 40),
        label: String(w.label || "").slice(0, 100),
        note: String(w.note || "").slice(0, 200)
      })).filter((w) => w.label);

      await env.STATUS_KV.put(tenantKey(companyId, "availability:windows"), JSON.stringify({ windows: cleaned, updatedAt: Date.now() }));
      return jsonResponse({ ok: true });
    }

    // ---------------- Submission log ----------------
    // Public write, unchanged trust level — a "secret" in public Jobs
    // Portal code was never real security. Now also requires a
    // company_id, supplied directly by the Portal (it always knows
    // which company it represents from its own URL) — NOT verified
    // against a license, since there's no license to check on a public
    // write. This doesn't reduce security versus the old single-tenant
    // design: a bad actor could always fake a submission before, and
    // still can now; the only new property is that a fake submission
    // lands in one specific tenant's bucket instead of the only one
    // that existed.
    //
    // RATE LIMITED — this is the one endpoint any anonymous visitor can
    // hit, on a Worker now shared by every tenant, which makes it the
    // one place abuse of one tenant's form could degrade service for
    // everyone. Uses Cloudflare's native Rate Limiting binding (not a
    // KV counter — that would burn KV's own tight write quota just to
    // police itself). Keyed by IP, not company_id, since a single bad
    // actor could otherwise just rotate the company_id to dodge a
    // per-tenant limit.
    if (request.method === "POST" && url.pathname === "/submission") {
      if (env.SUBMISSION_RATE_LIMITER) {
        const ip = request.headers.get("CF-Connecting-IP") || "unknown";
        const { success } = await env.SUBMISSION_RATE_LIMITER.limit({ key: ip });
        if (!success) {
          return jsonResponse({ error: "Too many requests — please try again shortly" }, 429);
        }
      }

      let body;
      try {
        body = await request.json();
      } catch (e) {
        return jsonResponse({ error: "Invalid JSON" }, 400);
      }

      if (body && body.botField) {
        return jsonResponse({ ok: true });
      }

      const companyId = (body && body.companyId || "").toString().trim();
      const name = (body && body.name || "").toString().trim();
      const phone = (body && body.phone || "").toString().trim();
      const email = (body && body.email || "").toString().trim();
      if (!companyId) return jsonResponse({ error: "companyId is required" }, 400);
      if (!name || (!phone && !email)) {
        return jsonResponse({ error: "name and (phone or email) are required" }, 400);
      }

      const record = {
        name: name.slice(0, 100),
        phone: phone.slice(0, 30),
        email: email.slice(0, 100),
        address: (body.address || "").toString().slice(0, 200),
        serviceType: (body.serviceType || "").toString().slice(0, 100),
        description: (body.description || "").toString().slice(0, 1000),
        when: (body.when || "").toString().slice(0, 50),
        preferredDate: (body.preferredDate || "").toString().slice(0, 20),
        preferredWindow: (body.preferredWindow || "").toString().slice(0, 100),
        preferredHandyman: (body.preferredHandyman || "").toString().slice(0, 100),
        isRecurring: !!body.isRecurring,
        cadence: (body.cadence || "").toString().slice(0, 20),
        routedTo: (body.routedTo || "").toString().slice(0, 100),
        hadPhotoAttachment: !!body.hadPhotoAttachment,
        submittedAt: Date.now()
      };

      const key = tenantKey(companyId, `submission:${Date.now()}:${crypto.randomUUID()}`);
      await env.STATUS_KV.put(key, JSON.stringify(record), { expirationTtl: SUBMISSION_TTL_SECONDS });
      return jsonResponse({ ok: true });
    }

    // Read — requires a valid license token, scoped to that tenant's
    // own submissions only.
    if (request.method === "GET" && url.pathname === "/submissions") {
      // Same reasoning as /statuses above — the other of the two
      // endpoints a scoped Portal Access Key is allowed to reach.
      const companyId = await getVerifiedPortalReadCompanyId(request, null);
      if (!companyId) return jsonResponse({ error: "Unauthorized" }, 401);

      const prefix = tenantKey(companyId, "submission:");
      const list = await env.STATUS_KV.list({ prefix, limit: MAX_SUBMISSIONS_RETURNED });
      const results = await Promise.all(
        list.keys.map(async (k) => {
          const record = await env.STATUS_KV.get(k.name, "json");
          return record ? { key: k.name, ...record } : null;
        })
      );
      const submissions = results.filter(Boolean).sort((a, b) => b.submittedAt - a.submittedAt);
      return jsonResponse({ submissions });
    }

    if (request.method === "DELETE" && url.pathname === "/submission") {
      const companyId = await getVerifiedCompanyId(request, null);
      if (!companyId) return jsonResponse({ error: "Unauthorized" }, 401);

      const key = url.searchParams.get("key");
      const expectedPrefix = tenantKey(companyId, "submission:");
      if (!key || !key.startsWith(expectedPrefix)) {
        return jsonResponse({ error: "Missing or invalid key" }, 400);
      }
      await env.STATUS_KV.delete(key);
      return jsonResponse({ ok: true });
    }

    // ---------------- Crew time tracking ----------------
    // A deliberate, disclosed expansion of this Worker's scope (see
    // PROJECT_HANDOFF.md Section 2 and this file's own header) — the
    // first case where the Worker relays something genuinely private
    // (labor hours) rather than client-facing status/payment info.
    // Every read AND write requires a valid license token; unlike
    // status tracking or the pay page, there is no public read here at
    // all — a crew member's hours are internal business data, not
    // something an unguessable ID alone should expose. No TTL, same as
    // invoices/catalog — these are real records, not ephemeral state.
    if (request.method === "POST" && url.pathname === "/time-entry") {
      let body;
      try {
        body = await request.json();
      } catch (e) {
        return jsonResponse({ error: "Invalid JSON" }, 400);
      }
      const companyId = await getVerifiedCompanyId(request, body);
      if (!companyId) return jsonResponse({ error: "Unauthorized" }, 401);

      const { id, crewMemberName, workOrderId, workOrderLabel, clockInTs, clockOutTs, notes } = body || {};
      if (!id || !crewMemberName || !clockInTs) {
        return jsonResponse({ error: "id, crewMemberName, and clockInTs are required" }, 400);
      }
      const record = {
        crewMemberName: String(crewMemberName).slice(0, 100),
        workOrderId: workOrderId ? String(workOrderId).slice(0, 100) : null,
        workOrderLabel: workOrderLabel ? String(workOrderLabel).slice(0, 200) : null,
        clockInTs: parseInt(clockInTs, 10),
        clockOutTs: clockOutTs ? parseInt(clockOutTs, 10) : null,
        notes: notes ? String(notes).slice(0, 500) : null,
        updatedAt: Date.now()
      };
      await env.STATUS_KV.put(tenantKey(companyId, `time:${String(id).slice(0, 64)}`), JSON.stringify(record));
      return jsonResponse({ ok: true });
    }

    // Every crew member's hours for this tenant — this is the actual
    // point of the feature: a lead handyman's device didn't record most
    // of these entries itself, they came from crew members' own
    // separate devices. This is the one deliberate exception to
    // "devices don't sync" for this kind of data, same as the pay page
    // is the deliberate exception for invoice/payment info.
    if (request.method === "GET" && url.pathname === "/time-entries") {
      const companyId = await getVerifiedCompanyId(request, null);
      if (!companyId) return jsonResponse({ error: "Unauthorized" }, 401);

      const prefix = tenantKey(companyId, "time:");
      const list = await env.STATUS_KV.list({ prefix, limit: MAX_TIME_ENTRIES_RETURNED });
      const results = await Promise.all(
        list.keys.map(async (k) => {
          const record = await env.STATUS_KV.get(k.name, "json");
          return record ? { id: k.name.slice(prefix.length), ...record } : null;
        })
      );
      const entries = results.filter(Boolean).sort((a, b) => b.clockInTs - a.clockInTs);
      return jsonResponse({ entries });
    }

    if (request.method === "DELETE" && url.pathname === "/time-entry") {
      const companyId = await getVerifiedCompanyId(request, null);
      if (!companyId) return jsonResponse({ error: "Unauthorized" }, 401);

      const id = url.searchParams.get("id");
      if (!id) return jsonResponse({ error: "Missing id" }, 400);
      await env.STATUS_KV.delete(tenantKey(companyId, `time:${String(id).slice(0, 64)}`));
      return jsonResponse({ ok: true });
    }

    // ---------------- Crew license roster (Phase 1 of crew licensing) ----------------
    // The Lead's own device is the actual roster — it holds every token
    // they've been given and pastes each one in once. What lives here in
    // the Worker is just the live status (active/revoked + whose name is
    // on it) so a crew member's own device can check itself, and so the
    // Lead's OTHER devices (if they ever use more than one) would see
    // the same picture. Writes require the OWNER role specifically —
    // this is the one place in the whole file where being a valid
    // license isn't enough; the token has to be the Lead's.
    if (request.method === "POST" && url.pathname === "/crew-seat") {
      let body;
      try {
        body = await request.json();
      } catch (e) {
        return jsonResponse({ error: "Invalid JSON" }, 400);
      }
      const companyId = await getVerifiedOwnerCompanyId(request, body);
      if (!companyId) return jsonResponse({ error: "Unauthorized \u2014 requires an Owner/Lead license" }, 401);

      const { pairingCode, crewMemberName, status } = body || {};
      if (!pairingCode || !status) {
        return jsonResponse({ error: "pairingCode and status are required" }, 400);
      }
      if (status !== "active" && status !== "revoked") {
        return jsonResponse({ error: "status must be 'active' or 'revoked'" }, 400);
      }
      const record = {
        crewMemberName: crewMemberName ? String(crewMemberName).slice(0, 100) : null,
        status,
        updatedAt: Date.now()
      };
      await env.STATUS_KV.put(tenantKey(companyId, `crew:${String(pairingCode).slice(0, 40)}`), JSON.stringify(record));
      return jsonResponse({ ok: true });
    }

    // Owner-only — the full roster, for the "Manage Crew Licenses" screen.
    if (request.method === "GET" && url.pathname === "/crew-seats") {
      const companyId = await getVerifiedOwnerCompanyId(request, null);
      if (!companyId) return jsonResponse({ error: "Unauthorized \u2014 requires an Owner/Lead license" }, 401);

      const prefix = tenantKey(companyId, "crew:");
      const list = await env.STATUS_KV.list({ prefix, limit: 500 });
      const results = await Promise.all(
        list.keys.map(async (k) => {
          const record = await env.STATUS_KV.get(k.name, "json");
          return record ? { pairingCode: k.name.slice(prefix.length), ...record } : null;
        })
      );
      return jsonResponse({ seats: results.filter(Boolean) });
    }

    // Public read, scoped by pairing code + company_id, same "unguessable
    // ID is the access control" reasoning as /status — this is what a
    // CREW member's own device checks (it can't use its own token to
    // authenticate a check of its own validity, that's circular). Only
    // ever reveals active/revoked, nothing else about the company.
    if (request.method === "GET" && url.pathname === "/crew-seat-status") {
      const pairingCode = url.searchParams.get("code");
      const companyId = url.searchParams.get("biz");
      if (!pairingCode || !companyId) return jsonResponse({ error: "Missing code or biz" }, 400);

      const record = await env.STATUS_KV.get(tenantKey(companyId, `crew:${pairingCode}`), "json");
      if (!record) return jsonResponse({ status: "unknown" }); // never activated via the roster — not the same as revoked, callers should treat unknown as "allow" so this stays backward-compatible with licenses issued before Phase 1
      return jsonResponse({ status: record.status });
    }

    // ---------------- Work-order routing (Phase 2 of crew licensing) ----------------
    // Deliberately narrow subset of a work order — client name, phone,
    // address, schedule, and the services/materials lists WITHOUT
    // pricing (confirmed explicitly with the customer: no cost data
    // travels here, only what a crew member needs to know what to do
    // and whether they have the parts). Any valid license token (owner
    // OR crew) can read or write — crew members can see each other's
    // assigned jobs, not just their own, matching how /time-entries
    // already works company-wide rather than per-person, not a new
    // permission shape invented just for this.
    // No TTL — cleared explicitly when a job is unassigned or done, not
    // left to expire on its own.
    if (request.method === "POST" && url.pathname === "/routed-job") {
      let body;
      try {
        body = await request.json();
      } catch (e) {
        return jsonResponse({ error: "Invalid JSON" }, 400);
      }
      const companyId = await getVerifiedCompanyId(request, body);
      if (!companyId) return jsonResponse({ error: "Unauthorized" }, 401);

      const { workOrderId, crewMemberName, clientName, clientPhone, address, scheduledDate, timeStart, timeEnd, services, materials, notes, crewStatus } = body || {};
      if (!workOrderId || !crewMemberName) {
        return jsonResponse({ error: "workOrderId and crewMemberName are required" }, 400);
      }
      const cleanServices = Array.isArray(services) ? services.slice(0, 50).map((s) => String(s).slice(0, 200)) : [];
      const cleanMaterials = Array.isArray(materials)
        ? materials.slice(0, 100).map((m) => ({ description: String(m.description || "").slice(0, 200), qty: String(m.qty || "").slice(0, 20) })) // deliberately no cost/unitCost field carried through, even if the caller sent one
        : [];
      const record = {
        crewMemberName: String(crewMemberName).slice(0, 100),
        clientName: clientName ? String(clientName).slice(0, 100) : null,
        clientPhone: clientPhone ? String(clientPhone).slice(0, 30) : null,
        address: address ? String(address).slice(0, 300) : null,
        scheduledDate: scheduledDate ? String(scheduledDate).slice(0, 20) : null,
        timeStart: timeStart ? String(timeStart).slice(0, 10) : null,
        timeEnd: timeEnd ? String(timeEnd).slice(0, 10) : null,
        services: cleanServices,
        materials: cleanMaterials,
        notes: notes ? String(notes).slice(0, 1000) : null,
        crewStatus: crewStatus ? String(crewStatus).slice(0, 30) : "assigned",
        updatedAt: Date.now()
      };
      await env.STATUS_KV.put(tenantKey(companyId, `routed:${String(workOrderId).slice(0, 100)}`), JSON.stringify(record));
      return jsonResponse({ ok: true });
    }

    // Every routed job for this tenant — a crew member's device filters
    // this down to their own name client-side (same pattern as the
    // Jobs Portal filtering catalog data, nothing new here).
    if (request.method === "GET" && url.pathname === "/routed-jobs") {
      const companyId = await getVerifiedCompanyId(request, null);
      if (!companyId) return jsonResponse({ error: "Unauthorized" }, 401);

      const prefix = tenantKey(companyId, "routed:");
      const list = await env.STATUS_KV.list({ prefix, limit: 500 });
      const results = await Promise.all(
        list.keys.map(async (k) => {
          const record = await env.STATUS_KV.get(k.name, "json");
          return record ? { workOrderId: k.name.slice(prefix.length), ...record } : null;
        })
      );
      return jsonResponse({ jobs: results.filter(Boolean) });
    }

    // Explicit removal — a job unassigned, or finished and no longer
    // worth showing on anyone's device. Not left to just go stale.
    if (request.method === "DELETE" && url.pathname === "/routed-job") {
      const companyId = await getVerifiedCompanyId(request, null);
      if (!companyId) return jsonResponse({ error: "Unauthorized" }, 401);

      const workOrderId = url.searchParams.get("id");
      if (!workOrderId) return jsonResponse({ error: "Missing id" }, 400);
      await env.STATUS_KV.delete(tenantKey(companyId, `routed:${workOrderId}`));
      return jsonResponse({ ok: true });
    }

    // ---------------- Inventory by location (Phase 3 of crew licensing) ----------------
    // Unlike almost everything else in this Worker, this dataset is
    // meant to be genuinely cross-device EDITABLE, not just cross-device
    // readable — a crew member adjusts their own truck's count from
    // their own device, the Lead adjusts the warehouse from theirs, and
    // each needs to see the other's numbers too. Last-write-wins on
    // conflicting edits to the same item, same limitation already
    // documented for this project's other shared-storage uses — not
    // silently pretended away here. Any valid license token can read or
    // write, same permission shape as time entries and routed jobs.
    if (request.method === "POST" && url.pathname === "/inventory-item") {
      let body;
      try {
        body = await request.json();
      } catch (e) {
        return jsonResponse({ error: "Invalid JSON" }, 400);
      }
      const companyId = await getVerifiedCompanyId(request, body);
      if (!companyId) return jsonResponse({ error: "Unauthorized" }, 401);

      const { id, name, qty, reorderAt, location, cost } = body || {};
      if (!id || !name || !location) {
        return jsonResponse({ error: "id, name, and location are required" }, 400);
      }
      const record = {
        name: String(name).slice(0, 200),
        qty: qty != null ? parseInt(qty, 10) || 0 : 0,
        reorderAt: reorderAt != null ? parseInt(reorderAt, 10) || 0 : 0,
        location: String(location).slice(0, 100),
        cost: cost ? String(cost).slice(0, 20) : "",
        updatedAt: Date.now()
      };
      await env.STATUS_KV.put(tenantKey(companyId, `inv:${String(id).slice(0, 100)}`), JSON.stringify(record));
      return jsonResponse({ ok: true });
    }

    if (request.method === "GET" && url.pathname === "/inventory-items") {
      const companyId = await getVerifiedCompanyId(request, null);
      if (!companyId) return jsonResponse({ error: "Unauthorized" }, 401);

      const prefix = tenantKey(companyId, "inv:");
      const list = await env.STATUS_KV.list({ prefix, limit: 1000 });
      const results = await Promise.all(
        list.keys.map(async (k) => {
          const record = await env.STATUS_KV.get(k.name, "json");
          return record ? { id: k.name.slice(prefix.length), ...record } : null;
        })
      );
      return jsonResponse({ items: results.filter(Boolean) });
    }

    if (request.method === "DELETE" && url.pathname === "/inventory-item") {
      const companyId = await getVerifiedCompanyId(request, null);
      if (!companyId) return jsonResponse({ error: "Unauthorized" }, 401);

      const id = url.searchParams.get("id");
      if (!id) return jsonResponse({ error: "Missing id" }, 400);
      await env.STATUS_KV.delete(tenantKey(companyId, `inv:${id}`));
      return jsonResponse({ ok: true });
    }

    return jsonResponse({ error: "Not found" }, 404);
  }
};
