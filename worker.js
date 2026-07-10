// Ranger Atlas save server — Cloudflare Worker (free).
// Holds your GitHub token AND all account passwords as SECRETS so no browser ever sees them.
//
// SETUP (one time, ~4 min):
// 1. Make a fine-grained GitHub token: github.com -> Settings -> Developer settings ->
//    Fine-grained personal access tokens -> Generate. Repository access: only
//    luiscredie/lorcana. Permissions: Contents = Read and write. Copy it.
// 2. dash.cloudflare.com -> Workers & Pages -> your existing Worker (or Create -> Create
//    Worker) -> "Edit code", paste THIS whole file (replacing what's there), Deploy.
// 3. Worker -> Settings -> Variables and Secrets -> Add these SECRETS:
//      GH_TOKEN        = your GitHub token from step 1
//      SESSION_SECRET  = any long random string you make up (used only to sign login
//                        sessions — never shown anywhere; e.g. mash your keyboard for 40+ chars)
//      USERS           = a JSON object mapping username -> {"pass":"...","role":"admin"|"viewer"}
//                        e.g. {"luiscredie":{"pass":"lorcanamaster123","role":"admin"},
//                              "friend":{"pass":"someotherpassword","role":"viewer"}}
//                        "admin" accounts can save changes; "viewer" accounts can only sign
//                        in to view the site. Add as many entries as you like — this is the
//                        multi-login table.
//    (Optional legacy fallback if you don't set USERS: ADMIN_USER + ADMIN_PASS, treated as a
//    single admin account. Optional plain vars: GH_OWNER, GH_REPO, GH_BRANCH, GH_PATH — defaults below.)
// 4. Deploy. That's it — the same Worker URL you already pasted into the app's Sync
//    panel keeps working; it now also handles login for the whole site.
//
// The whole site now requires signing in (any account in USERS) just to view it. Writes
// (POST, other than the login action) additionally REQUIRE a session whose role is "admin" —
// checked here on the server, so a browser can never bypass this by editing the page's JS.

const CFG = (env) => ({
  owner:  env.GH_OWNER  || "luiscredie",
  repo:   env.GH_REPO   || "lorcana",
  branch: env.GH_BRANCH || "main",
  path:   env.GH_PATH   || "atlas-data.json",
});
const ALLOW = "https://luiscredie.github.io"; // set to "*" to allow any origin
const SESSION_MS = 60 * 60 * 1000; // 1 hour

function cors(origin) {
  return {
    "Access-Control-Allow-Origin": ALLOW === "*" ? (origin || "*") : ALLOW,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
  };
}
const json = (obj, status, origin) =>
  new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...cors(origin) },
  });

async function hmacHex(secret, msg) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(msg));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
// Token format: "<exp>.<role>.<hexSignature>" — signature covers "<exp>.<role>" so a client
// can never forge or upgrade its own role.
async function verifyToken(token, secret) {
  const info = await decodeToken(token, secret);
  return !!info;
}
async function decodeToken(token, secret) {
  if (!token || !secret) return null;
  const parts = String(token).split(".");
  if (parts.length !== 3) return null;
  const [expStr, role, sig] = parts;
  const exp = parseInt(expStr, 10);
  if (!exp || Date.now() > exp) return null;
  const expected = await hmacHex(secret, expStr + "." + role);
  if (!timingSafeEqual(expected, sig)) return null;
  return { exp, role };
}
function loadUsers(env) {
  // Preferred: USERS secret, a JSON map of username -> {pass, role}.
  if (env.USERS) {
    try {
      const parsed = JSON.parse(env.USERS);
      if (parsed && typeof parsed === "object") return parsed;
    } catch (e) {}
  }
  // Legacy fallback: single admin account from ADMIN_USER/ADMIN_PASS.
  if (env.ADMIN_USER && env.ADMIN_PASS) {
    return { [env.ADMIN_USER]: { pass: env.ADMIN_PASS, role: "admin" } };
  }
  return null;
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(origin) });

    const c = CFG(env);
    const api = "https://api.github.com/repos/" + c.owner + "/" + c.repo + "/contents/" + c.path;
    const gh = (extra) => ({
      "Authorization": "Bearer " + env.GH_TOKEN,
      "Accept": "application/vnd.github+json",
      "User-Agent": "ranger-atlas-worker",
      ...(extra || {}),
    });

    try {
      if (request.method === "GET") {
        const r = await fetch(api + "?ref=" + c.branch + "&t=" + Date.now(), { headers: gh() });
        if (r.status === 404) return json({ doc: null, sha: null }, 200, origin);
        if (!r.ok) return json({ error: "read " + r.status }, 502, origin);
        const j = await r.json();
        let doc = null;
        try { doc = JSON.parse(decodeURIComponent(escape(atob(String(j.content).replace(/\s/g, ""))))); } catch (e) {}
        return json({ doc, sha: j.sha }, 200, origin);
      }

      if (request.method === "POST") {
        const body = await request.json().catch(() => ({}));

        // ---- Login: checked against secrets, never against anything client-visible ----
        if (body && body.action === "login") {
          const users = loadUsers(env);
          if (!users || !env.SESSION_SECRET) {
            return json({ error: "server missing login secrets (USERS or ADMIN_USER/ADMIN_PASS, plus SESSION_SECRET)" }, 500, origin);
          }
          const user = typeof body.user === "string" ? body.user : "";
          const pass = typeof body.pass === "string" ? body.pass : "";
          const account = Object.prototype.hasOwnProperty.call(users, user) ? users[user] : null;
          const passOk = !!account && typeof account.pass === "string" && timingSafeEqual(pass, account.pass);
          if (!account || !passOk) return json({ error: "invalid username or password" }, 401, origin);
          const role = account.role === "admin" ? "admin" : "viewer";
          const exp = Date.now() + SESSION_MS;
          const sig = await hmacHex(env.SESSION_SECRET, exp + "." + role);
          return json({ token: exp + "." + role + "." + sig, exp, role }, 200, origin);
        }

        // ---- Write: requires a valid, unexpired session token with the "admin" role ----
        const authHeader = request.headers.get("Authorization") || "";
        const token = authHeader.replace(/^Bearer\s+/i, "");
        const session = await decodeToken(token, env.SESSION_SECRET || "");
        if (!session || session.role !== "admin") return json({ error: "unauthorized — log in as admin to save" }, 401, origin);

        if (!env.GH_TOKEN) return json({ error: "server missing GH_TOKEN secret" }, 500, origin);
        if (typeof body.content !== "string") return json({ error: "no content" }, 400, origin);
        const put = {
          message: "Ranger Atlas sync " + new Date().toISOString(),
          content: btoa(unescape(encodeURIComponent(body.content))),
          branch: c.branch,
        };
        if (body.sha) put.sha = body.sha;
        const r = await fetch(api, { method: "PUT", headers: gh({ "Content-Type": "application/json" }), body: JSON.stringify(put) });
        if (r.status === 409 || r.status === 422) return json({ error: "conflict" }, 409, origin);
        if (!r.ok) { const t = await r.text(); return json({ error: "write " + r.status + " " + t.slice(0, 200) }, 502, origin); }
        const j = await r.json();
        return json({ ok: true, sha: j.content && j.content.sha }, 200, origin);
      }

      return json({ error: "method" }, 405, origin);
    } catch (e) {
      return json({ error: String((e && e.message) || e) }, 500, origin);
    }
  },
};
