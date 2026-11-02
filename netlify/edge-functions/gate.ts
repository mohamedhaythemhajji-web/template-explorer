// Two-level password gate.
//   Editor password = SITE_PASSWORD   (full access)
//   Viewer password = VIEWER_PASSWORD (read-only)

export const config = { path: "/*" };

const COOKIE = "tre_auth";
const ONE_YEAR = 60 * 60 * 24 * 365;
const enc = new TextEncoder();
declare const Deno: { env: { get(name: string): string | undefined } };

async function token(pw: string, tag: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(pw), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(tag));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function same(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

function getCookie(req: Request): string {
  const m = (req.headers.get("cookie") || "").match(new RegExp("(?:^|;\\s*)" + COOKIE + "=([^;]*)"));
  return m ? m[1] : "";
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const setCookie = (value: string, maxAge: number) =>
  `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;

function json(data: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store", ...extra },
  });
}

async function roleOf(req: Request, ePw: string, vPw: string): Promise<string> {
  const c = getCookie(req);
  if (!c) return "";
  if (same(c, await token(ePw, "tre-edit-v2"))) return "edit";
  if (vPw && same(c, await token(vPw, "tre-view-v2"))) return "view";
  return "";
}

function page(msg = "", status = 401): Response {
  const cards = Array.from({ length: 8 }, (_, i) =>
    `<div class="fc"><div class="fi" style="background:linear-gradient(${150 + i * 25}deg,#c9d6ff,#f3c6e0)"></div><i></i><i class="s"></i></div>`
  ).join("");
  const html = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Template Reference Explorer</title>
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f4f5f8;color:#12141a;overflow:hidden;
 font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.bg{position:fixed;inset:-40px;display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:16px;padding:60px;filter:blur(16px);opacity:.75;pointer-events:none}
.fc{background:#fff;border:1px solid #e2e5ec;border-radius:12px;padding:12px;height:260px}
.fi{height:170px;border-radius:8px;margin-bottom:12px}
.fc i{display:block;height:12px;border-radius:6px;background:#dfe3ec;margin-bottom:8px}.fc i.s{width:55%}
.card{position:relative;width:min(380px,92vw);background:#fff;border:1px solid #e2e5ec;border-radius:14px;padding:28px 26px;box-shadow:0 12px 44px rgba(15,23,42,.18)}
.logo{width:34px;height:34px;border-radius:9px;background:#1a5cff;color:#fff;display:grid;place-items:center;font-weight:700;font-size:13px;margin-bottom:14px}
h1{font-size:17px;margin:0 0 4px}p{margin:0 0 16px;color:#6b7280;font-size:13px}
input{width:100%;border:1px solid #e2e5ec;border-radius:8px;padding:10px 12px;font:inherit}
input:focus{outline:0;border-color:#1a5cff;box-shadow:0 0 0 3px rgba(26,92,255,.12)}
button{width:100%;margin-top:12px;border:0;border-radius:8px;background:#1a5cff;color:#fff;font:inherit;font-weight:600;padding:10px;cursor:pointer}
button:hover{background:#0f4ae0}.err{color:#b42318;font-size:12.5px;margin:10px 0 0}
.note{margin:14px 0 0;font-size:11.5px;color:#9aa1ae}
</style></head><body><div class="bg">${cards}</div>
<form class="card" method="POST" action="/__login">
<div class="logo">TR</div><h1>Template Reference Explorer</h1><p>🔒 Templates are locked. Enter the team password to continue.</p>
<input type="password" name="password" placeholder="Password" autofocus autocomplete="current-password" required>
<button type="submit">Unlock</button>${msg ? `<div class="err">${msg}</div>` : ""}
<div class="note">You will stay signed in on this browser.</div></form></body></html>`;
  return new Response(html, {
    status,
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
  });
}

export default async (req: Request, context: { next: () => Promise<Response> }) => {
  const ePw = Deno.env.get("SITE_PASSWORD") || "";
  const vPw = Deno.env.get("VIEWER_PASSWORD") || "";
  if (!ePw) return page("SITE_PASSWORD has not been configured yet.", 503);

  const url = new URL(req.url);

  if (url.pathname === "/logout") {
    return new Response(null, {
      status: 303,
      headers: { Location: "/", "Set-Cookie": setCookie("", 0), "cache-control": "no-store" },
    });
  }

  // login (lock screen form, or the "Unlock editing" button inside the app)
  if (url.pathname === "/__login" && req.method === "POST") {
    const wantsJson = url.searchParams.get("json") === "1";
    let given = "";
    try { given = String((await req.formData()).get("password") || ""); } catch (_e) { /* ignore */ }
    let role = "";
    if (given && same(given, ePw)) role = "edit";
    else if (given && vPw && same(given, vPw)) role = "view";
    if (!role) {
      await sleep(700); // slows down guessing
      return wantsJson ? json({ ok: false }, 401) : page("Wrong password. Try again.");
    }
    const val = role === "edit" ? await token(ePw, "tre-edit-v2") : await token(vPw, "tre-view-v2");
    const hdr = setCookie(val, ONE_YEAR);
    if (wantsJson) return json({ ok: true, role }, 200, { "set-cookie": hdr });
    return new Response(null, { status: 303, headers: { Location: "/", "Set-Cookie": hdr, "cache-control": "no-store" } });
  }

  const role = await roleOf(req, ePw, vPw);

  if (!role) {
    if (url.pathname.startsWith("/api/") || url.pathname === "/__role") return json({ error: "unauthorized" }, 401);
    return page();
  }

  if (url.pathname === "/__role") return json({ role });

  // viewers can read but never write
  if (role === "view" && url.pathname.startsWith("/api/") && req.method !== "GET" && req.method !== "HEAD") {
    return json({ error: "read-only" }, 403);
  }

  const res = await context.next();
  if (url.pathname.startsWith("/api/")) return res;
  const headers = new Headers(res.headers);
  headers.set("cache-control", "private, no-store");
  return new Response(res.body, { status: res.status, headers });
};