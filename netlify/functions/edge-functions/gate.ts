// Password gate: nothing is served (app, API, storage page) until the right password is entered.

export const config = { path: "/*" };

const COOKIE = "tre_auth";
const enc = new TextEncoder();

async function sessionToken(pw: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(pw), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode("tre-session-v1"));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function same(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

function getCookie(req: Request, name: string): string {
  const m = (req.headers.get("cookie") || "").match(new RegExp("(?:^|;\\s*)" + name + "=([^;]*)"));
  return m ? m[1] : "";
}

function page(msg = "", status = 401): Response {
  const html = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Template Reference Explorer</title>
<style>
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f4f5f8;color:#12141a;
 font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.card{width:min(360px,92vw);background:#fff;border:1px solid #e2e5ec;border-radius:14px;padding:28px 26px;box-shadow:0 8px 34px rgba(15,23,42,.1)}
.logo{width:34px;height:34px;border-radius:9px;background:#1a5cff;color:#fff;display:grid;place-items:center;font-weight:700;font-size:13px;margin-bottom:14px}
h1{font-size:17px;margin:0 0 4px}p{margin:0 0 16px;color:#6b7280;font-size:13px}
input{width:100%;border:1px solid #e2e5ec;border-radius:8px;padding:10px 12px;font:inherit}
input:focus{outline:0;border-color:#1a5cff;box-shadow:0 0 0 3px rgba(26,92,255,.12)}
button{width:100%;margin-top:12px;border:0;border-radius:8px;background:#1a5cff;color:#fff;font:inherit;font-weight:600;padding:10px;cursor:pointer}
button:hover{background:#0f4ae0}.err{color:#b42318;font-size:12.5px;margin:10px 0 0}
</style></head><body><form class="card" method="POST" action="/">
<div class="logo">TR</div><h1>Template Reference Explorer</h1><p>Enter the team password to continue.</p>
<input type="password" name="password" placeholder="Password" autofocus autocomplete="current-password" required>
<button type="submit">Unlock</button>${msg ? `<div class="err">${msg}</div>` : ""}</form></body></html>`;
  return new Response(html, {
    status,
    headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
  });
}

const cookieHeader = (value: string, maxAge: number) =>
  `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;

export default async (req: Request, context: { next: () => Promise<Response> }) => {
  const pw = Deno.env.get("SITE_PASSWORD");
  if (!pw) return page("The site password has not been configured yet (SITE_PASSWORD).", 503);

  const url = new URL(req.url);
  const expected = await sessionToken(pw);

  if (url.pathname === "/logout") {
    return new Response(null, {
      status: 303,
      headers: { Location: "/", "Set-Cookie": cookieHeader("", 0), "cache-control": "no-store" },
    });
  }

  // already logged in
  if (same(getCookie(req, COOKIE), expected)) return context.next();

  // login attempt
  if (req.method === "POST" && !url.pathname.startsWith("/api/")) {
    let given = "";
    try { given = String((await req.formData()).get("password") || ""); } catch (_e) { /* ignore */ }
    if (given && same(await sessionToken(given), expected)) {
      return new Response(null, {
        status: 303,
        headers: { Location: "/", "Set-Cookie": cookieHeader(expected, 60 * 60 * 24 * 30), "cache-control": "no-store" },
      });
    }
    return page("Wrong password. Try again.");
  }

  // not logged in
  if (url.pathname.startsWith("/api/")) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "content-type": "application/json", "cache-control": "no-store" },
    });
  }
  return page();
};