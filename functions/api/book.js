// POST /api/book — booking form handler for Cloudflare Pages.
// Validates input, checks the honeypot, verifies Cloudflare Turnstile (if configured),
// and emails the request via Resend. Returns JSON the front-end reads.
//
// Required environment variables (Pages project → Settings → Environment variables):
//   RESEND_API_KEY   — Resend API key (re_...)
//   TO_EMAIL         — where booking requests are delivered (e.g. joel@burslem.ca)
//   FROM_EMAIL       — a verified Resend sender (e.g. bookings@charlotteburslem.com)
// Optional:
//   TURNSTILE_SECRET — Cloudflare Turnstile secret key. If set, a valid token is required.

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });

const esc = (s) =>
  String(s == null ? "" : s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

const clip = (s, n = 2000) => String(s == null ? "" : s).slice(0, n);

export async function onRequestPost({ request, env }) {
  let data;
  const contentType = request.headers.get("content-type") || "";
  try {
    if (contentType.includes("application/json")) {
      data = await request.json();
    } else {
      const form = await request.formData();
      data = Object.fromEntries(form.entries());
    }
  } catch {
    return json({ ok: false, error: "Could not read the form." }, 400);
  }

  // Honeypot: a real person leaves "company" empty. Pretend success for bots.
  if (data.company) return json({ ok: true });

  const name = clip(data.name, 200).trim();
  const email = clip(data.email, 320).trim();
  if (!name || !email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return json({ ok: false, error: "Please include your name and a valid email." }, 400);
  }

  // Turnstile verification (only enforced when a secret is configured).
  if (env.TURNSTILE_SECRET) {
    const token = data["cf-turnstile-response"];
    if (!token) return json({ ok: false, error: "Please complete the spam check." }, 400);
    const ip = request.headers.get("cf-connecting-ip") || "";
    const body = new FormData();
    body.append("secret", env.TURNSTILE_SECRET);
    body.append("response", token);
    if (ip) body.append("remoteip", ip);
    const verify = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      { method: "POST", body }
    ).then((r) => r.json()).catch(() => ({ success: false }));
    if (!verify.success) {
      return json({ ok: false, error: "Spam check failed. Please try again." }, 400);
    }
  }

  if (!env.RESEND_API_KEY || !env.TO_EMAIL || !env.FROM_EMAIL) {
    return json({ ok: false, error: "Email is not configured yet." }, 500);
  }

  const fields = {
    Name: name,
    Email: email,
    Phone: clip(data.phone, 50),
    "Event type": clip(data.event_type, 100),
    "Event date": clip(data.event_date, 50),
    "Location / venue": clip(data.location, 300),
    Message: clip(data.message, 4000),
  };
  const rows = Object.entries(fields)
    .filter(([, v]) => v && String(v).trim())
    .map(([k, v]) => `<tr><td style="padding:4px 12px 4px 0;font-weight:600">${esc(k)}</td><td style="padding:4px 0">${esc(v).replace(/\n/g, "<br>")}</td></tr>`)
    .join("");

  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      authorization: `Bearer ${env.RESEND_API_KEY}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      from: `Charlotte Burslem Bookings <${env.FROM_EMAIL}>`,
      to: [env.TO_EMAIL],
      reply_to: email,
      subject: `Booking request — ${name}${fields["Event type"] ? ` (${fields["Event type"]})` : ""}`,
      html: `<h2 style="font-family:Georgia,serif">New booking request</h2><table style="font-family:system-ui,sans-serif;font-size:15px">${rows}</table>`,
    }),
  });

  if (!res.ok) {
    return json({ ok: false, error: "Could not send your request. Please call or text." }, 502);
  }
  return json({ ok: true });
}
// Pages returns 405 automatically for non-POST methods, since only onRequestPost is exported.
