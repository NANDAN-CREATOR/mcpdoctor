// MCPDoctor submission relay (Cloudflare Worker).
// Receives {url, consent, token} from the dashboard page, checks the Turnstile CAPTCHA, and opens a GitHub issue in the
// same format as the issue form. The existing "Scan request" workflow does the validation, limits, scan and publishing.
//
// Secrets (Settings > Variables and Secrets):  GITHUB_TOKEN (Issues: read+write on the mcpdoctor repo only),
//                                              TURNSTILE_SECRET
// Text variable:                                ALLOWED_ORIGIN  e.g. https://nandan-creator.github.io
// Optional text variable:                       REPO (default NANDAN-CREATOR/mcpdoctor)

const MAX_BODY = 2000;

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const allowed = env.ALLOWED_ORIGIN || "";
    const cors = {
      "Access-Control-Allow-Origin": allowed,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Vary": "Origin",
    };
    const reply = (status, obj) =>
      new Response(JSON.stringify(obj), { status, headers: { ...cors, "Content-Type": "application/json" } });

    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    if (request.method !== "POST") return reply(405, { error: "Use POST." });
    if (!allowed || origin !== allowed) return reply(403, { error: "This request did not come from the dashboard." });

    const raw = await request.text();
    if (raw.length > MAX_BODY) return reply(413, { error: "Request too large." });
    let data;
    try { data = JSON.parse(raw); } catch { return reply(400, { error: "Invalid request." }); }

    const url = String(data.url || "").trim();
    if (!/^https:\/\/[^\s]{4,280}$/.test(url)) {
      return reply(400, { error: "Please enter a full https:// address (no spaces)." });
    }
    if (data.consent !== true) return reply(400, { error: "Please tick the permission box." });

    // 1) CAPTCHA
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    const verify = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body: new URLSearchParams({ secret: env.TURNSTILE_SECRET, response: String(data.token || ""), remoteip: ip }),
    });
    const verdict = await verify.json().catch(() => ({}));
    if (!verdict.success) return reply(400, { error: "The spam check failed. Please reload the page and try again." });

    // 2) A stable anonymous id for the per-person limit (hash of IP; the IP itself is never stored)
    const bytes = new TextEncoder().encode(`${ip}|${env.TURNSTILE_SECRET}`);
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    const who = "web-" + [...new Uint8Array(digest)].slice(0, 6).map((b) => b.toString(16).padStart(2, "0")).join("");

    // 3) Open the issue the workflow listens for
    const host = new URL(url).hostname;
    const body =
      `### MCP server address\n\n${url}\n\n### Permission\n\n` +
      `- [X] I own this server, or I have permission to test it, and I am happy for the result to be public.\n\n` +
      `### Submitter\n\n${who}\n`;
    const repo = env.REPO || "NANDAN-CREATOR/mcpdoctor";
    const gh = await fetch(`https://api.github.com/repos/${repo}/issues`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.GITHUB_TOKEN}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "mcpdoctor-submit-worker",
        "X-GitHub-Api-Version": "2022-11-28",
      },
      body: JSON.stringify({ title: `Test request (web): ${host}`.slice(0, 120), body, labels: ["scan-request"] }),
    });
    if (!gh.ok) return reply(502, { error: "Could not queue the test right now. Please try again later." });
    const issue = await gh.json();
    return reply(200, { ok: true, issue: issue.number });
  },
};
