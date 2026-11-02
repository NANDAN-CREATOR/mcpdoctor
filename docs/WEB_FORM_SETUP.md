# Turn on the on-page "Test my server" form

The dashboard is a static GitHub Pages site, so the form needs a tiny relay. It is free (Cloudflare Workers + Turnstile).

1. Create a free Cloudflare account.
2. **Turnstile** -> Add widget: domain `nandan-creator.github.io`, mode Managed. Keep the *Site key* (public) and *Secret key*.
3. **GitHub token** (github.com/settings/personal-access-tokens/new): fine-grained, only the `mcpdoctor` repository, permission
   **Issues: Read and write**, nothing else.
4. **Workers & Pages** -> Create -> Hello World, name `mcpdoctor-submit` -> Deploy -> Edit code -> paste `worker/submit-worker.js` -> Deploy.
5. Worker **Settings -> Variables and Secrets**: secrets `GITHUB_TOKEN`, `TURNSTILE_SECRET`; text variable
   `ALLOWED_ORIGIN` = `https://nandan-creator.github.io`.
6. Put the Worker address and the Turnstile *Site key* in `site-config.json` and push:
   `{"submit_api": "https://mcpdoctor-submit.<you>.workers.dev", "turnstile_sitekey": "<site key>"}`
   then run the **Nightly leaderboard** workflow once.

How it behaves: the Worker verifies the CAPTCHA, then opens an issue with the form's fields plus an anonymous id
(`web-` + a hash of the visitor's IP; the IP is not stored). The "Scan request" workflow does everything else, including the
limits (5 per day in total, 2 per anonymous id). Rotate the GitHub token before it expires.
