# DatacenterBackend project instructions

## Architecture
- This project does **not** use Render or Python.
- The backend is a Cloudflare Worker.
- The Worker entry file is `worker.js`.
- Wrangler configuration is in `wrangler.jsonc`.
- The frontend is served from GitHub Pages.
- Persistent data is stored in Cloudflare D1 through the `datacenter_db` binding.
- Online-presence tracking uses the `PRESENCE` Durable Object binding.
- SMS delivery uses the configured SMS gateway and Worker environment secrets.

## Important rules
- Never add `app.py`, `render.yaml`, or `requirements.txt` back to the repository.
- Never place passwords, API keys, tokens, SMS credentials, admin credentials, or merchant IDs in committed files.
- Keep secrets in Cloudflare Worker secrets or local `.dev.vars` files only.
- Do not commit `.wrangler/`, `.dev.vars`, `.env`, or `node_modules/`.
- Preserve the existing D1 and Durable Object bindings in `wrangler.jsonc`.
- Treat `worker.js` as the source of truth for backend API behavior.
- Before changing frontend API calls, confirm they match the routes implemented in `worker.js`.

## Deployment
- Local development: `npx wrangler dev`
- Production deployment: `npx wrangler deploy`

## Review focus
When reviewing or fixing bugs, check these areas first:
1. OTP request and verification flow.
2. User session creation and 30-day session handling.
3. Admin authentication and authorization.
4. Product stock limits and order stock reduction.
5. D1 reads/writes and schema compatibility.
6. CORS between GitHub Pages and the Cloudflare Worker.
7. Mobile menu and frontend API integration.
