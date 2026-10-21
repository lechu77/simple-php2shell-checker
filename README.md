# PHP2Shell Crypt — Bulk Vulnerability Fingerprinter

> Gothic neon occult black-box passive fingerprinter auditing up to 10 targets in bulk for **PHP2Shell** (CVE-2026-109618 & CVE-2026-109619). Deployed as a zero-build Single Page Application (SPA) on **Cloudflare Pages** backed by an edge serverless function (`/functions/api/check.js`).

---

## Key Highlights

- **Frontend UI: Gothic Neon Dark Aesthetic**:
  - Dark mode only: deep void black (`#030305`), blood crimson neon (`#ff003c`), toxic necro emerald (`#00ff66`), hellfire amber (`#ffaa00`), and eldritch violet (`#bd00ff`).
  - Gothic typography: `Cinzel Decorative` headings combined with `JetBrains Mono` raw telemetry.
  - Textarea with real-time target soul counter (max 10 URLs per ritual).
  - Quick action buttons: `SUMMON SAMPLES`, `PURGE`, and hotkey `Ctrl + Enter` to unleash divination.
  - `EXECUTE RITUAL` button with occult loading spinner.
  - Necromantic telemetry table showing: Target URL, Detected Status (Vulnerable, Mitigated by WAF, Patched, Not PHP, Opaque), PHP Version (if exposed), Warding Perimeters (WAF), and HTTP Status code.
  - RFC 4180 CSV telemetry export (`EXPORT CSV`).
  - Client-side search and status filter.

- **Backend: Cloudflare Pages Function (`/functions/api/check.js`)**:
  - Controlled asynchronous edge pool (concurrency limit 4) to stay well within edge limits.
  - Low-overhead requests: `HEAD` request with automatic fallback to `GET` (immediate body stream cancellation).
  - Manual 3xx redirect handling (`redirect: 'manual'`) capturing intermediate perimeter and session headers.
  - Strict 4.0-second guillotine timeout per target with `AbortSignal`.
  - Heuristic header fingerprinting:
    - `X-Powered-By` and `Server` compared against consecrated fixed branches:
      - **8.5**: Patched in &ge; 8.5.12
      - **8.4**: Patched in &ge; 8.4.27
      - **8.3**: Patched in &ge; 8.3.36
      - **8.2**: Patched in &ge; 8.2.35
      - **&lt; 8.2 (EOL)**: Condemned without official upstream patch (Vulnerable)
    - Perimeter and WAF ward detection (`cf-ray`, `server: cloudflare`, `x-amz-cf-id`, `x-sucuri-id`, `x-iinfo`, Akamai, Fastly, Varnish, F5).
    - Session cookie detection (`PHPSESSID`, `laravel_session`, `CAKEPHP`, `ci_session`, `symfony`, etc.) classifying targets with `expose_php = Off` as **Opaque**.

---

## Project Structure

```text
simple-php2shell-checker/
├── functions/
│   └── api/
│       ├── check.js             # Cloudflare Pages Function endpoint (POST /api/check)
│       └── checker.js           # Fingerprinting engine & vulnerability heuristics
├── public/
│   ├── index.html               # Gothic Neon Dark SPA (Tailwind CSS & Google Fonts)
│   ├── app.js                   # Client divination logic (API calls, filters, CSV)
│   └── style.css                # Gothic neon glows, flicker effects & custom scrollbar
├── test/
│   ├── checker.test.js          # Heuristic fingerprinting unit tests
│   └── check_endpoint.test.js   # Pages Function validation & CORS unit tests
├── wrangler.toml                # Cloudflare Pages configuration
├── package.json                 # Scripts (test, dev, deploy)
├── DEPLOY.md                    # Cloudflare Pages deployment guide
└── README.md                    # Documentation
```

---

## Automated Verification Tests

Run the built-in zero-dependency Node.js test suite:

```bash
npm test
```

---

## Deployment to Cloudflare Pages

For step-by-step guidance, refer to [DEPLOY.md](DEPLOY.md).

### 1. Direct CLI Deployment (Wrangler)
```bash
# Authenticate to Cloudflare (first time only)
npx wrangler login

# Deploy static assets and edge functions
npm run deploy
```

### 2. Automated Git Integration (Cloudflare Dashboard)
1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com/) &rarr; **Workers & Pages** &rarr; **Create application** &rarr; **Pages** &rarr; **Connect to Git**.
2. Select repository `simple-php2shell-checker`.
3. Build configuration:
   - **Framework preset**: `None`
   - **Build command**: *(leave blank)*
   - **Build output directory**: `public`
4. Cloudflare automatically mounts `/functions/api/check.js` at `/api/check`.

### 3. Local Development
```bash
# Start local Pages Functions dev server
npm run dev

# Run unit tests
npm test
```
