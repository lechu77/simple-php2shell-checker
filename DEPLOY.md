# Cloudflare Pages Deployment Guide

This guide details the deployment methods for **simple-php2shell-checker** to Cloudflare Pages while ensuring the edge functions (`/functions/api/check.js`) operate seamlessly.

---

## Prerequisites

- A free or paid [Cloudflare](https://dash.cloudflare.com/) account.
- Git repository hosted on GitHub/GitLab (for continuous deployment) or [Node.js](https://nodejs.org/) v18+ (for CLI deployment).

---

## Method 1: Automatic Git Deployment (Recommended)

Every `git push` to your default branch (`main`) will trigger an automatic build and deployment.

1. **Access the Cloudflare Dashboard**:
   - Go to [Cloudflare Dashboard](https://dash.cloudflare.com/).
   - In the left sidebar, navigate to **Workers & Pages** -> **Overview**.
   - Click **Create application** and select the **Pages** tab.
   - Click **Connect to Git**.

2. **Select Repository**:
   - Connect your GitHub/GitLab account and choose `simple-php2shell-checker`.
   - Click **Begin setup**.

3. **Build Settings**:
   - **Project name**: `simple-php2shell-checker`.
   - **Production branch**: `main`.
   - **Framework preset**: `None` (no build step required).
   - **Build command**: *(leave completely empty)*.
   - **Build output directory**: `public`.
   - **Root directory**: `/` *(or leave blank)*.

4. **Edge Functions Routing**:
   - Cloudflare Pages automatically detects the root `/functions/` directory and mounts `/api/check`.

5. **Save and Deploy**:
   - Click **Save and Deploy**.
   - Within ~30 seconds, your public URL will be live (e.g. `https://simple-php2shell-checker.pages.dev`).

---

## Method 2: Direct CLI Deployment via Wrangler

Deploy directly from your terminal without linking Git to Cloudflare:

1. **Authenticate Wrangler**:
   ```bash
   npx wrangler login
   ```

2. **Deploy**:
   ```bash
   npm run deploy
   ```
   Or directly:
   ```bash
   npx wrangler pages deploy public --project-name=simple-php2shell-checker
   ```

---

## Method 3: GitHub Actions CI/CD Pipeline

To deploy automatically on push via GitHub Actions, add `.github/workflows/deploy.yml`:

```yaml
name: Deploy to Cloudflare Pages

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      deployments: write
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Execute Test Suite
        run: npm test

      - name: Deploy to Cloudflare Pages
        uses: cloudflare/wrangler-action@v3
        with:
          apiToken: ${{ secrets.CLOUDFLARE_API_TOKEN }}
          accountId: ${{ secrets.CLOUDFLARE_ACCOUNT_ID }}
          command: pages deploy public --project-name=simple-php2shell-checker
```

---

## Local Development and Verification

1. **Start local emulation server**:
   ```bash
   npm run dev
   ```
   Access the frontend at `http://localhost:8788`.

2. **Test API endpoint via cURL**:
   ```bash
   curl -s -X POST http://localhost:8788/api/check \
     -H "Content-Type: application/json" \
     -d '{"urls": ["https://www.php.net"]}'
   ```

3. **Run unit tests**:
   ```bash
   npm test
   ```
