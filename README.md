# Domain of Thrones — GOAD Attack & Defense Dashboard

Static interactive report with a shared passphrase gate on **Netlify**.

**Repo:** [CosmicSlothOracle/Domainofthrones](https://github.com/CosmicSlothOracle/Domainofthrones)

## Contents

```
index.html              ← dashboard (protected)
login.html              ← poem + passphrase form
dashboard-data.js       ← events, BloodHound, secrets, narratives
assets/                 ← icons + evidence screenshots
netlify/                ← login function, edge protect, Blobs sessions
```

Lab data only — redact credentials in `dashboard-data.js` before publishing.

---

## Deploy on Netlify (recommended)

1. Go to [app.netlify.com](https://app.netlify.com) → **Add new site** → **Import from Git** → select **Domainofthrones**.
2. Build settings (auto-detected from `netlify.toml`):
   - **Build command:** `npm install`
   - **Publish directory:** `.`
3. Deploy.

Visitors land on `/login.html`, read the poem, and enter the passphrase. Sessions are stored in [Netlify Blobs](https://docs.netlify.com/build/data-and-storage/netlify-blobs/) after a successful login.

### Passphrase rules

- Default passphrase: `ThereIsNoSpoon`
- **Case insensitive** — `thereisnospoon` works
- **Spaces ignored** — `there is no spoon` works

Optional: override in Netlify **Site configuration → Environment variables**:

| Variable | Purpose |
|----------|---------|
| `SITE_PASSWORD` | Change the shared passphrase without redeploying code |

### Local dev

```powershell
npm install
npx netlify dev
# http://localhost:8888/login.html
```

---

## GitHub Pages / Vercel

These hosts serve static files only — **no login gate**. Use Netlify if you need the shared passphrase.

---

## Logout

Open `/.netlify/functions/logout` to clear the session cookie and return to the login page.
