# GOAD — Attack & Defense Assessment Dashboard

Static interactive report. Deploy anywhere that serves HTML — no server or tunnel required.

**Live URL after deploy:** `https://<you>.github.io/goad-dashboard/` or your Vercel domain.

## Contents

```
index.html              ← dashboard entry point
dashboard-data.js       ← events, BloodHound, secrets, narratives
assets/icons/           ← host icons on the topology map
assets/evidence/        ← proof screenshots
GOAD_Attack_Evidence.zip
```

Lab data only — redact credentials in `dashboard-data.js` before publishing.

---

## Deploy: GitHub Pages (recommended — simplest)

1. Create a new GitHub repo (e.g. `goad-dashboard`).
2. Push this folder:

   ```powershell
   cd C:\Users\lauri\Downloads\goad-dashboard
   git init
   git add .
   git commit -m "Initial GOAD dashboard"
   git branch -M main
   git remote add origin https://github.com/YOUR_USER/goad-dashboard.git
   git push -u origin main
   ```

3. On GitHub: **Settings → Pages**
   - **Source:** Deploy from a branch
   - **Branch:** `main` / `/ (root)`
   - Save

4. After ~1 minute, open `https://YOUR_USER.github.io/goad-dashboard/`

No build step. No config files required.

---

## Deploy: Vercel (also easy)

1. Push the repo to GitHub (same steps as above).
2. Go to [vercel.com/new](https://vercel.com/new) → import the repo.
3. Leave defaults (Framework: **Other**, no build command, output: **.**).
4. Deploy.

Vercel gives you a URL like `https://goad-dashboard.vercel.app` and auto-redeploys on every push.

---

## GitHub Pages vs Vercel

| | GitHub Pages | Vercel |
|---|-------------|--------|
| Setup | Enable in repo Settings | Import repo, click Deploy |
| Cost | Free | Free |
| Custom domain | Yes | Yes |
| Password protection | Not on free tier | Pro plan only |
| Best for | Simple public static sites | Same + preview URLs per branch |

For a lab report you share with a few people, **GitHub Pages is the easiest**.

---

## Local preview

```powershell
cd C:\Users\lauri\Downloads\goad-dashboard
python -m http.server 8000 --bind 127.0.0.1
# http://127.0.0.1:8000/
```

## Optional: shared password

GitHub Pages and Vercel (free) do not support a server-side login. Options:

- Keep the repo **private** and only share the public Pages URL with people you trust (the URL is still guessable).
- Use **Vercel Deployment Protection** (Pro) or **Cloudflare Access** in front of a custom domain.
- For casual obfuscation only, a client-side gate can be added — not real security.
