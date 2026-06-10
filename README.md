# Domain of Thrones — GOAD Attack & Defense Dashboard

Static interactive report. Deploy anywhere that serves HTML — no server or tunnel required.

**Live URL after deploy:** `https://cosmicslothoracle.github.io/Domainofthrones/` or your Vercel domain.

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

## Deploy: GitHub Pages (recommended)

1. Push is already on [CosmicSlothOracle/Domainofthrones](https://github.com/CosmicSlothOracle/Domainofthrones).
2. On GitHub: **Settings → Pages**
   - **Source:** Deploy from a branch
   - **Branch:** `main` / `/ (root)`
   - Save
3. After ~1 minute, open `https://cosmicslothoracle.github.io/Domainofthrones/`

No build step. No config files required.

---

## Deploy: Vercel (alternative)

1. Go to [vercel.com/new](https://vercel.com/new) → import **Domainofthrones**.
2. Leave defaults (Framework: **Other**, no build command, output: **.**).
3. Deploy.

---

## Local preview

```powershell
python -m http.server 8000 --bind 127.0.0.1
# http://127.0.0.1:8000/
```

Lab data only — redact credentials before sharing.
