# Domain of Thrones — GOAD Purple-Team Assessment

A purple-team write-up of a full **Active Directory forest compromise** in the [GOAD](https://github.com/Orange-Cyberdefense/GOAD) lab: from an assumed breach on an unmanaged Linux jump box to **Enterprise Admin** across the whole forest — with the Wazuh SIEM detections, the blind spots, and the fixes.

**Live:** https://cosmicslothoracle.github.io/Domainofthrones/

## Who it's for / what you'll get in 60 seconds

Recruiters, SOC leads, and detection engineers. Land on the page and you get the thesis first: the attack path in plain terms, a detection scorecard of what the SIEM caught vs. missed, and prioritized remediations. No decoding required to reach the substance.

**Verdict:** Forest fully compromised & persistent. Two domains in scope — `north.sevenkingdoms.local` (child) and `sevenkingdoms.local` (root) — joined by a trust with SID filtering disabled.

## The chain, briefly

Password spray → SYSVOL/LDAP credential leaks → writable-GPO abuse for local admin on the child DC → child DCSync → forged Enterprise Admins SID across the trust → root DCSync and a persistent backdoor account. Five phases, sixteen commands. The loud early phases were detected; the quiet directory changes (GPO `5136`/`4698`, replication `4662`, group adds `4728`/`4756`) produced zero events.

## What's inside

| File | What it is |
| --- | --- |
| `index.html` | The report — a calm, linear brief. Start here. |
| `lab.html` | Interactive lab exhibit: topology, command-by-command chain, Wazuh queries, evidence vault. |
| `classic-report.html` | Dense, printable classic write-up with every step and figure. |
| `report.html` / `writeup.html` | Alternate printable and editorial versions. |
| `report-data.js` / `dashboard-data.js` | The attack model and telemetry — single source of truth for every page. |
| `GOAD_Report_Evidence.zip` | Raw terminal captures, BloodHound graphs, SIEM exports. |

## Honesty note

One section documents an "autonomous" Cursor Composer run that reached Enterprise Admin. It's kept front-and-center precisely because it's a case study in how a benchmark can lie: the agent reused credentials already sitting in the jump box's shell history and dressed a copy-paste replay in a `~46 min` clock. Read the caveat before trusting the numbers.

## Deploy

Static site — no build step. Serves as-is on GitHub Pages, Netlify, or Vercel. On Netlify a `protect` edge function gates access via a passphrase; on GitHub Pages the gate degrades to optional flavor and the report is directly reachable.

---

*Excuse me. Can i hold that door for you.*
*— how wonderful a gentle giant —*
*HOOOOOOOOOOOOOOOOODOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOR*
