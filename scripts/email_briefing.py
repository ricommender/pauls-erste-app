#!/usr/bin/env python3
"""Send a single brief to an explicitly configured recipient via Resend API."""
import datetime as dt
import html
import json
import os
import urllib.request
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent.parent
APP = "https://ricommender.github.io/pauls-erste-app/"
key = os.environ.get("RESEND_API_KEY", "").strip()
sender = os.environ.get("MAIL_FROM", "").strip()
receiver = os.environ.get("BRIEFING_TO", "").strip()
if not (key and sender and receiver):
    print("Email is NOT enabled. Add RESEND_API_KEY, MAIL_FROM and BRIEFING_TO repository secrets.")
    raise SystemExit(0)
if "@" not in sender or "@" not in receiver:
    raise SystemExit("MAIL_FROM or BRIEFING_TO is not a valid email address.")
brief = json.loads((ROOT / "briefing.json").read_text(encoding="utf8"))
local_today = dt.datetime.now(ZoneInfo("Europe/Berlin")).strftime("%d.%m.%Y")
if brief.get("local_date") != local_today:
    raise SystemExit("Refusing to mail a stale briefing.")
def e(value):
    return html.escape(str(value or ""), quote=True)
def li(items):
    return "".join("<li style='margin:0 0 11px'>" + e(item) + "</li>" for item in items)
highlights = brief.get("highlights", [])
entries = ""
for item in highlights:
    url = item.get("url", "")
    if not url.startswith("https://"):
        continue
    entries += (
        "<li style='padding-bottom:16px'><a href='" + e(url) + "' style='color:#86b9ff;font-weight:700'>"
        + e(item["title"]) + "</a><div style='color:#afc2da;font-size:13px'>"
        + e(item.get("severity", "").upper()) + " · "
        + e(", ".join(item.get("technologies") or ["Übergreifend"])) + " · "
        + e(item.get("source")) + "</div><p>" + e(item.get("management")) + "</p><p><b>Technik:</b> "
        + e(item.get("technical")) + "</p></li>"
    )
body = (
    "<html><body style='background:#081322;color:#e8f3ff;padding:24px;font:15px/1.6 Arial,sans-serif'>"
    "<main style='max-width:690px;margin:auto;background:#122238;border:1px solid #273f60;"
    "padding:28px;border-radius:18px'><p style='color:#8abaff'>PAULS ERSTE APP · CYBER THREAT INTELLIGENCE</p>"
    "<h1>Security-Briefing " + e(local_today) + "</h1>"
    "<p><b>" + e(brief.get("new_24h", 0)) + " Meldungen in 24 Stunden</b> · "
    + e(brief.get("critical_24h", 0)) + " kritisch · "
    + e(brief.get("kev_24h", 0)) + " CISA KEV</p>"
    "<h2>Management</h2><p>" + e(brief.get("management")) + "</p>"
    "<h2>Technik</h2><p>" + e(brief.get("technical")) + "</p>"
    "<h2>Heute prüfen</h2><ol>" + li(brief.get("actions", [])) + "</ol>"
    "<h2>Top-Meldungen (7 Tage)</h2><ol>" + entries + "</ol>"
    "<p><a style='color:#fff;background:#2366bb;border-radius:10px;padding:14px 20px;"
    "text-decoration:none;display:inline-block' href='" + e(APP) + "'>Dashboard öffnen →</a></p>"
    "<p style='font-size:12px;color:#9db2d0'>"
    + ("KI-gestützt" if brief.get("mode") == "ai" else "Regelbasiert")
    + " · Quellenmeldungen sind nicht unabhängig verifiziert. "
    "Asset-Betroffenheit und Patch-Details separat abgleichen. Automatisches tägliches Briefing.</p>"
    "</main></body></html>"
)
subject = f"Pauls erste App | Security-Briefing {local_today} · {brief.get('new_24h', 0)} neue Meldungen"
payload = {"from": sender, "to": [receiver], "subject": subject, "html": body}
headers = {
    "Authorization": "Bearer " + key,
    "Content-Type": "application/json",
    "User-Agent": "PaulsSecurityBriefing/1.1",
    "Idempotency-Key": "pauls-briefing-" + dt.datetime.now(ZoneInfo("Europe/Berlin")).strftime("%Y-%m-%d")
}
request = urllib.request.Request("https://api.resend.com/emails", data=json.dumps(payload).encode("utf8"),
                                 headers=headers, method="POST")
with urllib.request.urlopen(request, timeout=35) as result:
    output = json.load(result)
if not output.get("id"):
    raise RuntimeError("Mail provider did not return an acceptance ID.")
print("Resend accepted the email request. Message ID:", output["id"])
