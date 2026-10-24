# Pauls erste App – Security Intelligence

[**App öffnen**](https://ricommender.github.io/pauls-erste-app/)

Öffentliches, iPhone-optimiertes Browser-Dashboard für Schwachstellen, Breaches, Malware und neue Angriffsmethoden. Technologie-Fokus: **Microsoft 365, Windows, Azure, Sophos, VMware**.

## Funktionen und Status

| Funktion | Status |
| --- | --- |
| GitHub Pages / Suche / Filter | live |
| CISA KEV, BleepingComputer, The Hacker News | alle 3 Stunden automatisiert |
| FIRST EPSS CVE-Risikoscores | eingebaut, beim nächsten Collector-Lauf abrufbar |
| Management- und Technik-Bewertung pro Meldung | regelbasiert verfügbar |
| Tages-Briefing in `briefing.json` | verfügbar, täglich neu erzeugt |
| KI-generiertes Management-/Technik-Briefing | vorbereitet, benötigt `OPENAI_API_KEY` |
| E-Mail um 08:00 Europe/Berlin | geplant, benötigt Versand-Secrets |

**Hinweis:** Eine öffentliche Security-News-Anwendung kann nicht wissen, ob interne Systeme verwundbar sind. Die Betroffenheit muss immer anhand eigener Assets und offizieller Hersteller-Advisories geprüft werden.

## Einrichtung des täglichen E-Mail-Briefings

1. Bei [Resend](https://resend.com/) anmelden. Eigene Absenderdomain dort verifizieren (DNS: SPF/DKIM gemäß Resend-Anleitung).
2. Für diese App einen **Resend API Key** mit Versandberechtigung erzeugen.
3. In **GitHub → Settings → Secrets and variables → Actions** die folgenden **Repository Secrets** anlegen:
   - `RESEND_API_KEY`: Resend API Key
   - `MAIL_FROM`: verifizierter Absender, z. B. `Pauls Security <briefing@DEINE-DOMAIN.DE>`
   - `BRIEFING_TO`: Empfängeradresse für das morgendliche Security Briefing
   - `OPENAI_API_KEY`: optionaler OpenAI API Key für KI-Zusammenfassungen; ohne Schlüssel wird das Briefing regelbasiert generiert.
4. Workflow **Daily Security Briefing** öffnen: [Actions](https://github.com/ricommender/pauls-erste-app/actions/workflows/daily-briefing.yml).
5. **Run workflow**, Branch `main`. Zunächst `send_email` **nicht aktivieren**. Workflow auf Grün prüfen.
6. Nach Einrichtung der Mail-Secrets manuell nochmals **Run workflow** starten und für eine Testmail `send_email` anhaken.
7. Nach erfolgreichem Mail-Test läuft der Zeitplan täglich **08:00 Europe/Berlin**, inklusive Sommer-/Winterzeit (GitHub-Planung ist best effort und kann verspätet starten).

**Keinen API-Schlüssel, keine privaten Zugangsdaten und keine Empfängeradresse in Code, Issues oder Chat-Nachrichten veröffentlichen.** Alle vier Werte gehören unter Actions → Repository Secrets. Die öffentlichen JSON-Dateien enthalten ausschließlich Nachrichtendaten und Zusammenfassungen aus öffentlich zugänglichen Quellen.

**Kosten:** GitHub Actions, KI-API und Resend können je nach Nutzung und Tarif Kosten verursachen. Bei Resend sind Domainverifizierung und Absenderfreigabe erforderlich.

## Technischer Aufbau

- `scripts/collect.py`: Holt öffentliche Feeds und optional FIRST EPSS und erzeugt `data.json`. Wenn alle primären Quellen ausfallen, bleibt der letzte erfolgreiche Datenstand erhalten.
- `scripts/briefing.py`: Wählt aktuelle und stackrelevante Meldungen, erstellt Management- und technische Einschätzung; optional OpenAI Responses API mit strukturiertem JSON.
- `scripts/email_briefing.py`: Sendet HTML-Briefing ausschließlich über GitHub Actions mit drei gesetzten Versand-Secrets. Fehlen die Secrets, erfolgt kein Versand.
- `.github/workflows/refresh.yml`: automatischer Abruf alle 3 Stunden.
- `.github/workflows/daily-briefing.yml`: täglich um 08:00 Europe/Berlin, sowie manuell testbar.

Der Begriff **kritisch** ist eine heuristische Signalbewertung, keine Garantie für echte Kritikalität oder Unternehmensrelevanz; bei CISA KEV handelt es sich um dokumentierte Ausnutzung.

## Einrichtung GitHub Pages

[Settings → Pages](https://github.com/ricommender/pauls-erste-app/settings/pages) → Deploy from branch → `main` → `/(root)`.
