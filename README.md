# Pauls erste App – Security Intelligence

Öffentliches Browser-Dashboard, optimiert für iPhone. Fokus: Microsoft 365, Windows, Azure, Sophos und VMware.

## Veröffentlichung

GitHub → **Settings** → **Pages** → **Build and deployment** → **Deploy from a branch** → Branch **main**, Folder **/(root)** → **Save**.

Nach erfolgreichem Pages-Deployment: https://ricommender.github.io/pauls-erste-app/

## Aktueller Funktionsstand

- UI, Responsive-Ansicht, Technologien-/Kategorie-Filter, Suche und Management-/Technik-Ansicht vorhanden.
- `data.json` enthält bewusst keine synthetischen Meldungen; Live-Feed-Erfassung ist noch nicht online eingerichtet.
- Automatische 08:00-E-Mails sind **nicht aktiviert**. Dafür braucht es einen Backend-Workflow und Maildienst mit Secrets. Niemals API-Keys ins öffentliche Repository schreiben.
- KI-gestützte Zusammenfassungen sind noch nicht aktiviert.

Priorisierung ist keine Aussage über interne Betroffenheit. Quelle und Herstellerhinweise validieren.
