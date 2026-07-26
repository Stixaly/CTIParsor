# Screenshots

Product screenshots referenced by the top-level [`README.md`](../../README.md#screenshots).

## Files

| File | Screen |
|------|--------|
| `review-page.png`            | Review workspace — annotated entities, marginalia, relationships (hero) |
| `homepage.png`               | Dashboard — upload + kanban board |
| `review-page-PDF-view.png`   | Review — inline Source view (PDF) |
| `graph-report-view.png`      | STIX relationship graph (OASIS icons) |
| `sigma-rules.png`            | Detection-coverage matrix (ATT&CK × Sigma) |
| `relationships-settings.png` | Relationship policy — canonical STIX links |
| `Sigma-rules-settings.png`   | Settings — Sigma corpus management |

## Re-capturing / adding shots

- Serve the app (production build via FastAPI at `:8000`, or the Vite dev server) and open the relevant route.
- Keep the set on **one theme**, ~1440px wide, standard zoom. Crop to the app content.
- **Format:** PNG, ideally < 500 KB each — run through an optimiser (`pngquant`, `oxipng`, squoosh.app).
- **Redact** anything sensitive before committing.
- If you rename or add files, update the `<img src=…>` links in the top-level README's **Screenshots** section to match.
