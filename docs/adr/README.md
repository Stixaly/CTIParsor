# Architecture Decision Records

Each ADR records one significant decision: its context, the options weighed, the
choice, and the consequences. They're append-only — supersede rather than rewrite.

| # | Title | Status |
|---|---|---|
| [0002](0002-concurrent-report-ingestion.md) | Concurrent report ingestion | Accepted |
| [0004](0004-extraction-quality-enhancements.md) | Extraction quality enhancements (embeddings, GLiNER, doc-context, self-verify) | Accepted (retroactive) |
| [0005](0005-ioc-extraction-defang-robustness.md) | IoC extraction & defang robustness | Accepted (retroactive) |
| [0006](0006-multi-corpus-detection-ingestion.md) | Multi-corpus detection-rule ingestion | Accepted |
| [0007](0007-in-app-configuration-panel.md) | In-app configuration panel (keys + corpora) | Proposed |
| [0008](0008-detection-coverage-matrix.md) | Per-report detection-coverage matrix | Accepted |
| [0009](0009-stix-trust-and-provenance.md) | STIX trust & provenance (evidence labels, consensus, markings) | Accepted |
| [0010](0010-default-sigma-corpora-and-dedup.md) | Default multi-repo Sigma corpora + cross-corpus deduplication | Accepted |
| [0011](0011-ttp-extraction-precision.md) | TTP extraction precision (thresholds, margin gate, TTP self-verify, subsumption) | Accepted |
| [0012](0012-hallucination-measurement-and-canonicalization.md) | Hallucination measurement, entity canonicalisation & relationship precision | Accepted |
| [0013](0013-graph-completion.md) | STIX graph completion (alias fallback, ATT&CK grounding, transitive, long-distance) | Accepted |
| [0014](0014-observable-driven-detection-proposals.md) | Observable-driven detection proposals (rule atom index, IDF relevance, platform) | Accepted |
| [0015](0015-multi-format-detection-matching.md) | Multi-format detection matching (Suricata + YARA adapters, per-format IDF) | Proposed |
| [0016](0016-report-derived-sigma-synthesis.md) | Report-derived Sigma rule synthesis (gated templates, deterministic ids) | Proposed |
| [0017](0017-provenance-based-rule-dedup.md) | Provenance-based rule dedup (`related:` folding, technique union) | Proposed |
| [0018](0018-technique-idf-ranking.md) | Technique-IDF ranking (breaks the ~1,400-rule score plateau) | Proposed |

**Numbering notes**
- `0001` and `0003` are unused gaps (early informal decisions never filed).
- `0004` and `0005` were referenced in code (`ADR-004 P*`, `ADR-005`) before being
  filed; documented retroactively to match the implementation.
- The coverage matrix is **0008** — earlier drafts (and ADR-0006/0007) called it
  "ADR-0005"; that number belongs to IoC/defang robustness. References were repointed.

## Dependency sketch

```
0004 extraction quality ─┐
0005 IoC/defang ─────────┤→ better structured intel
0009 trust & provenance ─┘        │
   ▲   measured & extended by     │
   └── 0012 hallucination metric  │
       + canonicalisation         ▼
          ▲            0008 coverage matrix ◄── consumes techniques
          │               ▲   implemented by
 canonical names         └── 0006 multi-corpus rules ── managed by ── 0007 settings panel
 feed node identity          ▲   extended by
          │                  ├── 0010 default corpora + dedup
          │                  │      └── 0017 fixed by: dedup_key alone folded 11
          │                  │          of 11,396 rules; `related:` folds 5,036
          │                  │          and corrects 0014's IDF denominator
          │                  └── 0014 observable-driven proposals ◄── consumes IoCs (0005)
          │                         ▲   plateau broken by
          │                         ├── 0018 technique-IDF ranking ── needs 0017:
          │                         │      a technique's document frequency is
          │                         │      meaningless if rules are counted twice
          │                         ▲   generalised to N formats by
          │                         ├── 0015 multi-format matching (suricata + yara)
          │                         │       └── scopes IDF per format so 0014's
          │                         │           Sigma scores survive a 7.5× store
          │                         └── 0016 sigma synthesis — fills the gap 0014
          │                                 leaves (reuses its observables + IDF,
          │                                 and 0015's hostname gate)
          └── 0013 graph completion (denser edges, same precision gate)
```
