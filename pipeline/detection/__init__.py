"""Detection-rule ingestion (ADR-0006).

Adapters parse heterogeneous rule corpuses into normalized `DetectionRule`
records.  Only `SigmaAdapter` is implemented today; `RuleCorpusAdapter` is the
seam for future formats.
"""
