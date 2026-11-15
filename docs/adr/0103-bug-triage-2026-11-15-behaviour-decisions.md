# ADR-0103: Bug triage of 2026-11-15: behaviour decisions

**Status:** Accepted (2026-11-15)
**Date:** 2026-11-15
**Deciders:** maintainer
**Relates to:** ADR-0070 (the vendored Snort parser), ADR-0086 (bundle
staleness scopes), ADR-0102 (the previous triage)

## Context

A second triage covered the tracker issues #875 to #923. Six agents checked each
issue against the code of `main` before anything was changed; 41 were real and
are fixed, each with a regression test that fails without the fix. This page
records the choices where the code could have gone another way, the issues
closed without a fix, and the two left open for a decision.

## Decisions

1. **#922: the export's `filename=` is ASCII; the report's own name travels in
   `filename*`.** A `Content-Disposition` header is latin-1, so a Cyrillic report
   name made the ZIP export answer HTTP 500. `filename=` now carries an ASCII slug
   (`_ascii_slug`, fallback `report`), and `filename*=UTF-8''...` (RFC 5987) is added
   only when the name differs from that slug. `_safe_slug` is unchanged: it still
   names the files inside the archive.
2. **#894: `make .secrets/db_password` reads `.env` as text.** The recipe no
   longer sources the file, so a space, a `#` or a `$` in the password is kept and
   a CRLF line ending is removed, as `setup.sh` (`env_value`) already does. A value
   written between quotes now keeps its quotes in the secret file; the passwords
   `setup.sh` generates are hexadecimal and are not affected.
3. **#917: only the user-info part of a URL is not an email.** `evil.com` in
   `http://user:pass@evil.com/` no longer yields `pass@evil.com`; an address in a
   query (`?email=a@b.com`) is still extracted. The authority also ends at `?` and
   `#`.
4. **#920: a multicast or IPv4-mapped address is read as what it is.** `224.0.0.1`
   and `ff02::1` report `non_routable_address`; `::ffff:8.8.8.8` is judged as
   `8.8.8.8`.
5. **#918: the manifest's thresholds apply only to the model that wrote them.**
   When the active embedding model is not the manifest's, the thresholds are
   ignored. The corpus cache was already refused in that case, so only the status
   shown to the analyst changes.
6. **#905: `{"selected": []}` is a provisional abstention**, like a bare `[]`: a
   later answer in the same reply still counts.
7. **#912: `chunk_text` counts the separator.** Chunks used to exceed `max_chars`
   by two characters per joined unit.
8. **#890: `add_manual` rejects an empty term and falls back to the term when
   `display` is blank.** The `deny` path was already refused by the route and is
   unchanged.
9. **#895: only the missing final newline of `.env` is fixed.** The `sed` of the
   same helper only receives constants.
10. **#886 / #887: the control sample rate must be finite, and auto-accept runs in
    one transaction** (`with transaction(conn)` in the worker, since `pipeline/`
    does not import `api/`).
11. **Frontend (#875 to #885).** A `reader` no longer sees "Remove job"; the Coverage
    page shows an error with a Retry instead of "0 rule" when the rules fail to
    load, looks rules up by batches of 500, and resets when the job changes; the
    Dashboard download uses `downloadBundle` (its suffix becomes `_stix.json`, as in
    Review and Graph); the stage `1f` is ordered as 1.5.

## Closed without a fix

- **#888**: `PipelineConfig.from_env()` has no caller outside tests.
- **#889**: no caller passes `re.VERBOSE`, `re.UNICODE` or `re.LOCALE`; the fallback to
  `re` for unmapped flags is deliberate.
- **#891**: the revision comes from `git rev-parse` or `github.sha`, both lowercase.
- **#896**: the `Dockerfile` sets `HF_HOME`; a container cannot lack it.
- **#907, #908**: the graph completion only receives objects built by Stage 4; they
  never carry a string `aliases` or a `null` confidence.

## Left open

- **#897**: the 20 % cap of the title match is computed on the candidate set on
  purpose (see `relevance.py`); changing its base needs a measurement.
- **#914**: an alias held by two gazetteer identities goes to the first on a given
  span; emitting both needs a policy (ADR-0021).

## Consequences

- Stored Sigma rule atoms still hold `www.` domains (#900) and Sigma rules with a
  numeric `tags:` were dropped at ingestion (#904): the Sigma corpora must be
  re-ingested for the fix to reach stored data.
- The extraction fixes (#905, #909, #910, #912, #913, #915 to #921) change what a
  new run extracts: bundles built before them are stale with the scope
  `extraction` (ADR-0086).
- #910 leaves one margin: the chat-marker defusing runs after the report is fitted
  to the prompt, so a report full of such markers can still lose a few characters at
  the end of the prompt.
- The vendored Snort parser (#789 to #793) is still not patched (ADR-0102).
