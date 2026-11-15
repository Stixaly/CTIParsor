# ADR-0102: Bug triage of 2026-11-14: behaviour decisions

**Status:** Accepted (2026-11-14)
**Date:** 2026-11-14
**Deciders:** maintainer
**Relates to:** ADR-0070 (the vendored Snort parser), ADR-0086 (bundle
staleness scopes), ADR-0098 (Stage 2e asks its model), ADR-0099 (Stage 2d off
by default)

## Context

A triage of the tracker (#739 to #841) produced one batch of fixes on the
branch `claude/bug-triage-fixes`, each with a regression test named after its
issue number (`tests/test_*bugfix_*.py`). Most fixes have one obvious
behaviour. This page records the ones where the code could have gone another
way, the issues closed without a fix, and the ones left open upstream.

## Decisions

### Verdict and ledger

1. **#785: a bundle with no object is INVALID; a bundle whose `objects` is not
   a list is INVALID; an empty subset is VALIDATED.** `validate_bundle()` itself
   accepts `objects: []`, because Stage 5 checks the bundle without the trusted
   baseline objects (`validation_json`) and that subset can legitimately be
   empty. The whole bundle is checked before the filter, by
   `validate_without_trusted()` (used by `validate_and_export` and the worker's
   finalize): no object at all is INVALID with a message, and the file is
   written with the `_invalid` suffix. `null` or an object in place of the list
   cannot be a bundle. (#783 makes the same function answer INVALID instead of
   raising `TypeError`; #787 skips the Stage 3doc pass after Stage 3 failed:
   verdict and journal only.)

### Worker and database

2. **#750: a depth counter, `_tx_depth`, tracks nested `with get_conn()`.** An SQL
   error caught inside a nested `with` leaves the outer transaction in error
   state; it is no longer autocommitted from under the outer block. The outer
   `transaction()` decides.

### Stage 2

3. **#771: GLiNER reads its local cache first and falls back to the download on
   any exception, as CyNER does.** The model class is the same; only the loading
   order is shared.
4. **#770: an annotation in parentheses is not emitted as an alias.** In
   "Cozy Bear (NOBELIUM)", the name before the annotation is kept and
   "NOBELIUM" is not emitted; a value never keeps an unclosed "(".

### Stage 3 and Stage 4

5. **#772: `null` is accepted for `description` and `confidence`; a TTP given by
   its `mitre_id` alone is kept**, then dropped by Stage 3c if the name it
   resolves is empty.
6. **#777: the first TTP wins.** Two TTPs with one MITRE id give one
   AttackPattern; the duplicate's description and references are not merged
   into it. The ledger records the duplicate as "merged".

### API and authentication

7. **#759: an upload whose file name is invalid (NUL byte, lone surrogate) is
   refused with 400.**
8. **#740: two concurrent creations of one OIDC user name raise `AuthError`
   (409) and are tried again,** not a 500.

### Frontend

9. **#820: `fetchMe` no longer sets the CSRF token; `AuthContext` does, with a
   generation counter.**
10. **#814: the Policy page is read-only until its GET has answered; a failure
    shows an alert and a Retry button.** Until then Save cannot write over a
    policy that was never read.

### Not fixed here

11. **#789 to #793 (Snort parser):** the parser is vendored (ADR-0070). The
    defects are reported upstream, not patched in the copy.

## Closed without a fix

| Issue | Why |
|---|---|
| #745 | `HEAD` is absent from the `APIRoute` methods |
| #749 | the lock is an `RLock` |
| #763, #810, #817, #818 | closed as not reproducible or by design (see each issue) |
| #788 | relationship ids are `uuid4`: not deterministic by design |
| #821 | the serialization was checked by a test; it holds |
| #757, #739 | already fixed |
| #835 | fixed by d8405d5; not verified on a fresh stack |

## Consequences

- The behaviours above are tested by the regression tests of each issue.
- `BUNDLE_AFFECTING` carries two entries for this batch (extraction and
  mapping scope, ADR-0086): bundles built before the fixes are reported stale.
- The decisions on #785, #750 and #777 differ from what a reader of the
  issues would expect; a change to any of them needs a new ADR.

## Limits

- The reasons for the issues closed without a fix are in each issue's closing comment: #763 (a job
  refused because the queue is full is marked `failed` and its baseline row removed, pinned by
  `test_run_pipeline_async_rejects_when_queue_is_full`), #810 (the file named in the issue does not exist
  in the repository or its history), #817 (a mutation's state starts fresh on each call, so the two
  banners cannot coexist), #818 (ADR-0097: the front no longer reads a cookie), #745 (the `@router.get`
  routes register GET only, so HEAD answers 404 at routing) and #749 (the logging handler lock is
  re-entrant).
- #835 stays unverified on a fresh stack.
