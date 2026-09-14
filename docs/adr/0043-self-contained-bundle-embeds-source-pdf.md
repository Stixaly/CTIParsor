# ADR-0043: The STIX bundle embeds the source document (`payload_bin`)

**Status:** Accepted
**Date:** 2026-09-14
**Deciders:** maintainer
**Relates to:** reverses the "no `payload_bin`, keep the bundle compact" choice
recorded only as a code comment in `stage4_stix_mapping.py` (no prior ADR);
fixes a latent bug found while answering a direct question about bundle
contents

## Context

`build_stix_bundle` has always tried to represent the original ingested file
(PDF, DOCX, …) as a STIX 2.1 `Artifact` object (§4.4) carrying its SHA-256
hash and MIME type — deliberately without the file's bytes, per the code's
own comment: *"we do NOT embed the binary content (payload_bin) to keep the
bundle compact."*

**That Artifact has never actually been created.** Checked directly against
a real, just-built bundle (`c4679b1c`, the Breeze/Comet job): `artifact` came
back `None`, despite `source_hash` being present and correctly reaching
`Report.external_references`. Reproduced directly:

```
>>> stix2.Artifact(mime_type="application/pdf", hashes={"SHA-256": "..."})
MutuallyExclusivePropertiesError: The (payload_bin, url) properties for
Artifact are mutually exclusive.
```

STIX 2.1's `Artifact` object requires **exactly one** of `payload_bin` or
`url` — an `Artifact` carrying only a hash is not valid STIX. The
`except Exception: artifact_obj = None` around the construction call has
been silently swallowing this on every single job ever processed. The
original design — hash-only, no bytes — was never realizable; the code has
been dead on arrival since it was written, and nothing surfaced that until
this question was asked directly and checked against a real bundle instead
of the docstring's claim about what it does.

### What the alternative would cost, measured

The Breeze/Comet job's source PDF is 260,196 bytes. Base64 (STIX's
`payload_bin` encoding) adds its standard ~33%: **≈347 KB** added to that
one bundle. For a single-report bundle (not the multi-gigabyte offline
install bundle of ADR-0040, an unrelated concern), that is a small, bounded
cost paid once per report, not a scaling problem.

## Decision

Embed the source file as `payload_bin` (base64), making each bundle a
self-contained artifact: the original document travels with the STIX data,
not just a hash pointing at a copy the recipient must already have.

`build_stix_bundle` gains a new parameter, `source_bytes: bytes | None`. The
three callers that already read the source file once to hash it
(`api/worker.py`'s `_run_pipeline` and `re_run_final_stages`, and `main.py`'s
CLI path) now also read its bytes and pass them through — no new I/O pattern,
the file is already open at that point in each caller. The `Artifact` is
built as:

```python
stix2.Artifact(
    mime_type=mime,
    payload_bin=base64.b64encode(source_bytes).decode("ascii"),
    hashes={"SHA-256": source_hash},   # kept: still useful for verification
)
```

Gated on `source_bytes` being present (not `source_hash` — a hash alone can
no longer produce a valid `Artifact` at all, which is the bug this ADR
fixes). When the source file cannot be read, no `Artifact` is created and
nothing else changes — `Report.external_references` still carries the
filename and hash independently, exactly as it does today.

## Options considered

| Option | Verdict |
|---|---|
| **A — drop the `Artifact` object entirely** | Rejected: the hash/filename already travel via `Report.external_references`, but a self-contained bundle — the original document retrievable from the STIX data alone — is real, requested value that reference-only never provided (and never actually attempted to, once the spec constraint is accounted for) |
| **B — set `url`** to wherever the API might serve the original upload | Rejected for now: no such endpoint exists today; inventing one to satisfy an `Artifact`'s schema, rather than because the capability is otherwise needed, is solving the wrong problem |
| **C — embed `payload_bin`** (chosen) | Fully self-contained bundle at a measured, bounded, one-time cost (≈347 KB on the report checked); makes the `Artifact` object finally valid STIX instead of permanently unreachable code |

## Consequences

**Easier:** a STIX bundle is now a complete artifact on its own — the exact
source document is recoverable from `base64.b64decode(artifact.payload_bin)`
without access to whatever system originally stored the upload, and its hash
is still there to verify it. The `Artifact` object this project's own
comments described has existed in name only until now.

**Harder / revisit:**
- Bundle size now scales with source document size, not just extraction
  output. A report with a large embedded video or a multi-hundred-page PDF
  will carry that weight in every exported bundle. No cap or opt-out exists
  yet — revisit if a real report makes this a problem, rather than guessing
  a threshold now.
- The source file must still exist on disk (in `uploads/`) at bundle-build
  time. `re_run_final_stages`, run long after the original upload could have
  been cleaned up, degrades to no `Artifact` at all in that case — the same
  failure mode `source_hash` already has today (`_sha256_file` returns `None`
  on a missing file), not a new one.

## Validation

Rebuild the Breeze/Comet job's bundle (`re_run_final_stages`, zero LLM cost)
and confirm: an `artifact` object now exists (previously `None`), its
`payload_bin` base64-decodes to bytes whose SHA-256 matches both
`artifact.hashes["SHA-256"]` and the original uploaded file on disk, and the
bundle's total size grows by an amount consistent with the measured ≈347 KB.
