# ADR-0073: A TLP marking is never guessed, and AMBER+STRICT ships as OpenCTI defines it

**Status:** Accepted
**Date:** 2026-10-03
**Deciders:** maintainer
**Amends:** ADR-0066 (OpenCTI's identifiers), ADR-0069 (what ships is what the UI says)

## Context

The October 2026 audit (B 8.1.3) reproduced this table on `d580e8c`:

| `STIX_TLP` or the job's `tlp_level` | Marking in the bundle |
|---|---|
| unset | TLP:WHITE (`clear` was the code's and `.env.example`'s default) |
| `AMBER` | TLP:AMBER |
| `AMBER+STRICT` | **TLP:WHITE** — the env default, because the level was unknown |
| `TLP:AMBER` (the usual spelling) | **TLP:WHITE** |
| `STIX_TLP=TLP:AMBER`, no level on the job | **no marking at all** |

`_tlp_marking` returned `None` for any value outside RED / AMBER / GREEN /
WHITE / CLEAR, and the caller fell back to the default, then to nothing. A
report imported under a restriction could leave in TLP:CLEAR, or unmarked,
into OpenCTI and from there to partners. The API also offered only four
levels: AMBER+STRICT, the TLP 2.0 level most CERTs use, did not exist.

The obstacle to adding it is upstream. STIX 2.1 predates TLP 2.0 and the
`stix2` library refuses any `tlp`-typed marking that is not one of the four
objects of the specification (`check_tlp_marking`, called at construction
and at serialisation). OpenCTI defines AMBER+STRICT itself:
`opencti-graphql/src/schema/identifier.js` fixes its id
(`MARKING_TLP_AMBER_STRICT`, `826578e1-40ad-459f-bc73-ede076f81f37`) and
resolves `{definition_type: 'TLP', definition: 'TLP:AMBER+STRICT'}` to it
statically; `stix-2-1-converter.ts` exports it with `definition_type:
"TLP"` (upper case), `name: "TLP:AMBER+STRICT"`, **no `definition`**, and
the platform's property extension.

## Decision

1. **One function owns the spelling.** `normalise_tlp` in
   `pipeline/stage4_stix_mapping.py` maps `white`, `TLP:amber+strict`,
   `Amber`… to `CLEAR | GREEN | AMBER | AMBER+STRICT | RED` and **raises** on
   anything else. `_tlp_marking` never returns `None`; a bundle always
   carries exactly one TLP marking.
2. **The default is AMBER.** `STIX_TLP` unset means AMBER; `.env.example`
   says `STIX_TLP=amber`. A deployment that wants CLEAR says so.
3. **A bad default stops the process.** `tlp_default()` runs at API start
   (`lifespan`), at worker start (`api.queue_loop.main`) and before a CLI
   run — a typo in `STIX_TLP` is a startup error, not a wrongly marked bundle
   an hour later.
4. **The API accepts the five levels** (`clean_tlp` in
   `api/routes/upload.py`, shared by the text and URL entry points) and
   stores the canonical form; the UI offers them. PAP keeps its four.
5. **AMBER+STRICT is emitted exactly as OpenCTI exports it**: a
   `MarkingDefinition` with `definition_type: "TLP"`, the name, OpenCTI's
   extension-definition (`ea279b3e-5c71-4632-ac08-831c66a786ba`) and
   OpenCTI's static id. Measured on stix2 3.0.2 and stix2-validator: the
   object builds, serialises, parses back (even without `allow_custom`), and
   validates with two SHOULD warnings — `{111}` (vocabulary value not lower
   case) and `{201}` (`definition_type` not `statement`/`tlp`) — accepted by
   choice, as `{103}`/`{302}` already are (ADR-0066).

## Options rejected

- **Keep the fallback, log a warning.** The failure is silent to the
  consumer; a warning in a worker log does not stop a TLP:RED report from
  leaving as CLEAR.
- **A `tlp`-typed marking with `definition: {"tlp": "amber+strict"}`.**
  `stix2` refuses it at construction; bypassing that with a subclass made an
  object `stix2.parse` then refused on the way back (every consumer that
  re-reads a bundle through the library breaks), and the validator adds
  `{401}` (custom markings should use `extensions`). It is also not what
  OpenCTI writes.
- **A `statement` marking "TLP:AMBER+STRICT".** Valid everywhere, but
  OpenCTI would import it as a new statement marking, not as its
  TLP:AMBER+STRICT: the restriction would not apply.
- **Emit AMBER for AMBER+STRICT until the CTI TC defines TLP 2.0 in STIX.**
  Loses the one thing the level adds (no sharing outside the organisation)
  on the platform that enforces it, for an unknown wait.
- **Make the level mandatory at import** instead of a default. Every CLI
  batch and every API call without a level would fail; a safe default plus
  a startup check gives the same guarantee without the friction.

## Consequences

- Bundles are TLP:AMBER unless the report was imported with its own level
  or `STIX_TLP` says otherwise. The previous CLEAR default is a one-line
  change back, made explicitly.
- `STIX_TLP=bogus` refuses to start the API, the worker and the CLI.
- `pipeline/stage4_stix_mapping.py` is the single source of the levels;
  `api/routes/upload.py` imports it. `TLP_AMBER_STRICT` and
  `OPENCTI_EXTENSION_ID` are module constants a validator can check against.
- Tests: `tests/test_provenance.py` (every spelling, the default, the
  OpenCTI id, no bundle without a marking, startup refusal),
  `tests/test_upload_route.py` and `tests/test_ingest_routes.py` (the five
  levels, canonical storage, 400 on an unknown one).
