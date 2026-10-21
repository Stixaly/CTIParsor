# ADR-0087: An ATT&CK release is a track a run selects

**Status:** Accepted
**Date:** 2026-10-18
**Deciders:** maintainer
**Relates to:** ADR-0059 (the run manifest hashes the ATT&CK files), ADR-0086
(each build records its manifest), ADR-0060 (the evaluation protocol and its
decision rule), ADR-0072 (select mode and its retrieval corpus), ADR-0073 (an
unknown setting fails closed, as a TLP level does)

## Context

The audit of 2026-10-17 recommends adding an ATT&CK v20 track without replacing
the experimental snapshots. Replacing them would mix two changes: the system's
evolution and the change of taxonomy. A score that moves could not be assigned
to either.

ATT&CK v20.0 came out on 2026-10-13. The release before it is v19.2
(2026-08-05), after v19.1 (2026-05-12) and v19.0 (2026-04-28).

Three facts made the question concrete.

- **No file said which release it came from.** The retrieval corpus's manifest
  read `attack_version: null`. `data/enterprise-attack.json`, the copy of
  mitre/cti it was built from, has no `x-mitre-collection` object, which is
  where a release records its version.
- **`scripts/download_attack.py` without an option fetches the master branch of
  mitre/cti**, which is now 20.0. A re-download would have changed the
  evaluation's gold mapping in silence, while the pipeline's index stayed on
  19.2.
- **A run recorded hashes, not a release.** The manifest of ADR-0059 hashed
  the data files. Nothing in it said which ATT&CK those hashes were, and nothing
  could select another.

## What was found (2026-10-18)

To name the release of the shipped files, each was rebuilt from the official
assets of v19.2 (mitre-attack/attack-stix-data) and compared.
`pipeline/data/attack_manifest.json` records the result.

| File | Against a rebuild from v19.2 |
|---|---|
| `data/enterprise-attack.json` (mitre/cti copy, sha256 `f7eaf37f…`, fetched 2026-09-27) | The same 26,085 objects, with the same `modified` dates, as the v19.2 asset (sha256 `dc1639…`). Only the serialisation differs: STIX 2.0 against 2.1 (`spec_version`, `labels`, `is_family`). No index reads those fields |
| `mitre_index.json` | Identical: the Enterprise, Mobile and ICS parts, and the 41 tactics |
| `attack_revoked.json` | Identical, except the date of the source |
| `attack_retrieval_corpus.json` | Identical, 17,350 entries |
| `attack_retrieval_embeddings.npy` | Byte-identical after re-encoding with all-MiniLM-L6-v2 |
| `mitre_embeddings_meta.json` | Byte-identical |
| `mitre_embeddings.npy` | The same entries; the vectors are equal to within 2e-7 |
| `gazetteer.json` | **Older than 19.2.** The 14 name variants 19.2 added are missing (G1056, G1057, S9041 to S9044) |
| `attack_relationships.json` | **Older than 19.2.** 237 pairs of 19.2 are missing, and it keeps 1 pair 19.2 no longer has (C0028 uses T1692.001) |
| The 615 CAPEC entries of `mitre_index.json` and `mitre_embeddings*` | From a CAPEC bundle whose version was not recorded |

The historical run `sel-dev-revoked-5d1bbe4` ran on exactly these files: the
hashes in its manifest match (`mitre_index.json` 52409d46…, the corpus
2c2eceb2…).

Out of scope, unchanged: `frontend/public/mitre_index.json` is another file
(the same 1,533 techniques, without `shortname`, and 39 tactics instead of
41). The
interface keeps reading that static file whichever track a run uses. (The
amendment of 2026-10-19 removes it: the interface reads the selected track's
index from the API.)

### From 19.2 to 20.0

`python -m evaluation attack-diff --old 19.2 --new 20.0`:

- **Enterprise:** 697 → 706 active techniques (9 new ids). The new ones:
  T1608.007 AI Result Poisoning, T1685.007 Impair Autonomous Defenses, T1696
  Anti-Automation Evasion (T1696.001 Automate CAPTCHA Completion, T1696.002
  Avoid CAPTCHA), T1697 Steal Application Specific Passwords, T1698 Indirect
  Prompt Injection, T1699 Direct Prompt Injection and T1700 AI-Enabled
  Exfiltration. No technique is revoked, deprecated or renamed, and no tactic
  changes. 31 descriptions change. Procedure examples: 17,136 → 17,636, on 242
  techniques.
- **Mobile:** 124 → 125 (T1476 is new).
- **ICS:** 97 → 104. Nine are new: T1701 Command and Scripting Interpreter and
  its six sub-techniques, T0869.001 DNS and T0869.002 Publish/Subscribe
  Protocols. T0807 and T0853 are deprecated, with no `revoked-by`.
- **Software, groups and campaigns:** 20 new in Enterprise (among them G1058 The
  Gentlemen, G1059 NIMBUS MANTICORE and S9050 Vidar).

## Decision

**1. A release is a track, selected per process by `ATTACK_RELEASE`.**
`pipeline/attack_data.py` defines the tracks.

- The **default track** is the files of `pipeline/data/`, unchanged. Its
  `pipeline/data/attack_manifest.json` holds the release (`"19.2"`), the
  `sources` (with their sha256), `matches_release` (what was found identical),
  `exceptions` (what was not) and `files` (the sha256 of each file).
- Any **other track** is a directory `pipeline/data/attack/<X.Y>/` with the same
  file names (`ATTACK_FILES`) and its own `attack_manifest.json`.
- `ATTACK_RELEASE` unset or empty selects the default track. So do `19.2`,
  `v19.2` and `default`. `20.0` (or `v20.0`) selects the v20 track. The `v` is a
  prefix only before a digit (`v` and `vdefault` are refused), and digits are
  ASCII.
- It is read per process. The loaders call `attack_data.resolve()` when they
  read, and cache what they read: change the setting before the process starts.
  The first `attack_data.current()` that resolves **fixes** the release for the
  process. `.env` is loaded when `stage3_llm` or `api.db` is imported, so a
  process could otherwise read the default track for Stages 2b and 2c and
  `ATTACK_RELEASE`'s after that import. A later call that resolves another
  version raises `UnknownAttackRelease` ("ATTACK_RELEASE changed from 19.2 to
  20.0 in this process; set it before the process starts"); the same version
  written another way (`v19.2`, empty) does not. `attack_data.reset()` forgets it,
  for tests. The API (`lifespan`), the worker (`api.queue_loop.main`) and the
  evaluation's `run` and `inhouse-run` resolve it when they start: a typo stops
  the process there, and the API and the worker log the release.
- **A value that names no track, or that is not a version number (a path), raises
  `UnknownAttackRelease`.** `run_document` checks it before Stage 1,
  `build_stix_bundle` before Stage 4 (a finalize reaches Stage 4 without
  `run_document`), and `build_manifest` too. There is never a fallback to
  another release: ADR-0073's rule for a TLP level.

**2. The run manifest records the release** (`api/run_config.build_manifest`).

- A new `attack` block: `release`, `default`, `requested`, `directory`,
  `manifest_sha256`, the sha256 of the source bundles per domain (16 hex
  characters, as the other hashes), `exceptions`, `built_with` (how the track was
  built, `null` for the default one) and `modified_files`: the files whose hash no
  longer matches the track's manifest, and the ATT&CK files that sit in the
  directory without being in it, listed as `<name> (not in the manifest)` (a local
  `mitre_embeddings_manifest.json` would change Stage 2c's thresholds). For those,
  the release the block announces is no longer proven.
- `data` hashes the files the process actually loads, and `attack_manifest.json`
  joins `_DATA_FILES`.
- `ATTACK_RELEASE` joins the captured environment.
- `stage3_settings` carries `attack_release`, so the Stage 3 checkpoint does not
  resume across tracks (Stage 3f reads the technique descriptions of the
  selected release). The checkpoints that exist are therefore invalidated once,
  when this change is deployed.

**3. A v20.0 track ships beside the default one.** `pipeline/data/attack/20.0/`
holds 39,900,662 bytes in nine files, committed like the default track. It is
built by `scripts/build_attack_release.py --release 20.0` from the assets of
release v20.0 of mitre-attack/attack-stix-data.

- **The assets are verified.** Each is checked against the sha256 GitHub
  publishes for it (the `digest` field of the releases API). Enterprise:
  `81113ba98afa2928…`, 55.3 MB. The three also match the git blob of the
  versioned `*-20.0.json` files at tag v20.0.
- **`scripts/download_attack.py --release X.Y` fetches them.** It checks each
  sha256 before renaming a file, and writes `release.json` beside them, in
  `data/attack-stix/vX.Y/`. It refuses an asset with no digest or no size, a URL
  that is not exactly the expected asset's, a stream that goes past the published
  size or ends with another one, and a published digest that differs from the
  sha256 the track's manifest records.
- **Contents** (the manifest gives the sha256 of each file): `mitre_index.json`
  holds 706 Enterprise, 125 Mobile, 104 ICS and 615 CAPEC entries; the retrieval
  corpus 17,845 entries; the curated relationships 20,849 pairs; the gazetteer
  1,866 name variants, against 1,827 on the default track.
- **Parity with the default track**, so that the two differ by ATT&CK only
  (except the default track's gazetteer and curated relationships, which
  predate 19.2: its `exceptions`): the
  CAPEC entries are the default track's, carried over; the revoked table and the
  retrieval corpus cover Enterprise only; there is no
  `mitre_embeddings_manifest.json`; the embedding model is the same. (A track
  built with another `TTP_EMBEDDING_MODEL` gets that manifest, so that Stage 2c
  reads its model and thresholds.)
- **The rebuild is deterministic on the build machine.**
  `build_attack_release.py --release 19.2` returns the shipped 19.2 files:
  byte for byte for `mitre_index.json` (with the CAPEC entries carried over),
  `attack_retrieval_embeddings.npy` and `mitre_embeddings_meta.json`; the
  retrieval corpus has the same entries (its own manifest names another
  source file and the release); `mitre_embeddings.npy` is equal to within 2e-7.
- The build writes into a neighbouring directory, then renames it. It refuses to
  overwrite a track without `--force`.
- `built_with.git_rev` is `null` for this track: the script was not committed
  when it was built.

**4. The evaluation maps the gold against one release.**

- `Catalogue.for_release` finds the release's Enterprise bundle by its sha256.
  For the default track it takes `data/enterprise-attack.json` at sha
  `f7eaf37f…`, else `data/attack-stix/v19.2/enterprise-attack.json` at sha
  `dc1639…`. Any other file is refused, and the message says what to download.
- A run with no `attack` block (an older run) is mapped on the default track.
- `run` and `inhouse-run` resume only on the release the run began with
  (`manifest.attack.release` of its `run.json`; an older run's is the default
  track's): another one stops the command with a message, and so does an unknown
  `ATTACK_RELEASE`, before any document is recorded as failed. `inhouse-score`
  maps with the run's release, as `score` does.
- `score` without an option gives the score it gave before: checked on
  `sel-dev-revoked-5d1bbe4`.
- `compare` requires the same mapping on both sides.
- `score`, `ttp-errors`, `compare` and `release-effect` warn on stderr when a
  run's manifest lists `modified_files`, and record them (`attack_modified_files`
  in the report). The score stands: it is not a refusal.
- `release-effect --a --b` takes `--old` and `--new` from the releases the runs
  ran on; an option has to be the release of the run it stands for, and two runs
  on the same release need both. It classes each parent technique on which
  two runs differ as `new_technique`, `new_subtechnique`, `status_changed`,
  `content_changed` or `unchanged`, the first that applies. Per class it gives
  ΔTP, ΔFP and ΔFN, and a "hybrid" F1: run A, with only that class's differences
  taken from run B. It lists the documents whose gazetteer entities or candidate
  lists differ.
- `attack-diff` writes the diff between two releases.

**5. The default does not change.** Making 20.0 the default asks for the paired
comparison of ADR-0060's rule (docs/eval/README.md). That rule is applied on
dev; the frozen test split is not consulted for this choice.

**6. What a v20 run can show on this gold.** The AnnoCTR gold is annotated with
the ATT&CK of 2022. It is mapped through the `revoked-by` chains of the
mapping's release.

- v20 revokes no Enterprise technique, so the mapped gold is the same under 19.2
  and under 20.0. T1562 and T1562.001, revoked for T1685 in 2026, are handled
  today by `attack_revoked.json` and Stage 3c (CHANGELOG, 2026-10-11, run
  `sel-dev-revoked-5d1bbe4`).
- An id new in v20 cannot be in this gold: a T1698 prediction counts as a false
  positive. A T1685.007 prediction can be a true positive at parent level,
  because its parent T1685 is in the gold.
- The 39 name variants the 20.0 gazetteer has beyond the default track's (14
  of 19.2, which the default gazetteer predates, and 25 of 20.0) appear in
  none of the 16 dev reports (searched case-insensitively, on word
  boundaries).

## Comparison on AnnoCTR dev

docs/eval/attack-v20-2026-10.md, at `5b98a49`, with fixed sampling and paired
runs.

- **The 19.2 reference reproduces the historical run exactly.**
  `sel-dev-a19.2-5b98a49` and `sel-dev-revoked-5d1bbe4` have the same
  techniques and the same candidates on all 16 reports. The system's effect
  between the two commits is zero, and so is the run-to-run spread.
- **Retrieval alone (no LLM).** The candidate ceiling of the select path is the
  same on both tracks: 0.884 in the chunk, 0.954 in the document, with about
  21 candidates per chunk.
- **20.0 against 19.2**: F1 parent 0.584 → 0.609, +0.025 [−0.019, +0.076].
  The difference is the same under either mapping.
- **Taxonomy effect on ids: none on dev.** No revoked or renamed id, and no
  technique new in v20 in any candidate list or prediction.
- **Every difference goes through the new descriptions and procedure examples.**
  `release-effect` puts 36 of the 41 (report, technique) differences, 32
  distinct ids, in `content_changed` and 5 in `unchanged`.
- **A parse failure moved.** Each run has one selection answer that did not
  parse, and it moved from the DarkSide report (19.2: 2 correct, 20.0: 8) to
  TA505. Without those two reports, the difference is +0.014 [−0.026, +0.042],
  with precision +0.041 [−0.015, +0.078].
- **ADR-0060's rule is not met** (the interval includes 0). The default stays
  19.2, and the 20.0 track is selectable.
- **Re-run on 2026-10-21** at `01aeea6`, with ADR-0072's cut-off salvage on
  both tracks. Neither run has a cut-off answer, and the difference is +0.003
  [−0.028, +0.028], with precision −0.001. The rule still fails, and on dev the
  two tracks cannot be told apart (addendum to docs/eval/attack-v20-2026-10.md).

## Consequences

- **+39.9 MB in the repository and in the image** (39,900,662 bytes).
- **The interface stays on the default track.** `frontend/public/mitre_index.json`
  is static. The API's ATT&CK search (`pipeline/mitre_db.py`) follows
  `ATTACK_RELEASE`. (Both corrected by the amendment of 2026-10-19.)
- **The ordinary-word policy of the gazetteer** (docs/gazetteer-ordinary-words.md)
  reviewed the forms of the default track only. The forms v20 adds are not
  reviewed. `GAZETTEER_POLICY` is `shadow` by default, so nothing is withheld on
  that ground.
- **A finalize uses the release of the process that serves it**, which is not
  necessarily the run's. The build record of ADR-0086 stores the finalize's own
  manifest, so the difference shows.
- **The Stage 3 checkpoints that exist are invalidated once**, on the first run
  after the update (decision 2).
- **OpenCTI ids follow the names of the track.** An `attack-pattern`'s id comes
  from its ATT&CK id (ADR-0066), so it is the same on both tracks. An
  `intrusion-set`, `malware` or `tool` id comes from the canonical name the
  track's gazetteer gives it: a group a release renames would get another id,
  and two bundles built on two releases would make two objects in OpenCTI.
  v20.0 renames none (`attack-diff`: 0 renamed software, groups or campaigns).
- **The default track's gazetteer and curated relationships stay older than
  19.2.** The `exceptions` of its manifest say so. Rebuilding them is a
  follow-up, and would change the default.
- **A rebuilt file is visible.** `modified_files` lists any file whose hash is
  not the one the manifest recorded, or that the manifest does not know.
- **`data/` needs the bundles to score.** `Catalogue.for_release` reads the
  release's Enterprise bundle from `data/` (git-ignored). `attack-diff` and
  `release-effect` read the three bundles of both releases in
  `data/attack-stix/`.

## Rejected

- **Replace the shipped files with v20.** It mixes the taxonomy and the system,
  and breaks the comparison with every past run.
- **One directory per track that also moves the default track.** Every path
  would change, for no gain.
- **Take the bundle of mitre/cti master.** It is not versioned, and no digest is
  published for it.
- **Fall back to the default track for an unknown value.** A run would be given
  another release than the one it asked for, and say nothing.
- **Not commit the v20 track and let everyone build it.** The track could not be
  selected from the image.

## Implementation

- `pipeline/attack_data.py` (new): `ATTACK_FILES`, `current`, `release`
  (a value resolved without touching the process's release), `is_version`,
  `reset`, `resolve`, `available`, `describe`, `modified_files`,
  `UnknownAttackRelease`.
- Loaders that call `attack_data.resolve()` at read time: `pipeline/aliases.py`,
  `pipeline/mitre_db.py`, `pipeline/stage2b_gazetteer.py`,
  `pipeline/stage2c_ttp_semantic.py`, `pipeline/stage4b_graph_completion.py`,
  `pipeline/ttp_retrieval.py` (and `pipeline/stage3f_ttp_select.py`, which lets
  an unknown release through its definitions cache). `pipeline/orchestrator.py::run_document` and
  `pipeline/stage4_stix_mapping.py::build_stix_bundle` check the release.
  `pipeline/stage3_llm.py::stage3_settings` carries it.
- `api/run_config.py`: the `attack` block, `ATTACK_RELEASE` in `_CAPTURED_ENV`,
  `attack_manifest.json` in `_DATA_FILES`.
- `scripts/build_attack_release.py` (new); `scripts/build_indexes.py` gains
  `--out-dir` and `--capec-index`; `scripts/download_attack.py` gains
  `--release` and `--out`.
- `evaluation/attack.py`: `Catalogue.for_release`, `release_diff`,
  `release_change`. `evaluation/__main__.py`: `--attack-release` on `prepare`,
  `score`, `ttp-errors`, `compare`, `release-effect` and `retrieval`; the commands
  `attack-diff` and `release-effect`.
- `pipeline/data/attack_manifest.json`, `pipeline/data/attack/20.0/`; the
  `pipeline/data/attack/*/` globs in `REUSE.toml`; `ATTACK_RELEASE` in
  `.env.example`.

Tests:

- `tests/test_attack_data.py` (37 test functions): the selection and its
  refusals (a `v` without a digit, non-ASCII digits), the release a process
  keeps, `resolve`, `modified_files` (a file outside the manifest included),
  every shipped track against its manifest, the run manifest, the Stage 3
  fingerprint, the check before Stage 1 and before Stage 4b, the start of the API
  and of the worker, every loader on the selected track.
- `tests/test_build_attack_release.py` (23): the files built from the three
  domains, Enterprise-only tables, the manifest (no absolute path, the build
  stamp), the embeddings manifest by model, a wrong digest, a bundle that is not
  the published file, a collection of another release, no overwrite without
  `--force`, a failed build leaves no track.
- `tests/test_download_attack.py` (24): digests, sizes, URLs, a refusal leaves
  nothing behind, the track manifest's agreement.
- `tests/test_evaluation_attack.py` (32): the bundle found by hash, `release_diff`
  and `release_change`, `score`, `ttp-errors`, `compare` and `release-effect`
  across releases, a run resumed on another or an unknown release, the `.env`
  file, runs whose files were modified.
- `tests/test_run_config.py`, `tests/test_bundle_builds.py`: the manifest has an
  `attack` key. `tests/conftest.py`: an autouse fixture unsets `ATTACK_RELEASE`
  and forgets the release a process fixed (`attack_data.reset`), so a
  developer's `.env` cannot put the suite on another track.
- Run locally on 2026-10-18 on the code of `5b98a49`: the full suite, 2,937
  passed and 9 skipped (`SKIP_HEAVY_MODELS=1`); `ruff check .`, mypy (135
  files), `reuse lint` and `scripts/check_doc_claims.py` clean.

## Amendment (2026-10-19): the interface reads the index of the selected track

The Consequences above leave the interface on `frontend/public/mitre_index.json`.
That file was not a track's. It came with the initial commit (2026-06-05), and no
script writes it. It held the same 1,533 techniques as the default track's
`mitre_index.json`, with these differences:

- domains spelled `enterprise`, `mobile` and `ics` (not `enterprise-attack`,
  `mobile-attack` and `ics-attack`);
- no technique `shortname`;
- descriptions cut at 161 characters (300 in a track);
- 39 tactics instead of 41. The two missing are mobile: `TA0038` Network Effects
  and `TA0039` Remote Service Effects.

The amendment makes these changes:

- **`GET /api/attack/index`** (`api/routes/attack.py`) serves the
  `mitre_index.json` of the track the API runs, unmodified. Its release is in
  `X-Attack-Release`. The ETag is the file's sha256 and `Cache-Control` is
  `no-cache`. A reload gets a 304 while the file is unchanged. After a restart on
  another `ATTACK_RELEASE`, the browser gets the new track's index, never the one
  it cached. A track without the file answers 404, not with the default track's
  file.
- **The Coverage page and `useMitreSearch` share one query** (`useAttackIndex`).
  The page shows the release next to the report's name. `useMitreSearch` has had
  no caller since the initial commit. It is kept on the same index, so a picker
  built on it would not bring the static file back.
- **The static file is removed**, along with its entries in `REUSE.toml` and
  `THIRD_PARTY_NOTICES.md`. A fallback to it would show the default track's names
  under an API that runs another track: the bug this amendment removes.
- **The column check runs on every track.**
  `test_every_enterprise_tactic_in_the_index_has_a_column` reads the index of each
  track `attack_data.available()` lists, not only the one the process selects.
  `frontend/src/components/coverage/tactics.test.ts` holds the page's own columns
  to the same rule. The columns moved to `components/coverage/tactics.ts`. Both
  tracks have the same fifteen enterprise tactics, so the columns do not change.
- **The index weighs about 750 KB instead of 440 KB**: 749,660 bytes for 19.2 and
  758,174 for 20.0, against 440,155. Nothing compresses it. A browser downloads it
  once per index: later loads get a 304 with no body.
- **Correction.** The Consequences say the API's ATT&CK search follows
  `ATTACK_RELEASE` through `pipeline/mitre_db.py`. No route calls
  `mitre_db.search`. The code that reads `mitre_db` is Stages 3c and 3f, TTP
  retrieval, the phase band of `/api/jobs/{job_id}/coverage/artifacts`
  (`pipeline/detection/phases.py`) and the evaluation. `GET /api/attack/index` is
  the first route that serves the index.

Tests: `tests/test_attack_api.py` (each committed track served unmodified with
its release, the ETag and the 304, the 19.2 ETag sent to an API on 20.0 gets the
20.0 index, a track without an index answers 404);
`tests/test_detection_phases.py` (the column check on each track, and a check
that both tracks are listed); `frontend/src/components/coverage/tactics.test.ts`,
`frontend/src/hooks/useMitreSearch.test.tsx` (on 20.0 the search finds `T1698`;
on 19.2 it does not), `frontend/src/api/client.test.ts` (`fetchAttackIndex`).
