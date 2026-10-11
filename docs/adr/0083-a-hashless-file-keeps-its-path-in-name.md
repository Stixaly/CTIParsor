# ADR-0083: A file named without a hash keeps its path in `name`, as OpenCTI identifies it

**Status:** Accepted
**Date:** 2026-10-11
**Deciders:** maintainer
**Relates to:** ADR-0066 (STIX ids are OpenCTI's standard ids), the STIX
relationship review of 2026-10-02 (point 5, embedded references)

## Context

The October 2026 audit (B 8.1.12) found that a file the report names with
its path, `C:\Users\Public\it's.exe`, ships as a File SCO whose `name` is
the whole path, and an Indicator `[file:name = 'C:\\Users\\Public\\it\'s.exe']`.
STIX 2.1 puts the file's name in `name` and its directory in a Directory
SCO (`path`) that the File references through `parent_directory_ref`. The
audit proposed that split, with the pattern
`[file:name = 'it\'s.exe' AND file:parent_directory_ref.path = 'C:\\Users\\Public']`.

The two standards a bundle has to satisfy disagree on what identifies such a
file:

- **STIX 2.1**: a File's deterministic id is computed from `hashes`, `name`,
  `parent_directory_ref` and `extensions` (the `stix2` library, OASIS's
  reference implementation: `File._id_contributing_properties`). Two
  `svchost.exe` in different directories have different ids.
- **OpenCTI**: a StixFile's standard id is computed from its hashes or, with
  none, from `name` alone (`opencti-graphql/src/schema/identifier.js`, whose
  comment marks what it leaves out: `// hashes, name, (!) extensions,
  parent_directory_ref`). Its pattern-to-observable conversion keeps only the
  comparisons on id-contributing properties, so `parent_directory_ref.path`
  is dropped there too.

A file a report names by its path almost never comes with a hash in the same
row: Stage 2 extracts paths and hashes as separate observables. So the split
would hit exactly the case where OpenCTI identifies a file by its name: the
`svchost.exe` an attacker dropped in `C:\Users\Public` and the legitimate one
in `C:\Windows\System32` would become **one** observable on import. The
location is the indicator.

## Decision

A File SCO built from a file name or path without a hash keeps the value as
the report wrote it in `name`, path included, with no Directory and no
`parent_directory_ref`; its Indicator compares `file:name` to that value.
This is the OpenCTI behaviour CTIParsor already had; the ADR records it as a
choice so that it is not "fixed" toward the split.

Measured on 2026-10-11 against OpenCTI's rule (`uuidv5` in the OASIS
namespace over the canonical `{"name": …}`): the id CTIParsor ships for a
hashless file equals OpenCTI's standard id for the same StixFile, for a full
Windows path, another directory and a bare name. An import therefore reuses
the observable rather than creating a second one, and the two `svchost.exe`
stay two observables.

When an export profile for strict STIX exists (the audits' T12, lot 3.1),
that profile splits name and directory; the OpenCTI profile keeps this one.

## Consequences

- OpenCTI: distinct files stay distinct, and their ids match the platform's.
- Other STIX consumers (MISP, another TIP) read a path where the
  specification expects a file name. The bundle stays valid: `name` is a
  string, and the validator accepts it.
- A file with hashes is unaffected: Stage 4 builds it from the hashes, and
  both standards identify it by them.
- `tests/test_file_identity.py` holds the decision: the name as written, no
  directory reference, an id equal to OpenCTI's, two directories two ids.
