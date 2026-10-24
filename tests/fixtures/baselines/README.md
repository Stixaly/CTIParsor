# Baseline STIX fixtures (ADR-0090)

Hand-written bundles that the baseline parser (`pipeline/baseline_stix.py`) reads in later lots. Checked by `tests/test_baseline_fixtures.py`.

- `opencti_report.json`: an OpenCTI 2.1 export in the shape of `stix-2-1-converter.ts` (report, author identity, TLP:AMBER marking without `definition`, APT29 intrusion-set with alias Cozy Bear and `G0016`, malware, attack-pattern T1059.001, indicator + ipv4-addr + `based-on`, file SCO, `uses` and `indicates`, `extensions` on every object, bundle `spec_version`); for families, TLP, copied objects and the matching of I2.
- `opencti_report.txt`: the report text to match against `opencti_report.json`: it names Cozy Bear (matched) and the file's SHA-256 (matched), a malware and a technique the bundle lacks (new: SUNBURST, T1566.001) and not the bundle's IPv4 (baseline only); the bundle's malware and T1059.001 are not named either.
- `misp_indicators_only.json`: MISP-style (misp-stix 2.1) export (creator identity, TLP marking, report) whose Indicators (`pattern_type: stix`) have no SCO, among them `[file:hashes.MD5 = ... OR file:hashes.'SHA-256' = ...]` and `[domain-name:value = ...] AND [url:value = ...]`, `misp:*` labels and `x_misp_*` properties; for compound patterns and the Indicator alone.
- `rules.json`: Indicators of `pattern_type` yara, sigma (one accepted, one that `check_pattern` refuses: no condition) and suricata; for the `baseline_rule_refused` exclusion.
- `invalid_objects.json`: valid objects plus a malware without `is_family`, an indicator whose id is not a UUID, and two versions (`modified` differs) of one threat-actor; for the exclusion by object and for versions.
- `stix20.json`: a STIX 2.0 bundle (`spec_version: "2.0"`, objects without `spec_version`); for the refusal with a 400.
- `two_reports.json`: two reports sharing one object (APT29) and each owning one malware; for the choice of the Report (D4): scope, refusal without `baseline_report_id`.
- `report_with_confidence.json`: a report with `confidence: 85`, `x_opencti_*` properties and the OpenCTI extension; for the upsert (D1): `confidence` and properties kept.
- `refs_outside.json`: objects whose `created_by_ref` and `object_marking_refs` point at ids that are not in the bundle; for the warning without exclusion (§1.7).

Provenance of the ids: foreign ids are UUIDv4 from a fixed seed; observables (`ipv4-addr`, `file`) carry the id stix2 computes; the TLP:AMBER id is OpenCTI's `MARKING_TLP_AMBER_ID`, the standard STIX one. The id of OpenCTI's property extension is the one `pipeline/stage4_stix_mapping.py` already carries; the ids of its SCO and MITRE extensions are the `STIX_EXT_OCTI_SCO` and `STIX_EXT_MITRE` constants of OpenCTI's `src/types/stix-2-1-extensions.ts` (opencti-master, 2026-10-01), checked.

Observable values belong to nobody: addresses in 198.18.0.0/15 (benchmarking range), domains under `.test`.
