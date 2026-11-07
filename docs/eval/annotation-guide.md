# Annotation guide — in-house evaluation set (version 1)

The in-house set measures what AnnoCTR cannot: the application reading the
**original file** (PDF, DOCX, HTML), IoCs, relationships, and cases where a
report mentions a behaviour without saying it happened. See
`evaluation/inhouse.py` for the file format and ADR-0060 for the protocol.

## 1. Before you start

* One folder per report: `data/eval/inhouse/<doc_id>/source.<ext>` and
  `gold.json`. `python -m evaluation preannotate <file> --doc-id <id>` creates
  both. The draft is the pipeline's output: **it is biased towards what the
  pipeline already finds.** Read the whole report and add what it missed,
  not only delete what it got wrong.
* Annotate a layer **completely or not at all**, then list it in `layers`.
  A layer that is not listed is not scored — an unannotated fact is not an
  absent fact.
* Set `status` to `gold` only after a full pass. Note `annotator`,
  `annotated_at` and the time you spent (in `note`, free text).
* Pick reports that differ: short/long, PDF/DOCX/HTML, IoC tables, scanned
  pages, figures, several actors. A set of similar reports measures one case
  many times.

## 2. IoCs (`iocs`)

* Annotate every indicator the report gives **as an indicator of this
  activity**: IP, domain, URL, e-mail, hashes, CVE, file names and paths,
  registry keys, mutexes.
* Write the **refanged** value (`evil[.]com` → `evil.com`), hashes as given
  (case is ignored when scoring).
* Include IoCs that sit in tables, appendices, figures and screenshots —
  those are exactly what ingestion loses.
* Do **not** annotate legitimate infrastructure the report names as abused
  or benign (`update.microsoft.com` used for a lookalike comparison); add it
  to `negatives` if the pipeline is likely to pick it up.

### 2.1 Observables that are not IoCs (`observables`)

A report often lists, in an IoC table or a YARA rule, values that are real
but indicate nothing: a detection on them would fire on every machine. Put
them in `observables`, not in `iocs` (ADR-0095):

    "observables": [{"type": "file", "value": "C:\\Windows\\System32\\rundll32.exe",
                     "why": "legitimate", "quote": "..."}]

* `why: legitimate` — a file or registry key every system of its kind has:
  a Windows binary or DLL in its own directory or bare (`rundll32.exe`,
  `comsvcs.dll`, `kernel32.dll`), a standard key (`...\CurrentVersion\Run`,
  `...\Winlogon\SpecialAccounts\UserList`), a standard Unix file
  (`.bash_history`).
* `why: no-ioc-type` — a value no IoC type fits: a Telegram handle, a GUID,
  a device name (`\\.\EPMNTDRV`). Give it a descriptive `type`
  (`telegram_handle`, `guid`, `device`).
* `quote` — the sentence or table cell that names it.
* Stays an IoC: a system name **outside its directory**
  (`C:\Users\Public\svchost.exe`, a masquerade), a near name (`schtask.exe`),
  a file given with a hash, a key the attacker created
  (`...\Services\EvilSvc`), and a store the attacker copied: the SAM,
  SECURITY and SYSTEM hives (`HKLM\SAM`), `ntds.dit`, an LSASS dump.
* Same value in `iocs` and `observables`: never. If the report uses the same
  name both ways (the real `rundll32.exe` and a dropped copy), the IoC is the
  copy's path or hash.

The `observables` list is part of the `iocs` layer: annotate it with that
layer, completely. The scorer counts an extracted observable neither as a
hit nor as a false positive, and reports how many the bundle wrongly turned
into an Indicator (`observables.as_indicator`).

## 3. Named entities (`entities`)

Same definitions as AnnoCTR's guidelines (in the AnnoCTR repository):

* `malware` — software written for malicious purposes (Emotet, SUNBURST).
* `tool` — legitimate or dual-use software used maliciously (Cobalt Strike,
  PsExec, AnyDesk, a "malicious Excel builder").
* `threat_actor` — a group or operator (APT29, TA505, FIN7).
* `campaign` — a named campaign.

Give the name as written most often in the report in `value`, every other
name used for the same thing in `aliases` (Solorigate for SUNBURST). One
entry per real-world thing, not per mention.

## 4. Techniques (`techniques`)

* `kind: explicit` — the report names the technique or its ATT&CK id.
  `kind: implicit` — it describes the behaviour without naming it ("the
  loader downloads the second stage" → T1105).
* Use the most specific id the text supports: T1566.001 only if it says the
  e-mail carried an attachment, T1566 otherwise.
* `quote`: the sentence that shows the technique **being used in this
  intrusion**. If you cannot find one, it is probably not a technique of this
  report.
* Use the current ATT&CK ids (the scorer maps older ones, e.g. T1562 → T1685).

## 5. Relationships (`relations`)

* `source`, `type`, `target`, with the STIX verbs the pipeline emits:
  `uses`, `targets`, `attributed-to`, `indicates`, `communicates-with`,
  `drops`, `downloads`, `exploits`, `variant-of`, `related-to`.
* Only relationships the text states; direction matters
  (`APT29 uses WellMess`, not the reverse).
* Both ends must be entities or IoCs you annotated above.

## 6. Negative cases (`negatives`)

The most useful entries per minute spent. Add every sentence where a
technique or relationship is **mentioned but not asserted**:

* `why: negated` — "no persistence mechanism was observed", "the sample does
  not communicate with a C2".
* `why: recommendation` — mitigations and defensive advice: "enable MFA",
  "monitor for PowerShell execution".
* `why: generic` — background or examples not about this activity: "actors
  often use phishing", a description of another group's past campaign.

Format: `{"kind": "technique", "id": "T1547", "quote": "...", "why": "negated"}`
or `{"kind": "relation", "triple": ["APT29", "uses", "Mimikatz"], ...}`.
The score counts how many of them the pipeline wrongly outputs.

## 7. Agreement

For 3 to 5 reports, a second person annotates **independently** (from the
source file, not from your gold). Compare with
`python -m evaluation agreement <gold_a.json> <gold_b.json>`: per layer, the
F1 of one annotation against the other. Disagreements usually point to this
guide, not to the annotator — fix the guide, bump its version, and note the
version in each `gold.json`.

Without a second person, re-annotate 2 or 3 reports yourself a few weeks
later. That measures consistency, not agreement; report it as such.
