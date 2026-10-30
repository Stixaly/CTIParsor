# ADR-0093: Context in STIX descriptions

**Status:** Accepted
**Date:** 2026-10-30
**Deciders:** maintainer
**Relates to:** ADR-0043 (the `artifact` stays, so the source file is in the
bundle twice), ADR-0090 (the re-issued Report keeps its description and gets the
file), ADR-0066 (object ids are OpenCTI's, so an object's description is shared
across reports), ADR-0061 (the mapping ledger gives each relationship the origin
its "Why" sentence reads)

## Context

OpenCTI shows a STIX `description` as GitHub-flavoured Markdown. Before this
change, CTIParsor's descriptions said little:

- The Report's `description` was the raw extracted text.
- An extracted relationship's `description` was the sentence the report quotes
  for it. The link itself had no reason. A policy rule, an IoC association, a
  MITRE ATT&CK reference and an inferred link read the same as a claim of the
  report.
- Named objects (malware, threat actors, intrusion sets, campaigns, tools,
  infrastructure) carried no description from CTIParsor.
- The source file was in the bundle only as an `artifact` (ADR-0043), which
  OpenCTI does not attach to the Report.

Text written into Markdown is read as Markdown. A line that starts with `#`
becomes a heading, `*.exe` becomes emphasis, and a URL or a domain that the
report names as an IoC becomes a link. Report text therefore has to be escaped
before it goes into a description.

## Decision

**1. Each relationship says why it exists.** Every relationship CTIParsor builds
gets a `description`: Markdown blocks, separated by a blank line.

1. A title: the source's name in bold, the verb in code, the target's name in bold.
   No ids.
2. The sentence the report quotes for the link, as a blockquote, when there is
   one. The quote moves from `description` to `x_evidence_text`, the key that
   long-distance edges already used.
3. `**Why:**` and one sentence, chosen by the origin the mapping ledger records:

| Origin | Why says |
|---|---|
| extracted | The report states the link in the quoted sentence. Without a quote, the row came from this job (the report or an analyst) and no sentence supports it. |
| `ioc_based_on` | The indicator's pattern is built from this observable, which the report lists. |
| `ioc_association` | The report associates the indicator value with the malware (named in bold). |
| `embedded_rule_title` | The detection rule quoted in the report names the malware in its title. |
| `targeted_location` | The report names the actor and the target. CTIParsor links every actor to every target it names, so the report may not say that this actor targets this one. |
| `policy_pin` | The analyst's relationship policy rule, not a claim of the report. Then what the pin pass checked (`x_pin_evidence`): both objects are named in one sentence, or N sentences apart, or whether the report names them together could not be checked. |
| `completion_reference` | MITRE ATT&CK records the link; the report does not state it. |
| `completion_transitive` | Composed from two named links of this bundle; the report does not state it. |
| `completion_long_distance` | The language model inferred it from the report; the quoted sentence was found in the report's text. |

4. `**Evidence:** <grade> · **Confidence:** n/100`.

No relationship id appears in the text. stix2 gives each relationship a random
uuid4, so the text would change between two builds of one job.

**2. The Report's description is its context.** Three blocks, separated by a
blank line. A block with nothing to show is left out.

- `## Source document`: the file name, the SHA-256, the document's own
  publication date and source (the value of `x_source_published`, ADR-0063; a
  file's print date is not used), and that the original file is attached.
- `## What CTIParsor extracted`: a table of the Report's objects by STIX type,
  most frequent first.
- `## Document text`: the extracted text, made literal line by line. Each line is
  escaped, and a blank line separates paragraphs. A line break inside a paragraph
  is a hard break, so a DOCX or HTML export with one paragraph per line does not
  run them together. A Markdown source file (`.md`) is made literal too: kept as
  Markdown, its links would be live in OpenCTI, and its images would be fetched,
  from wherever the report's author pointed them, by the browser of each analyst
  who opens the Report.

**3. The source file is attached to the Report.** The Report carries the file as
`x_opencti_files`: `name`, `data` (base64), `mime_type` and
`no_trigger_import: true`.

- OpenCTI's import reads this property and attaches the file to the object. Its
  own export writes the same property (pycti, `utils/opencti_stix2.py`).
- `no_trigger_import` is set because CTIParsor has already extracted the report,
  and an import connector would do it again.
- The entry carries no `object_marking_refs`. OpenCTI then gives the file the
  markings of the Report (`upsert-utils.js`).
- The `artifact` of ADR-0043 stays, for a STIX consumer that does not read
  `x_opencti_files`. The file is in the bundle twice.

The re-issued baseline Report (ADR-0090) keeps its `description` as received. It
receives the file, unless the Report as received already holds a file of the
same name.

**4. Named objects get the report's sentences.** A malware, threat-actor,
intrusion-set, campaign, tool or infrastructure object without a description of
its own gets:

- `Mentioned in *<report name>*:`, then up to three sentences of the report, each
  a blockquote, that name the object, ignoring case, at a word boundary. A name
  is the object's name, one of its aliases, or a form ATT&CK knows for it
  (`alias_surface_forms`): a report that says "Cozy Bear" is about APT29. The
  gazetteer policy's review of ordinary words applies: a CONTEXT form ("ping",
  "play") is not searched, and a CASE form ("Silence", "Tick") counts only where
  the text writes it with an initial capital;
- names under three characters are ignored, and a sentence is cut at 400
  characters.

An object kept from a baseline keeps its own description (ADR-0090).

**5. Escaping and defanging.** `pipeline/markdown_text.py` makes the report's
text literal in two steps.

- It defangs what GFM turns into a link, the way CTI reports write it:
  `http://` becomes `hxxp://`, `www.` becomes `www[.]`, and the `@` of an e-mail
  address becomes `[@]`. Escaping alone does not stop a link: remark-gfm finds
  autolinks in the text after the escapes are decoded, so `http:\/\/x` is still a
  link. This was checked on remark-gfm 4.0.1, the version of OpenCTI's front end
  and of ours: the escaped forms gave links, the defanged ones none.
- It backslash-escapes every Markdown-active character: backslash, backtick,
  `*`, `_`, `[`, `]`, `<`, `>`, `&`, `|`, `~`, `#` and `=`. It also escapes the
  block markers that act only at the start of a line: a list dash or plus, an
  ordered-list number. Leading whitespace is dropped, since four spaces would
  open a code block.

This covers the quoted sentences, the object names, the Document text and the
mention sentences. The bundle's observables and indicators keep the live values:
only the descriptions are defanged.

**6. A failed description never costs the object.** When a description cannot be
written, the object ships without one, and a warning is logged. When the names or
the mentions cannot be computed at all, no context is written and the bundle is
built as before.

**7. Frontend.** In the STIX bundle view of the Graph page, an edge's panel reads
the quote from `x_evidence_text` ("Quoted evidence") and shows its `description`
as Markdown in a "Description" block. An object's panel shows its `description`
the same way, whole, instead of the first 400 characters as plain text. The
Review rows view is unchanged: the context the LLM wrote for a row is plain text,
and is shown as such.

## Options considered

| Option | Verdict |
|---|---|
| The source file in `x_opencti_files` alone, without the `artifact` | Rejected. It reverses ADR-0043: a STIX consumer that does not read `x_opencti_files` loses the file. |
| The `artifact` alone, as before | Rejected. In OpenCTI the PDF is then not a file of the Report. |
| Report `description`: the text alone | Rejected. The source and the counts would not be in the description. |
| Report `description`: the header alone | Rejected. The full text would then be only in the PDF. |
| Relationship `description`: the quote alone | Rejected. A policy rule or an inference would read as a claim of the report. |
| One STIX Note (§4.12) per object, with `object_refs` to the object and to the Report | Not chosen. A Note overwrites nothing in OpenCTI. The maintainer chose the object's `description`; see Consequences for the cost and the alternative. |

## Consequences

**OpenCTI can replace these descriptions.** OpenCTI declares `description`
upsertable on domain objects and on relationships
(`stixDomainObject-registrationAttributes.ts`,
`stixCoreRelationship-registrationAttributes.ts`). On import, it replaces a stored
value when the import's confidence, capped at the importing user's maximum, is at
least the stored confidence, or when the stored value is empty
(`upsert-utils.js`, `generateAttributesInputsForUpsert`). Consequently:

- a malware or an actor keeps its id across reports (ADR-0066), so the sentences
  of a later report can replace the description an earlier report gave it, and
  the next report replaces those in turn;
- a relationship's description is replaced the same way, whenever the imported
  relationship resolves to one OpenCTI already holds.

The quoted sentence already had this property before this change. The maintainer
accepts the risk. If it becomes a problem, the Note option above is the
alternative.

**Bundle size.** The source file is in the bundle twice: as the `payload_bin` of
the `artifact`, and as `x_opencti_files[].data`. ADR-0043 measured ≈347 KB of
base64 for one copy of the 260,196-byte Breeze/Comet report, so about 694 KB for
that file. The Report's description also carries the extracted text, as it did
before. The size of a real bundle before and after was not measured.

**The Report's `description` is no longer the raw text.** A reader that took it
for the source text finds headings and backslashes. The Graph page treats the
Report as a meta-object (`META_TYPES` in `buildBundleGraph.ts`), so the Report is
not a node, and its description is not shown as a node's context.

**A Markdown source file loses its formatting.** Its headings and lists show as
written (`# Title`), since its links and images cannot be kept without them
becoming live (decision 2).

**Descriptions CTIParsor does not write are not escaped.** An attack-pattern's
description (the summary the language model wrote) and a vulnerability's (the
CVE record's) go out as they were, as before this change. The Graph page renders
every description as Markdown, as OpenCTI does, so either can show emphasis or a
link there. Escaping them is a separate change.

**Bundles stored before this change read differently in the Graph page.** Their
extracted relationships carry the quote in `description` and no
`x_evidence_text`: the panel shows the quote under "Description", rendered as
Markdown, and no "Quoted evidence" block, until the bundle is rebuilt.

**OpenCTI's Markdown display loads more than GFM.** Its front end depends on
`remark-breaks`, which makes every line break a break (the hard breaks of the
Document text change nothing there), and on `remark-flexible-markers`, which
highlights `==text==`. `=` is escaped too, so a YARA condition such as
`uint16(0) == 0x5A4D and filesize == 2` is not highlighted.

**Stored bundles keep their text.** A bundle built before this change keeps its
descriptions, and has no `x_opencti_files`, until a finalize at a revision that
has this change. The commit that lands it is listed in `BUNDLE_AFFECTING` with
scope `mapping` (ADR-0086), so the next finalize rebuilds the bundle.

**The re-issued Report is an exception to ADR-0090 §6.** That section keeps the
Report's `x_opencti_*` properties as received. This ADR adds the source file to
the Report's `x_opencti_files`, when no file of the same name is there, and keeps
the other entries as they are.

**A failed description is local.** An object is never dropped because its
description could not be written (decision 6).

## Validation

Checked on 2026-10-30:

1. **Only the context changed.** The five reference bundles of
   `tests/fixtures/stage4_reference/expected/` were regenerated. A script paired
   every object of each scenario with its previous version and compared them
   with `description`, `x_evidence_text` and `x_opencti_files` set aside: no other
   key differs, and the ledgers are identical. In `apt_report` (79 objects),
   46 descriptions changed (41 relationships, the Report, and a campaign, a
   malware, a threat actor and a tool), 6 relationships gained
   `x_evidence_text`, and the Report gained `x_opencti_files`. The diff of the
   files also shows `relationship--R<n>` labels renumbered: the reference
   harness numbers the random ids by content, and the content now includes the
   description.
2. **Every link has a reason.** All 41 relationships of `apt_report` have a
   `**Why:**` line. APT29, which the report calls only "Cozy Bear", is described
   by two of its sentences.
3. **No link survives in remark-gfm.** The escaped forms of the first version
   (`http:\/\/`, `www\.`, `\@`) still gave links in remark-gfm 4.0.1; the
   defanged ones give none. A frontend test renders `escape_inline`'s output for a
   URL, a `www.` domain, an e-mail address and a `==` condition, and finds no
   link.
4. **Tests.** The new tests (`test_markdown_text`, `test_report_markdown`,
   `test_edge_justification`, `test_object_mentions`, `test_stage4_context`) and
   the Stage 4, reference and baseline tests pass on `.venv` and on the Python 3.12
   environment with RE2 (339 passed in each). A failure to compute the names
   leaves every object in the bundle, with no context written. The full suite
   passes locally (4,489 passed, 9 skipped for missing optional modules).
   `npm run check` passes (311 tests). ruff and mypy pass on the changed modules.

Not checked:

- an import into a throwaway OpenCTI (`docker/opencti-test`): that the file is
  attached once to the Report with its markings, and how OpenCTI's own display
  renders the descriptions;
- the size of a real bundle before and after.

## Implementation

- `pipeline/markdown_text.py`: the escaping (`escape_inline`, `escape_line`,
  `blockquote`).
- `pipeline/edge_justification.py`: the relationship `description`.
- `pipeline/report_markdown.py`: the Report's `description` and `x_opencti_files`.
- `pipeline/object_mentions.py`: the `description` of named objects without one.
- `pipeline/stage4_stix_mapping.py`: the calls, in place of the raw text and the
  quote-only `description`; `_stamp_objects` writes each object's context.
- `pipeline/bundle_revisions.py`: the `BUNDLE_AFFECTING` entry, added by the commit
  that lands the change.
- Frontend: `frontend/src/components/graph/BundlePanels.tsx`,
  `frontend/src/components/graph/buildBundleGraph.ts`,
  `frontend/src/components/MarkdownPreview.tsx` (a `compact` mode).
