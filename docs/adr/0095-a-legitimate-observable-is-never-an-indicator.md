# ADR-0095: A legitimate observable ships without an Indicator

**Status:** Accepted
**Date:** 2026-11-08
**Deciders:** maintainer
**Relates to:** ADR-0061 (bundle view and MappingLedger), ADR-0066 (OpenCTI is
the interop target), ADR-0083 (a hashless file keeps its path in `name`),
the benign-value filter of audit B 8.1.7 (`pipeline/benign.py`), the in-house
annotation of 2026-11-07 (`data/eval/inhouse/A-TRANCHER.md`, decisions A6, B1,
B6, B18, C2)

## Context

Reports list legitimate things beside the attacker's: the cert-ua table puts
`C:\Windows\System32\rundll32.exe` and `comsvcs.dll` (the LSASS dump command)
next to the wipers; apt44's YARA strings name `chkdsk.exe`, `kernel32.dll`
and `Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`; the
shinyhunters report reads the attacker's `.bash_history`; greyvibe lists the
actor's Telegram handles; cert-polska gives a task-filter GUID.

Stage 2 extracts each one, and Stage 4 gave each an Indicator typed
`malicious-activity`, `[file:name = 'rundll32.exe']` among them. An Indicator
is a detection: a consumer that loads the bundle into OpenCTI, then into a
SIEM, alerts on every Windows machine.

When annotating the in-house set, the analyst moved these values out of the
gold's `iocs` into a new `observables` list (decision A6), and asked that the
pipeline tell the two apart too. One exception: the `HKLM\SYSTEM`, `SECURITY`
and `SAM` hives the cert-ua attacker saved stay IoCs (B1), although every
Windows system has them.

The pipeline already ships some values as an observable without an Indicator:
a private address, a big public resolver, a vendor's blog, a top-10k domain
(`pipeline/benign.py`, audit B 8.1.7). The mechanism exists; the files,
registry keys and values without an IoC type were not in it.

## Decision

### 1. Three more reasons in `benign_reason`

`pipeline/benign.py` answers for three more types. A value it names keeps its
observable (SCO) in the bundle, and gets no Indicator:

| Reason | Type | What it is | Example |
|---|---|---|---|
| `legitimate_file:windows` | file | a Windows system binary or DLL, bare or in its standard directory | `rundll32.exe`, `%SystemRoot%\System32\comsvcs.dll` |
| `legitimate_file:unix` | file | a standard Unix file in its usual directory, or bare | `.bash_history`, `/home/x/.bash_history`, `/usr/bin/curl` |
| `legitimate_registry_key` | registry key | a key every Windows system has, exactly | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` |
| `no_ioc_type:guid` | file, registry key, user account | a bare GUID | `79A87EBB-4DF6-4541-9530-CAD8BEE8A7AD` |
| `no_ioc_type:device` | file | a device name, not a file | `\\.\EPMNTDRV` |
| `no_ioc_type:messenger_handle` | user account | a handle (`@name`) | `@lilymihalyk` |

`BENIGN_IOC_FILTER=false` turns them off with the others.

### 2. Exact matches only

The failure to avoid is the reverse one: a real IoC losing its Indicator. A
name a malware borrows is the usual masquerade (T1036.005), so the match is
narrow, and anything else keeps its Indicator:

- **A system file name counts only bare or in one of its own directories.**
  `C:\Users\Public\svchost.exe`, `C:\Windows\Temp\rundll32.exe`,
  `C:\Windows\rundll32.exe` (wrong directory), `%APPDATA%\kernel32.dll` (DLL
  side-loading) and a UNC share keep their Indicator. A near name
  (`schtask.exe`, an IoC of the cert-polska gold beside the legitimate
  `schtasks.exe`) is not the name. Each entry of the list carries its
  directories, relative to the Windows directory, whichever way the report
  writes it (`C:\Windows`, `%SystemRoot%`, `%windir%`, `\SystemRoot`,
  `\??\C:\Windows`, another drive letter, a bare `System32\`).
- **A file with a hash is never judged by its name.** The hash names the
  content, maybe a trojanised `rundll32.exe`; the Indicator is on the hash.
- **A registry key counts only as itself, not its subkeys.** `...\Services`
  is listed, `...\Services\EvilSvc` is the attacker's service. The hive is
  ignored (`HKLM`, `HKEY_CURRENT_USER`, `HKU\<SID>`, the kernel's
  `\Registry\Machine`), as are `WOW6432Node` and the `ControlSet00n` number.
- **A mutex is never judged.** A mutex named by a GUID is the malware's own.

### 3. What the attacker takes stays an IoC

The SAM, SECURITY and SYSTEM hives are on every Windows system, as are
`ntds.dit` and `/etc/shadow`. A copy of them is what the attacker steals or
what decrypts it: its presence in a public folder is the trace (B1). The list
never names them; its `never_listed` block says so, and a test fails if a
list ever does. The same reasoning leaves out files whose existence is
already suspicious (`/etc/ld.so.preload`) and `authorized_keys`, the file an
attacker writes to persist.

A Run key is listed, although it is where persistence is written: the key
exists everywhere, and an Indicator on it matches everywhere. The attacker's
trace is the value written in it, which the key SCO does not carry.

### 4. The data: `pipeline/data/legitimate_observables.json`

Written for this project, versioned in the repository, hashed into the build
fingerprint (`api/run_config._DATA_FILES`): changing it changes what a run
emits. It holds the Windows roots, the Windows files by directory group (135
names, the ones reports quote: LOLBins, core processes, core DLLs, a few
drivers), the 52 Unix files (shell history and rc files, a few `/bin` tools, some
`/etc` files), and 38 registry keys in their normal form (no hive,
lower-cased, sorted; a test holds that form).

No public list fits. MISP warninglists cover network values only; LOLBAS lists
abusable binaries with their paths but under GPL-3.0, and only abusable ones
(no `kernel32.dll`, no `.bash_history`). The list errs short: a name missing
from it keeps its Indicator, which is what happened before it existed.

### 5. The bundle and the ledger

Nothing new in the output's shape. The SCO ships; no Indicator, so no
`based-on` and no `indicates`. An IoC association naming the value is dropped
with `reason: benign` and `benign: <reason>`, and the observable's ledger
entry says `no_indicator: benign` (ADR-0061). A relationship the LLM routed
through the missing Indicator is dropped as `benign_observable`.
`verify_ioc_coverage` counts these values under `benign`, not as missing. The
Graph page says why, in words, for each of the new reasons.

### 6. The evaluation

`evaluation/inhouse.py` documents the gold's `observables` list. The scorer
counts a gold observable the pipeline extracted neither as a hit nor as a
false positive of the `iocs` layer: extracting it is right. It counts the
gold observables the bundle gave an Indicator (`observables.as_indicator`),
from a new `bundle_indicated` field of each run's record: the values of the
SCOs an Indicator is `based-on`. A run recorded before this field has `None`.

## Measures

The rule run on the in-house gold of 2026-11-07 (`benign_reason` on each
gold value, not a pipeline run):

- the 15 gold observables (9 files, 2 registry keys, 1 device, 1 GUID, 2
  Telegram handles; the GUID judged as a file, the handles as user accounts,
  the types the pipeline gives them), all 15 recognised;
- none of the 117 gold IoCs of type file or registry key (114 files, the 3
  hives) is judged legitimate.

The five gold IoCs `benign_reason` rejects are private addresses of the
intelsq1 exercise infrastructure (decision B14), judged by the existing
`non_routable_address` rule, not by this ADR.

A pipeline run on the eight reports, to count `as_indicator` before and after,
is not part of this change: the gold files are named `gold.claude.json`, which
`inhouse.load()` does not read yet.

## Consequences

- A bundle loses Indicators it should never have had; an OpenCTI user sees
  the observable without the detection. `BUNDLE_AFFECTING` records it
  (mapping scope: a finalize rebuilds the bundle with it).
- A Telegram handle extracted as a user account loses its Indicator. Other
  user accounts keep theirs.
- The list will need entries; a missing one costs a false Indicator, not a
  lost IoC. Adding one is a data change, hashed, and goes through review.
- A GUID or a device name typed as something else than file, registry key or
  user account (a mutex, a URL) is not judged.

## Alternatives rejected

- **Drop the observable too.** The report names the value, and an analyst
  reading the bundle wants to see that `rundll32.exe` ran `comsvcs.dll`; only
  the detection is wrong.
- **Indicator typed `benign`.** STIX allows `indicator_types: ["benign"]`,
  but the object is still a pattern, and every consumer that does not read
  that field (a SIEM fed from the platform's indicators) alerts on it. The
  benign values of audit B 8.1.7 already made the same choice.
- **Match a system name in any directory.** Hides every masquerade.
- **Let the LLM say whether a value is legitimate.** Not checkable, not
  repeatable, and the list is short enough to write.
