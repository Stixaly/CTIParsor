"""#431: `also_in` follows the same transitive closure as `dedupe_store`.

dedupe_store unions folded rules through a union-find, so a chain C→B→A puts
all three in one cluster. `rules_for_technique` used to read one hop of
`related:` from the canonical rule, which lost the corpus of C.
"""
import pathlib
import tempfile

from pipeline.detection.dedup import dedupe_store
from pipeline.detection.sigma import SigmaAdapter
from pipeline.detection.store import replace_corpus_rules, rules_for_technique


def _parse(text, corpus):
    d = pathlib.Path(tempfile.mkdtemp())
    (d / "r.yml").write_text(text, encoding="utf-8")
    return list(SigmaAdapter().parse(d, corpus=corpus, license="x"))[0]


# The canonical rule (A).
_CANON = """\
title: Alpha Marker
id: aaaaaaaa-0000-0000-0000-000000000001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: 'alpha-marker'
  condition: selection
level: high
tags:
  - attack.t1059.001
"""

# B is derived from A: its own logic, and it names A in `related:`.
_MIDDLE = """\
title: Beta Marker
id: aaaaaaaa-0000-0000-0000-000000000002
related:
  - id: aaaaaaaa-0000-0000-0000-000000000001
    type: derived
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: 'beta-marker'
  condition: selection
level: high
tags:
  - attack.t1059.001
"""

# C is derived from B: it names B in `related:` and shares no dedup_key with A.
_LAST = """\
title: Gamma Marker
id: aaaaaaaa-0000-0000-0000-000000000003
related:
  - id: aaaaaaaa-0000-0000-0000-000000000002
    type: derived
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: 'gamma-marker'
  condition: selection
level: high
tags:
  - attack.t1059.001
"""

# C2 has B's logic and no `related:`: it folds into B by dedup_key, not by provenance.
_LAST_SAME_LOGIC = """\
title: Gamma Marker (same logic as beta)
id: aaaaaaaa-0000-0000-0000-000000000004
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: 'beta-marker'
  condition: selection
level: high
tags:
  - attack.t1059.001
"""

# An independent rule that covers the same technique: must stay out of also_in.
_INDEPENDENT = """\
title: Independent Download Cradle
id: bbbbbbbb-0000-0000-0000-000000000001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: 'DownloadString'
  condition: selection
level: high
tags:
  - attack.t1059.001
"""


def test_also_in_follows_a_chain_of_provenance_folds_issue_431(temp_db):
    """C→B→A: the canonical A must credit both B's and C's corpora."""
    temp_db.get_conn()          # job store
    rconn = temp_db.get_rule_conn()    # rule store
    replace_corpus_rules(rconn, "sigmahq", [_parse(_CANON, "sigmahq")])
    replace_corpus_rules(rconn, "midcorp", [_parse(_MIDDLE, "midcorp")])
    replace_corpus_rules(rconn, "lastcorp", [_parse(_LAST, "lastcorp")])
    replace_corpus_rules(rconn, "indie", [_parse(_INDEPENDENT, "indie")])
    summary = dedupe_store(rconn, {"sigmahq": 10, "midcorp": 50, "lastcorp": 90, "indie": 60})
    assert summary["canonical"] == 2   # the chain is one cluster, indie is its own

    rules = {r["corpus"]: r for r in rules_for_technique(rconn, "T1059.001")}
    assert set(rules) == {"sigmahq", "indie"}
    assert rules["sigmahq"]["also_in"] == ["lastcorp", "midcorp"]
    assert rules["indie"]["also_in"] == []


def test_also_in_follows_a_dedup_key_fold_after_a_provenance_fold_issue_431(temp_db):
    """A→B by `related:`, then C2→B by dedup_key: the closure mixes both edges."""
    temp_db.get_conn()          # job store
    rconn = temp_db.get_rule_conn()    # rule store
    replace_corpus_rules(rconn, "sigmahq", [_parse(_CANON, "sigmahq")])
    replace_corpus_rules(rconn, "midcorp", [_parse(_MIDDLE, "midcorp")])
    replace_corpus_rules(rconn, "samelogic", [_parse(_LAST_SAME_LOGIC, "samelogic")])
    dedupe_store(rconn, {"sigmahq": 10, "midcorp": 50, "samelogic": 90})

    [rule] = rules_for_technique(rconn, "T1059.001")
    assert rule["corpus"] == "sigmahq"
    assert rule["also_in"] == ["midcorp", "samelogic"]
