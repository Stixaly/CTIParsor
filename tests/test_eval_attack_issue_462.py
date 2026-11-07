"""evaluation/attack — a `revoked-by` chain that ends on a non-active id (#462),
and the release diff of "more procedures" for a technique new in the release.

The chain and the diff are read from small synthetic bundles: the real v19.2 and
v20.0 bundles have no chain ending on a revoked id, and their diff is checked by
hand, not here."""
from __future__ import annotations

import json

from evaluation import attack

_DOMAINS = ("enterprise-attack", "mobile-attack", "ics-attack")


def _tech(stix_id, tid, **flags):
    return {"type": "attack-pattern", "id": stix_id, "name": tid, "description": "text",
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "discovery"}],
            "external_references": [{"source_name": "mitre-attack", "external_id": tid}], **flags}


def _revoked_by(src, dst):
    return {"type": "relationship", "relationship_type": "revoked-by", "source_ref": src, "target_ref": dst}


def _uses(src, dst, n):
    return [{"type": "relationship", "relationship_type": "uses", "source_ref": "intrusion-set--0",
             "target_ref": dst, "description": f"procedure {i}"} for i in range(n)]


def _write_bundle(path, objects):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"type": "bundle", "objects": objects}), encoding="utf-8")


# ── resolve: the end of a revoked-by chain ───────────────────────────────────

def _chain_catalogue(tmp_path):
    """T2001 -> T2002 (active); T2003 -> T2004 (deprecated); T2005 -> T2006 -> T2007
    (active, a two-step chain); T2008 -> T2009 (revoked, with no successor)."""
    objects = [
        _tech("attack-pattern--1", "T2001", revoked=True),
        _tech("attack-pattern--2", "T2002"),
        _tech("attack-pattern--3", "T2003", revoked=True),
        _tech("attack-pattern--4", "T2004", x_mitre_deprecated=True),
        _tech("attack-pattern--5", "T2005", revoked=True),
        _tech("attack-pattern--6", "T2006", revoked=True),
        _tech("attack-pattern--7", "T2007"),
        _tech("attack-pattern--8", "T2008", revoked=True),
        _tech("attack-pattern--9", "T2009", revoked=True),
        _revoked_by("attack-pattern--1", "attack-pattern--2"),
        _revoked_by("attack-pattern--3", "attack-pattern--4"),
        _revoked_by("attack-pattern--5", "attack-pattern--6"),
        _revoked_by("attack-pattern--6", "attack-pattern--7"),
        _revoked_by("attack-pattern--8", "attack-pattern--9"),
    ]
    bundle = tmp_path / "enterprise-attack.json"
    _write_bundle(bundle, objects)
    index = tmp_path / "mitre_index.json"
    index.write_text(json.dumps({"techniques": [{"id": t} for t in ("T2002", "T2007")]}), encoding="utf-8")
    return attack.Catalogue(bundle, index)


def test_a_chain_ending_on_a_deprecated_id_resolves_to_nothing_issue_462(tmp_path):
    cat = _chain_catalogue(tmp_path)
    r = cat.resolve("T2003")
    assert (r.status, r.canonical, r.in_pipeline) == ("revoked", None, False)


def test_a_chain_ending_on_a_revoked_id_resolves_to_nothing_issue_462(tmp_path):
    cat = _chain_catalogue(tmp_path)
    r = cat.resolve("T2008")
    assert (r.status, r.canonical, r.in_pipeline) == ("revoked", None, False)


def test_a_chain_ending_on_an_active_id_still_resolves_issue_462(tmp_path):
    """Control: one step, and two steps, both end on an active id."""
    cat = _chain_catalogue(tmp_path)
    assert cat.resolve("T2001").canonical == "T2002" and cat.resolve("T2001").in_pipeline
    r = cat.resolve("T2005")
    assert (r.status, r.canonical, r.in_pipeline) == ("revoked", "T2007", True)


def test_an_active_id_resolves_to_itself_issue_462(tmp_path):
    cat = _chain_catalogue(tmp_path)
    assert cat.resolve("T2002").canonical == "T2002"
    assert cat.resolve("T2002").in_pipeline


def test_an_unknown_id_is_not_mapped_issue_462(tmp_path):
    """Control: UNKNOWN keeps its own rule (kept only if the pipeline knows it)."""
    cat = _chain_catalogue(tmp_path)
    assert cat.resolve("T9999").canonical is None
    assert cat.resolve("T2002").status == "active"


# ── release_diff: more procedures among the techniques of both releases ──────

def _release(directory, enterprise_objects):
    _write_bundle(directory / "enterprise-attack.json", enterprise_objects)
    for domain in _DOMAINS[1:]:
        _write_bundle(directory / f"{domain}.json", [])


def test_a_technique_new_in_the_release_is_not_counted_as_more_procedures_issue_462(tmp_path):
    old, new = tmp_path / "v1", tmp_path / "v2"
    _release(old, [_tech("attack-pattern--1", "T3001"), *_uses("x", "attack-pattern--1", 1)])
    _release(new, [
        _tech("attack-pattern--1", "T3001"),
        _tech("attack-pattern--3", "T3003"),           # new in v2, with two procedures
        *_uses("x", "attack-pattern--1", 2),
        *_uses("x", "attack-pattern--3", 2),
    ])
    diff = attack.release_diff(old, new)["enterprise-attack"]

    assert diff["new_active"] == ["T3003"]
    assert diff["procedures"]["techniques_with_more"] == 1
    assert diff["more_procedures"] == ["T3001"]
    assert diff["procedures"]["old"] == 1 and diff["procedures"]["new"] == 4   # the totals still count T3003
    why = attack.release_change(attack.release_diff(old, new))
    assert why("T3003") == "new_technique"                                    # its own category
    assert why("T3001") == "content_changed"


def test_a_technique_that_grows_is_counted_issue_462(tmp_path):
    """Control: the count of a technique present in both releases is unchanged."""
    old, new = tmp_path / "v1", tmp_path / "v2"
    _release(old, [_tech("attack-pattern--1", "T3001"), _tech("attack-pattern--2", "T3002"),
                   *_uses("x", "attack-pattern--1", 1), *_uses("x", "attack-pattern--2", 3)])
    _release(new, [_tech("attack-pattern--1", "T3001"), _tech("attack-pattern--2", "T3002"),
                   *_uses("x", "attack-pattern--1", 3), *_uses("x", "attack-pattern--2", 3)])
    diff = attack.release_diff(old, new)["enterprise-attack"]

    assert diff["procedures"]["techniques_with_more"] == 1
    assert diff["more_procedures"] == ["T3001"]
    assert diff["procedures"]["techniques_with_fewer"] == 0
