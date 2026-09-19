"""pipeline.overrides — the runtime read of the deny / promote lists (ADR-0052).

Locks the fail-soft contract (no store, no table, kill switch -> nothing
acts, and asking never creates a store), that only `active` rows act, and
that `reload()` also forgets the gazetteer built on the promoted terms.
"""
from __future__ import annotations

import api.db as db
import pipeline.overrides as ov
from models.schemas import EntityType, RawEntity
from pipeline import promotion as pm


def _ent(value: str, etype: EntityType, source: str = "cyner") -> RawEntity:
    return RawEntity(value=value, entity_type=etype, confidence=0.9, source=source)


def test_nothing_acts_without_a_store_and_none_is_created(monkeypatch):
    """ADR-0053: no DATABASE_URL means get_conn() raises, which _load_active's
    broad except already treats as the normal CLI case (no store configured)
    -- confirms that still fails soft rather than crashing the caller."""
    monkeypatch.setattr(db, "DATABASE_URL", None)
    db.reset_connections()
    ov.reload()

    ents = [_ent("Emotet", EntityType.MALWARE)]
    assert ov.denied_keys() == frozenset()
    assert ov.promoted_entries() == []
    assert ov.drop_denied(ents) is ents          # the no-op path hands the list back untouched


def test_nothing_acts_when_the_table_is_missing(temp_db):
    conn = temp_db.get_conn()
    conn.execute("DROP TABLE entity_overrides")
    conn.commit()
    ov.reload()
    assert ov.is_denied("Emotet", "malware") is False


def test_only_active_rows_act(temp_db):
    conn = temp_db.get_conn()
    row = pm.add_manual(conn, "Microsoft", "threat_actor", "deny", temp_db.now_iso())
    pm.set_status(conn, row["id"], "candidate", temp_db.now_iso())
    ov.reload()
    assert ov.is_denied("Microsoft", "threat_actor") is False

    pm.set_status(conn, row["id"], "active", temp_db.now_iso())
    ov.reload()
    assert ov.is_denied("Microsoft", "threat_actor") is True
    assert ov.is_denied("  microsoft ", "threat_actor") is True     # exact value, case-folded, trimmed
    assert ov.is_denied("Microsoft", "identity") is False           # per type
    assert ov.is_denied("Microsoft Corporation", "threat_actor") is False   # never a substring


def test_drop_denied_filters_by_value_and_type(temp_db):
    pm.add_manual(temp_db.get_conn(), "Emotet", "malware", "deny", temp_db.now_iso())
    ov.reload()
    kept = ov.drop_denied([
        _ent("Emotet", EntityType.MALWARE),
        _ent("emotet", EntityType.TOOL),
        _ent("APT29", EntityType.THREAT_ACTOR),
    ])
    assert [(e.value, e.entity_type) for e in kept] == [("emotet", EntityType.TOOL), ("APT29", EntityType.THREAT_ACTOR)]


def test_promoted_entries_have_the_gazetteer_shape(temp_db):
    conn = temp_db.get_conn()
    pm.add_manual(conn, "ArguePatch", "malware", "promote", temp_db.now_iso(), display="ARGUEPATCH")
    pm.add_manual(conn, "healthcare", "identity", "deny", temp_db.now_iso())   # a deny row never becomes an entry
    ov.reload()
    assert ov.promoted_entries() == [{
        "name": "arguepatch", "canonical": "ARGUEPATCH", "entity_type": "malware",
        "mitre_id": None, "domain": "override",
    }]


def test_kill_switch_ignores_every_row(temp_db, monkeypatch):
    pm.add_manual(temp_db.get_conn(), "Microsoft", "threat_actor", "deny", temp_db.now_iso())
    monkeypatch.setenv("ENTITY_OVERRIDES_ENABLED", "false")
    ov.reload()
    assert ov.overrides_enabled() is False
    assert ov.is_denied("Microsoft", "threat_actor") is False


def test_reload_forgets_the_gazetteer_built_on_the_promoted_terms(temp_db):
    from pipeline import stage2b_gazetteer as gaz

    base = {e["name"] for e in gaz._load()}
    assert "arguepatch" not in base
    pm.add_manual(temp_db.get_conn(), "ArguePatch", "malware", "promote", temp_db.now_iso())
    assert "arguepatch" not in {e["name"] for e in gaz._load()}     # still the cached view
    ov.reload()
    assert "arguepatch" in {e["name"] for e in gaz._load()}
