"""The mapping ledger (ADR-0061): Stage 4 says what it did with each row.

The review graph draws the job store's rows; the bundle is built from them and
then differs.  Each test here pins one of those differences to the ledger entry
that reports it, so the graph can never again show an edge the bundle dropped,
or a verb the bundle rewrote, without saying so.
"""
import json
from datetime import datetime, timezone

from models.schemas import EntityType, RawEntity
from pipeline.bundle_ledger import MappingLedger
from pipeline.stage3_llm import IoCAssociation, LLMEnrichmentResult, RelationshipExtracted
from pipeline.stage4_stix_mapping import build_stix_bundle


def _build(entities=(), llm=None, **kw):
    ledger = MappingLedger()
    bundle = build_stix_bundle(list(entities), llm or LLMEnrichmentResult(), "r",
                               ledger=ledger, **kw)
    return bundle, ledger.to_dict()


def _rel(src, verb, tgt, **kw):
    return RelationshipExtracted(source_value=src, relationship_type=verb,
                                 target_value=tgt, confidence=0.9, **kw)


def _entry(ledger, src, verb, tgt):
    matches = [e for e in ledger["relationships"]
               if (e["source_value"], e["relationship_type"], e["target_value"]) == (src, verb, tgt)]
    assert len(matches) == 1, matches
    return matches[0]


def _by_id(bundle):
    return {o.id: o for o in bundle.objects}


# ── relationships: emitted, rewritten ────────────────────────────────────────

def test_emitted_relationship_points_at_the_sro_that_ships():
    llm = LLMEnrichmentResult(threat_actors=["APT29"], malware_families=["WINELOADER"],
                              relationships=[_rel("APT29", "uses", "WINELOADER")])
    bundle, led = _build(llm=llm)
    e = _entry(led, "APT29", "uses", "WINELOADER")
    assert e["outcome"] == "emitted"
    assert e["changes"] == []
    sro = _by_id(bundle)[e["stix_id"]]
    assert sro.relationship_type == "uses" and e["final_type"] == "uses"
    assert led["objects"][sro.id]["origin"] == "extracted"


def test_verb_not_suggested_for_the_pair_is_reported_as_a_change():
    llm = LLMEnrichmentResult(threat_actors=["APT29"], malware_families=["WINELOADER"],
                              relationships=[_rel("WINELOADER", "uses", "APT29")])
    bundle, led = _build(llm=llm)
    e = _entry(led, "WINELOADER", "uses", "APT29")
    assert e["outcome"] == "emitted"
    assert e["final_type"] == "related-to"
    assert e["changes"] == [{"kind": "verb", "from": "uses", "to": "related-to",
                             "reason": "not_suggested"}]


def test_unknown_verb_and_policy_pin_are_reported():
    pol = {"version": 1, "global": "enforce",
           "rules": [{"src": "threat-actor", "verb": "uses", "tgt": "malware",
                      "mode": "pin", "enabled": True}]}
    llm = LLMEnrichmentResult(threat_actors=["APT29"], malware_families=["WINELOADER"],
                              relationships=[_rel("APT29", "wields", "WINELOADER")])
    _, led = _build(llm=llm, relationship_policy=pol)
    e = _entry(led, "APT29", "wields", "WINELOADER")
    assert [c["reason"] for c in e["changes"]] == ["unknown_verb", "policy_pin"]
    assert e["final_type"] == "uses"


def test_observable_endpoint_is_rerouted_through_its_indicator():
    # No table lists `domain-name indicates malware`; `indicator indicates
    # malware` is the spec's own edge, so the row keeps its verb once routed.
    llm = LLMEnrichmentResult(malware_families=["WINELOADER"],
                              relationships=[_rel("evil.example", "indicates", "WINELOADER")])
    ents = [RawEntity(value="evil.example", entity_type=EntityType.DOMAIN)]
    bundle, led = _build(ents, llm)
    e = _entry(led, "evil.example", "indicates", "WINELOADER")
    assert [c["kind"] for c in e["changes"]] == ["reroute"]
    reroute = e["changes"][0]
    assert reroute["end"] == "source"
    objs = _by_id(bundle)
    assert objs[reroute["from"]].type == "domain-name"
    assert objs[reroute["to"]].type == "indicator"
    assert objs[e["stix_id"]].source_ref == reroute["to"]
    assert e["final_type"] == "indicates"


def test_listed_observable_pair_ships_as_extracted():
    # ADR-0062: the row the seeded Industroyer2 report showed rewritten twice
    # (reroute, then communicates-with -> related-to) now ships untouched.
    llm = LLMEnrichmentResult(malware_families=["WINELOADER"],
                              relationships=[_rel("WINELOADER", "communicates-with", "evil.example")])
    ents = [RawEntity(value="evil.example", entity_type=EntityType.DOMAIN)]
    bundle, led = _build(ents, llm)
    e = _entry(led, "WINELOADER", "communicates-with", "evil.example")
    assert e["outcome"] == "emitted" and e["changes"] == []
    assert e["final_type"] == "communicates-with"
    objs = _by_id(bundle)
    assert objs[e["target_ref"]].type == "domain-name"
    assert objs[e["stix_id"]].target_ref == e["target_ref"]


def test_unlisted_verb_is_rerouted_then_downgraded():
    # What ADR-0041 still does, and the ledger must keep saying: `uses` is
    # listed neither for malware -> domain-name nor for malware -> indicator.
    llm = LLMEnrichmentResult(malware_families=["WINELOADER"],
                              relationships=[_rel("WINELOADER", "uses", "evil.example")])
    ents = [RawEntity(value="evil.example", entity_type=EntityType.DOMAIN)]
    _, led = _build(ents, llm)
    e = _entry(led, "WINELOADER", "uses", "evil.example")
    assert [(c["kind"], c.get("reason")) for c in e["changes"]] == [
        ("reroute", None), ("verb", "not_suggested")]
    assert e["final_type"] == "related-to"


def test_pinned_verb_keeps_the_observable_and_is_reported():
    pol = {"version": 1, "global": "enforce",
           "rules": [{"src": "malware", "verb": "communicates-with", "tgt": "domain-name",
                      "mode": "pin", "enabled": True}]}
    llm = LLMEnrichmentResult(malware_families=["WINELOADER"],
                              relationships=[_rel("WINELOADER", "uses", "evil.example")])
    ents = [RawEntity(value="evil.example", entity_type=EntityType.DOMAIN)]
    bundle, led = _build(ents, llm, relationship_policy=pol)
    e = _entry(led, "WINELOADER", "uses", "evil.example")
    assert e["changes"] == [{"kind": "verb", "from": "uses", "to": "communicates-with",
                             "reason": "policy_pin"}]
    assert _by_id(bundle)[e["target_ref"]].type == "domain-name"


def test_routed_row_takes_the_policy_of_the_pair_it_lands_on():
    # `domain-name hosts malware` is listed nowhere: routed, the row meets the
    # indicator>malware rule, not a domain-name>malware one.
    pol = {"version": 1, "global": "enforce",
           "rules": [{"src": "indicator", "verb": "indicates", "tgt": "malware",
                      "mode": "pin", "enabled": True}]}
    llm = LLMEnrichmentResult(malware_families=["WINELOADER"],
                              relationships=[_rel("evil.example", "hosts", "WINELOADER")])
    ents = [RawEntity(value="evil.example", entity_type=EntityType.DOMAIN)]
    _, led = _build(ents, llm, relationship_policy=pol)
    e = _entry(led, "evil.example", "hosts", "WINELOADER")
    assert [(c["kind"], c.get("reason")) for c in e["changes"]] == [
        ("reroute", None), ("verb", "policy_pin")]
    assert e["final_type"] == "indicates"


# ── relationships: merged, dropped ───────────────────────────────────────────

def test_duplicate_row_is_merged_into_the_first_edge():
    llm = LLMEnrichmentResult(threat_actors=["APT29"], malware_families=["WINELOADER"],
                              relationships=[_rel("APT29", "uses", "WINELOADER"),
                                             _rel("apt29", "uses", "wineloader")])
    _, led = _build(llm=llm)
    first = _entry(led, "APT29", "uses", "WINELOADER")
    second = _entry(led, "apt29", "uses", "wineloader")
    assert second["outcome"] == "merged"
    assert second["merged_with"] == first["stix_id"]


def test_dated_duplicate_replaces_the_undated_edge_and_the_ledger_follows():
    start = datetime(2023, 1, 1, tzinfo=timezone.utc)
    llm = LLMEnrichmentResult(threat_actors=["APT29"], malware_families=["WINELOADER"],
                              relationships=[_rel("APT29", "uses", "WINELOADER"),
                                             _rel("APT29", "uses", "wineloader", start_time=start)])
    bundle, led = _build(llm=llm)
    undated = _entry(led, "APT29", "uses", "WINELOADER")
    dated = _entry(led, "APT29", "uses", "wineloader")
    assert dated["outcome"] == "emitted"
    assert undated["outcome"] == "merged" and undated["merged_with"] == dated["stix_id"]
    assert dated["stix_id"] in _by_id(bundle)
    assert led["objects"][dated["stix_id"]]["origin"] == "extracted"


def test_unresolved_endpoint_is_dropped_with_its_side():
    llm = LLMEnrichmentResult(threat_actors=["APT29"],
                              relationships=[_rel("APT29", "uses", "NoSuchMalware")])
    _, led = _build(llm=llm)
    e = _entry(led, "APT29", "uses", "NoSuchMalware")
    assert e["outcome"] == "dropped" and e["reason"] == "unresolved_target"
    assert "stix_id" not in e


def test_self_loop_is_dropped_and_names_the_object():
    llm = LLMEnrichmentResult(threat_actors=["APT29"],
                              relationships=[_rel("APT29", "related-to", "apt29")])
    bundle, led = _build(llm=llm)
    e = _entry(led, "APT29", "related-to", "apt29")
    assert e["outcome"] == "dropped" and e["reason"] == "self_loop"
    assert _by_id(bundle)[e["stix_ref"]].type == "threat-actor"


def test_observable_to_attack_pattern_is_dropped():
    from pipeline.stage3_llm import TTPExtracted
    llm = LLMEnrichmentResult(
        ttps=[TTPExtracted(technique_name="Application Layer Protocol", mitre_id="T1071")],
        relationships=[_rel("9.9.9.9", "communicates-with", "T1071")],
    )
    ents = [RawEntity(value="9.9.9.9", entity_type=EntityType.IPV4)]
    _, led = _build(ents, llm)
    e = _entry(led, "9.9.9.9", "communicates-with", "T1071")
    assert e["outcome"] == "dropped" and e["reason"] == "observable_to_attack_pattern"


# ── entities ─────────────────────────────────────────────────────────────────

def _entities(led, value, etype):
    return [e for e in led["entities"] if e["value"] == value and e["entity_type"] == etype]


def test_entity_outcomes():
    ents = [
        RawEntity(value="9.9.9.9", entity_type=EntityType.IPV4),
        RawEntity(value="9.9.9.9", entity_type=EntityType.IPV4),
        RawEntity(value="ASnothing", entity_type=EntityType.ASN),
        RawEntity(value="Atlantis", entity_type=EntityType.LOCATION),
        RawEntity(value="France", entity_type=EntityType.LOCATION),
    ]
    llm = LLMEnrichmentResult(malware_families=["WINELOADER", "wineloader"],
                              targeted_countries=["Narnia"])
    bundle, led = _build(ents, llm)
    ip = _entities(led, "9.9.9.9", "ipv4")
    assert [e["outcome"] for e in ip] == ["emitted", "merged"]
    assert ip[0]["stix_id"] == ip[1]["stix_id"] and ip[0]["stix_type"] == "ipv4-addr"
    assert _entities(led, "ASnothing", "asn")[0]["reason"] == "not_representable"
    assert _entities(led, "Atlantis", "location")[0]["reason"] == "no_iso_country"
    assert _entities(led, "France", "location")[0]["outcome"] == "emitted"
    wl = _entities(led, "wineloader", "malware")[0]
    assert wl["outcome"] == "merged" and wl["reason"] == "same_value"
    narnia = _entities(led, "Narnia", "location")[0]
    assert narnia["outcome"] == "dropped" and narnia["input"] == "targeted_country"


def test_named_raw_entity_the_llm_did_not_list_is_reported_dropped():
    # A pipeline run passes NER/gazetteer names as raw entities; the bundle maps
    # named objects from the LLM lists only, so one the LLM did not echo is not
    # in the first bundle.  It must say so rather than vanish.
    ents = [RawEntity(value="Cobalt Strike", entity_type=EntityType.TOOL, source="gazetteer"),
            RawEntity(value="WINELOADER", entity_type=EntityType.MALWARE, source="gazetteer")]
    bundle, led = _build(ents, LLMEnrichmentResult(malware_families=["WINELOADER"]))
    cs = _entities(led, "Cobalt Strike", "tool")[0]
    assert cs["outcome"] == "dropped" and cs["reason"] == "not_in_llm_lists"
    wl = [e for e in _entities(led, "WINELOADER", "malware") if e["outcome"] == "merged"]
    assert wl and wl[0]["stix_id"] in _by_id(bundle)


# ── why generated objects and edges exist ────────────────────────────────────

def test_generated_objects_and_edges_carry_their_origin():
    ents = [RawEntity(value="evil.example", entity_type=EntityType.DOMAIN)]
    llm = LLMEnrichmentResult(
        threat_actors=["APT29"], malware_families=["WINELOADER"],
        targeted_countries=["France"],
        ioc_associations=[IoCAssociation(ioc_value="evil.example", malware_name="WINELOADER")],
    )
    bundle, led = _build(ents, llm)
    origin = {o.id: led["objects"].get(o.id, {}).get("origin") for o in bundle.objects}
    by_type: dict[str, set] = {}
    for o in bundle.objects:
        key = o.type if o.type != "relationship" else f"rel:{o.relationship_type}"
        by_type.setdefault(key, set()).add(origin[o.id])
    assert by_type["indicator"] == {"ioc_indicator"}
    assert by_type["rel:based-on"] == {"ioc_based_on"}
    assert by_type["rel:indicates"] == {"ioc_association"}
    assert by_type["rel:targets"] == {"targeted_location"}
    assert by_type["location"] == {"targeted_country"}
    assert by_type["report"] == {"report"}
    # every SRO in the bundle is classified
    assert all(origin[o.id] for o in bundle.objects if o.type == "relationship")


def test_pin_and_completion_edges_are_classified_from_their_provenance():
    from pipeline.stage3_llm import TTPExtracted
    llm = LLMEnrichmentResult(
        threat_actors=["APT29"], malware_families=["WINELOADER"], tools=["Mimikatz"],
        ttps=[TTPExtracted(technique_name="PowerShell", mitre_id="T1059.001")],
        relationships=[_rel("APT29", "uses", "WINELOADER"),
                       _rel("WINELOADER", "uses", "PowerShell")],
    )

    def origins(completion):
        pol = {"version": 1, "global": "enforce", "completion": completion,
               "rules": [{"src": "threat-actor", "verb": "uses", "tgt": "tool",
                          "mode": "pin", "enabled": True}]}
        bundle, led = _build(llm=llm, relationship_policy=pol)
        return {led["objects"][o.id]["origin"] for o in bundle.objects if o.type == "relationship"}

    # ATT&CK curates "APT29 uses PowerShell" (G0016 > T1059.001): the reference
    # step adds it, which leaves the transitive step nothing new to compose.
    with_reference = origins({})
    assert {"policy_pin", "completion_reference", "extracted"} <= with_reference
    assert "completion_transitive" in origins({"reference": False})


def test_alias_merge_in_stage_4b_is_carried_into_the_ledger():
    pol = {"version": 1, "global": "auto", "rules": [],
           "completion": {"alias": True, "reference": False, "transitive": False}}
    llm = LLMEnrichmentResult(
        threat_actors=["APT29"],
        malware_families=["WINE-LOADER", "WINELOADER"],
        relationships=[_rel("WINE-LOADER", "variant-of", "WINELOADER"),
                       _rel("APT29", "uses", "WINE-LOADER"),
                       _rel("APT29", "uses", "WINELOADER")],
    )
    bundle, led = _build(llm=llm, relationship_policy=pol)
    ids = set(_by_id(bundle))
    removed = {r["stix_id"]: r for r in led["removed"]}
    assert any(r["kind"] == "object" and r["reason"] == "alias_merge" for r in removed.values())
    loop = _entry(led, "WINE-LOADER", "variant-of", "WINELOADER")
    assert loop["outcome"] == "dropped" and loop["reason"] == "self_loop_after_alias_merge"
    a = _entry(led, "APT29", "uses", "WINE-LOADER")
    b = _entry(led, "APT29", "uses", "WINELOADER")
    assert {a["outcome"], b["outcome"]} == {"emitted", "merged"}
    assert a["stix_id"] == b["stix_id"] and a["stix_id"] in ids
    for name in ("WINE-LOADER", "WINELOADER"):
        e = _entities(led, name, "malware")[0]
        assert e["stix_id"] in ids, e


def test_ledger_does_not_change_the_bundle():
    ents = [RawEntity(value="evil.example", entity_type=EntityType.DOMAIN)]
    llm = LLMEnrichmentResult(threat_actors=["APT29"], malware_families=["WINELOADER"],
                              relationships=[_rel("APT29", "uses", "WINELOADER")])

    def shape(b):
        return sorted(
            (o.type, o.get("relationship_type", ""), o.get("source_ref", ""), o.get("target_ref", ""))
            for o in b.objects if o.type not in ("report", "identity", "marking-definition")
        )

    with_ledger = build_stix_bundle(ents, llm, "r", ledger=MappingLedger())
    without = build_stix_bundle(ents, llm, "r")
    assert shape(with_ledger) == shape(without)


# ── stored with the bundle, served by the API ────────────────────────────────

def test_finalize_stores_the_ledger_and_the_api_serves_it(temp_db, temp_db_client):
    from api import worker

    job_id = "job-ledger"
    with temp_db.get_conn() as conn:
        conn.execute(
            "INSERT INTO jobs (id, original_filename, status, report_text, created_at, updated_at) "
            "VALUES (?,?,?,?,?,?)",
            (job_id, "report.txt", "reviewing", "APT29 used WellMess.",
             temp_db.now_iso(), temp_db.now_iso()),
        )
        conn.commit()

    assert temp_db_client.get(f"/api/jobs/{job_id}/bundle/ledger").status_code == 404

    llm = LLMEnrichmentResult(threat_actors=["APT29"], malware_families=["WellMess"],
                              relationships=[_rel("APT29", "uses", "WellMess"),
                                             _rel("APT29", "uses", "Ghost")])
    worker._save_entities(job_id, [], llm)
    path = worker.bundle_output_path(job_id, "report")
    try:
        assert worker.re_run_final_stages(job_id, skip_rescan=True)
    finally:
        path.unlink(missing_ok=True)

    resp = temp_db_client.get(f"/api/jobs/{job_id}/bundle/ledger")
    assert resp.status_code == 200
    led = resp.json()
    assert led["version"] == 1
    outcomes = {(e["target_value"], e["outcome"]) for e in led["relationships"]}
    assert outcomes == {("WellMess", "emitted"), ("Ghost", "dropped")}
    bundle = temp_db_client.get(f"/api/jobs/{job_id}/bundle").json()
    shipped = {o["id"] for o in bundle["objects"]}
    assert all(e["stix_id"] in shipped for e in led["relationships"] if e["outcome"] == "emitted")
    json.dumps(led)   # plain JSON all the way down
