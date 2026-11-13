"""scripts/opencti_import_bundle.py (ADR-0094 item 10, #708): one bundle imported, checked, reported.

No OpenCTI and no pycti are needed: the client and pycti's splitter are fakes.
Without pycti installed, the script's module is loaded with stubs of the two
pycti names it imports; the stubs are removed from sys.modules afterwards.

The fake keeps what it imports, as OpenCTI's STIX export shows it, so the
checks of scripts/opencti_expectations.py run on it as they run on a real
platform. Each test changes one thing OpenCTI could do, and expects the check
that guards it to fail.
"""
from __future__ import annotations

import copy
import json
import sys
import types
from pathlib import Path

import pytest


def _load_script():
    """The script, with the real pycti when it is installed, else with stubs removed again after the import."""
    try:
        import pycti  # noqa: F401
    except ImportError:
        pass
    else:
        from scripts import opencti_import_bundle
        return opencti_import_bundle
    package = types.ModuleType("pycti")
    package.OpenCTIApiClient = object
    utils = types.ModuleType("pycti.utils")
    splitter = types.ModuleType("pycti.utils.opencti_stix2_splitter")
    splitter.OpenCTIStix2Splitter = object
    stubs = {"pycti": package, "pycti.utils": utils, "pycti.utils.opencti_stix2_splitter": splitter}
    sys.modules.update(stubs)
    try:
        from scripts import opencti_import_bundle
    finally:
        for name in stubs:
            sys.modules.pop(name, None)
    return opencti_import_bundle


script = _load_script()
check = script.check
expect = script.expect

IDENT = "identity--11111111-1111-4111-8111-111111111111"
MALWARE = "malware--22222222-2222-4222-8222-222222222222"
RELATIONSHIP = "relationship--33333333-3333-4333-8333-333333333333"
MARKING = "marking-definition--44444444-4444-4444-8444-444444444444"
REPORT = "report--55555555-5555-4555-8555-555555555555"
REPORT_TWO = "report--77777777-7777-4777-8777-777777777777"
DUPLICATE = "malware--99999999-9999-4999-8999-999999999999"
TOKEN = "SECRET-TOKEN-7f3a9c"
DIGEST = "sha256:" + "a" * 64
REQUIRED_NOT_RUN = "not checked"


def bundle_objects() -> list[dict]:
    return [
        {"type": "marking-definition", "id": MARKING, "definition_type": "tlp", "definition": {"tlp": "amber"}},
        {"type": "identity", "id": IDENT, "name": "ACME", "identity_class": "organization"},
        {"type": "malware", "id": MALWARE, "name": "WellMess", "description": "A backdoor.",
         "created_by_ref": IDENT, "object_marking_refs": [MARKING]},
        {"type": "relationship", "id": RELATIONSHIP, "relationship_type": "uses", "source_ref": MALWARE,
         "target_ref": IDENT, "created_by_ref": IDENT},
        {"type": "report", "id": REPORT, "name": "WellMess report", "published": "2026-11-08T00:00:00Z",
         "description": "The analyst's summary.", "object_refs": [MALWARE, RELATIONSHIP],
         "created_by_ref": IDENT, "object_marking_refs": [MARKING],
         "x_opencti_files": [{"name": "wellmess.pdf", "mime_type": "application/pdf"}]},
    ]


def without(objects: list[dict], stix_id: str) -> list[dict]:
    return [o for o in objects if o["id"] != stix_id]


class FakeOpenCTI:
    """An OpenCTI that keeps each import under its key and answers the platform reads.

    refuse: ids it refuses with an error. unseen: ids it keeps but never shows.
    attach: whether a Report's x_opencti_files are attached to it.
    keep: optional (item, stored, store) -> (key, stored), to change what is kept.
    churn: every marking read adds a new marking, so two readings never agree.
    """

    def __init__(self, refuse=(), unseen=(), attach=True, keep=None, churn=False) -> None:
        self.store: dict[str, dict] = {}
        self.refuse = set(refuse)
        self.unseen = set(unseen)
        self.attach = attach
        self.keep = keep
        self.churn = churn
        self.marking_reads = 0
        self.stix2 = self

    def import_item(self, item: dict, update: bool = True, *args) -> None:
        if item["id"] in self.refuse:
            raise RuntimeError(f"MISSING_REFERENCE_ERROR: {item['id']} refused by the fake")
        stored = copy.deepcopy(item)
        if item["type"] == "report" and self.attach:
            files = [{"name": f["name"], "mime_type": f["mime_type"]} for f in item.get("x_opencti_files") or []]
            stored["extensions"] = {check.expect.OPENCTI_EXTENSION: {"files": files}}
        key = item["id"]
        if self.keep is not None:
            key, stored = self.keep(item, stored, self.store)
        self.store[key] = stored

    def _node(self, key: str, stored: dict) -> dict:
        return {"standard_id": key, "entity_type": stored["type"],
                "x_opencti_stix_ids": [] if key == stored["id"] else [stored["id"]],
                "toStix": stored, "definition": stored.get("definition"),
                "definition_type": stored.get("definition_type")}

    def _connection(self, nodes: list[dict]) -> dict:
        return {"pageInfo": {"hasNextPage": False, "endCursor": None}, "edges": [{"node": n} for n in nodes]}

    def query(self, query: str, variables: dict | None = None) -> dict:
        shown = [(k, s) for k, s in self.store.items() if s["id"] not in self.unseen]
        if query == check.ABOUT_QUERY:
            return {"data": {"about": {"version": "7.test"}}}
        if query == check.ALL_OBJECTS_QUERY:
            nodes = [self._node(k, s) for k, s in shown if s["type"] not in ("relationship", "marking-definition")]
            return {"data": {"stixCoreObjects": self._connection(nodes)}}
        if query == check.ALL_RELATIONSHIPS_QUERY:
            nodes = [self._node(k, s) for k, s in shown if s["type"] == "relationship"]
            return {"data": {"stixCoreRelationships": self._connection(nodes)}}
        if query == check.ALL_MARKINGS_QUERY:
            nodes = [self._node(k, s) for k, s in shown if s["type"] == "marking-definition"]
            if self.churn:
                self.marking_reads += 1
                nodes.append({"standard_id": f"marking-definition--00000000-0000-4000-8000-{self.marking_reads:012d}",
                              "x_opencti_stix_ids": [], "definition": "churn", "definition_type": "churn"})
            return {"data": {"markingDefinitions": {"edges": [{"node": n} for n in nodes]}}}
        raise AssertionError(f"unexpected query: {query[:60]}")


class FakeSplitter:
    def split_bundle_with_expectations(self, bundle, flag, event_version):
        return None, [], [{"id": "work", "objects": bundle["objects"]}]


@pytest.fixture(autouse=True)
def no_wait(monkeypatch):
    monkeypatch.setattr(script.check, "POLL_INTERVAL", 0.0)


@pytest.fixture
def install(monkeypatch):
    def install_fake(fake, seen_tokens: list[str] | None = None):
        def make_client(url, token):
            if seen_tokens is not None:
                seen_tokens.append(token)
            return fake
        monkeypatch.setattr(script.check, "make_client", make_client)
        monkeypatch.setattr(script.check, "OpenCTIStix2Splitter", FakeSplitter)
    return install_fake


def write_bundle(path: Path, objects: list[dict]) -> Path:
    path.write_text(json.dumps({"type": "bundle", "id": "bundle--66666666-6666-4666-8666-666666666666",
                                "objects": objects}), encoding="utf-8")
    return path


@pytest.fixture
def files(tmp_path):
    bundle = write_bundle(tmp_path / "bundle.json", bundle_objects())
    token = tmp_path / "token.txt"
    token.write_text(TOKEN + "\n", encoding="utf-8")
    return tmp_path, bundle, token


def argv(bundle: Path, token: Path, out: Path, *extra: str) -> list[str]:
    return [str(bundle), "--token-file", str(token), "--out-dir", str(out), "--timeout", "5", *extra]


def report_of(out: Path) -> dict:
    return json.loads((out / "report.json").read_text(encoding="utf-8"))


def status_of(report: dict, name: str) -> list[str]:
    return [c["status"] for c in report["checks"] if name in c["check"]]


def test_everything_found_exits_zero_and_both_reports_are_written(files, install, capsys):
    tmp_path, bundle, token = files
    seen: list[str] = []
    install(FakeOpenCTI(), seen)
    out = tmp_path / "out"
    assert script.main(argv(bundle, token, out)) == 0
    assert seen == [TOKEN]

    report = report_of(out)
    assert report["passed"] is True
    assert report["totals"] == {"sent": 5, "found": 5, "missing": 0, "refused": 0}
    assert report["types"]["relationship"] == {"sent": 1, "found": 1, "missing": 0, "refused": 0}
    assert report["types"]["marking-definition"] == {"sent": 1, "found": 1, "missing": 0, "refused": 0}
    assert report["opencti"]["version"] == "7.test"
    assert report["bundle"]["objects"] == 5 and len(report["bundle"]["sha256"]) == 64
    assert report["image_digest"] is None
    assert report["not_checked"] == []
    assert all(c["status"] == "pass" for c in report["checks"])
    assert status_of(report, "every object in OpenCTI, once") == ["pass", "pass"]
    assert status_of(report, "no attribute changed by a second import") == ["pass"]
    markdown = (out / "report.md").read_text(encoding="utf-8")
    assert "| report | 1 | 1 | 0 | 0 |" in markdown
    assert "every check passed" in capsys.readouterr().out
    assert TOKEN not in markdown + json.dumps(report)


def test_the_inventory_is_taken_from_the_bundle_and_written(files, install):
    tmp_path, bundle, token = files
    install(FakeOpenCTI())
    out = tmp_path / "out"
    assert script.main(argv(bundle, token, out)) == 0
    inventory = report_of(out)["inventory"]
    assert [o["id"] for o in inventory["objects"]] == [o["id"] for o in bundle_objects()]
    assert inventory["relationships"] == [{"id": RELATIONSHIP, "relationship_type": "uses",
                                           "source_ref": MALWARE, "target_ref": IDENT}]
    assert inventory["reports"] == [{"id": REPORT, "name": "WellMess report", "object_refs": [MALWARE, RELATIONSHIP],
                                     "description": True, "files": ["wellmess.pdf"]}]
    malware = next(o for o in inventory["objects"] if o["id"] == MALWARE)
    assert malware == {"id": MALWARE, "type": "malware", "name": "WellMess", "description": True}


def test_a_missing_and_a_refused_object_exit_one_and_are_named(files, install, capsys):
    tmp_path, bundle, token = files
    install(FakeOpenCTI(refuse=[MALWARE], unseen=[RELATIONSHIP]))
    out = tmp_path / "out"
    assert script.main(argv(bundle, token, out)) == 1

    report = report_of(out)
    assert report["passed"] is False
    assert {m["id"] for m in report["missing"]} == {MALWARE, RELATIONSHIP}
    assert [r["id"] for r in report["refused"]] == [MALWARE]
    assert "MISSING_REFERENCE_ERROR" in report["refused"][0]["error"]
    assert report["types"]["malware"] == {"sent": 1, "found": 0, "missing": 1, "refused": 1}
    assert report["types"]["relationship"] == {"sent": 1, "found": 0, "missing": 1, "refused": 0}
    assert report["types"]["report"]["found"] == 1

    out_text = capsys.readouterr().out
    assert f"MISSING  {RELATIONSHIP} (relationship)" in out_text
    assert f"REFUSED  {MALWARE} (malware)" in out_text
    markdown = (out / "report.md").read_text(encoding="utf-8")
    assert f"- `{RELATIONSHIP}` (relationship)" in markdown
    assert "MISSING_REFERENCE_ERROR" in markdown
    assert TOKEN not in out_text + markdown + json.dumps(report)


def test_a_refusal_alone_fails_even_when_every_object_is_found(files, install):
    tmp_path, bundle, token = files
    fake = FakeOpenCTI()
    real_import = fake.import_item

    def refuse_report_once(item, update=True, *args):
        if item["id"] == REPORT:
            raise RuntimeError("FORBIDDEN_ACCESS: the fake refuses the report")
        real_import(item, update, *args)

    fake.import_item = refuse_report_once
    install(fake)
    out = tmp_path / "out"
    assert script.main(argv(bundle, token, out)) == 1
    report = report_of(out)
    assert report["missing"] == [{"id": REPORT, "type": "report"}]
    assert report["refused"][0]["error"].startswith("FORBIDDEN_ACCESS")
    assert status_of(report, "nothing refused on import") == ["fail"]


def test_a_second_import_that_adds_a_duplicate_fails(files, install):
    tmp_path, bundle, token = files

    def duplicate_on_second_import(item, stored, store):
        if item["id"] == MALWARE and item["id"] in store:
            return DUPLICATE, stored     # OpenCTI keeps a second object under the same name
        return item["id"], stored

    install(FakeOpenCTI(keep=duplicate_on_second_import))
    out = tmp_path / "out"
    assert script.main(argv(bundle, token, out)) == 1
    report = report_of(out)
    # The first import is clean; the second one leaves two objects under one name, and the
    # bundle's id now answers to two objects, so the second reading finds it ambiguous.
    assert status_of(report, "a second import adds nothing") == ["fail"]
    assert status_of(report, "no second object of the same type and name") == ["pass", "fail"]
    assert status_of(report, "every object in OpenCTI, once") == ["pass", "fail"]


def test_an_attribute_changed_by_the_second_import_fails(files, install, capsys):
    tmp_path, bundle, token = files

    def describe_on_second_import(item, stored, store):
        if item["id"] == MALWARE and item["id"] in store:
            stored["description"] = "Changed by the second import."
        return item["id"], stored

    install(FakeOpenCTI(keep=describe_on_second_import))
    out = tmp_path / "out"
    assert script.main(argv(bundle, token, out)) == 1
    report = report_of(out)
    assert status_of(report, "no attribute changed by a second import") == ["fail"]
    changed = next(c for c in report["checks"] if c["check"] == "no attribute changed by a second import")
    assert changed["detail"][0]["id"] == MALWARE and changed["detail"][0]["field"] == "description"
    assert "FAIL" in capsys.readouterr().out


def test_a_dropped_description_fails(files, install):
    tmp_path, bundle, token = files

    def drop_description(item, stored, store):
        if item["id"] == MALWARE:
            stored.pop("description", None)
        return item["id"], stored

    install(FakeOpenCTI(keep=drop_description))
    out = tmp_path / "out"
    assert script.main(argv(bundle, token, out)) == 1
    report = report_of(out)
    assert status_of(report, "no description emptied") == ["fail", "fail"]
    assert status_of(report, "no attribute changed by a second import") == ["pass"]


def test_a_lost_marking_fails(files, install):
    tmp_path, bundle, token = files

    def unmark(item, stored, store):
        if item["id"] == MALWARE:
            stored["object_marking_refs"] = []
        return item["id"], stored

    install(FakeOpenCTI(keep=unmark))
    out = tmp_path / "out"
    assert script.main(argv(bundle, token, out)) == 1
    report = report_of(out)
    assert status_of(report, "each object's markings (TLP, PAP) as the bundles set them") == ["fail", "fail"]


def test_an_object_merged_into_another_by_alias_fails(tmp_path, install):
    other = {"type": "malware", "id": "malware--88888888-8888-4888-8888-888888888888", "name": "Other family",
             "aliases": ["WellMess"], "created_by_ref": IDENT, "object_marking_refs": [MARKING]}
    bundle = write_bundle(tmp_path / "bundle.json", bundle_objects() + [other])
    token = tmp_path / "token.txt"
    token.write_text(TOKEN, encoding="utf-8")

    def merge_by_alias(item, stored, store):
        if item["id"] == other["id"]:
            return MALWARE, stored    # OpenCTI puts it on the object it finds under the alias
        return item["id"], stored

    install(FakeOpenCTI(keep=merge_by_alias))
    out = tmp_path / "out"
    assert script.main(argv(bundle, token, out)) == 1
    report = report_of(out)
    merged = [c for c in report["checks"] if c["check"].endswith("each object on an OpenCTI object of its own")]
    assert [c["status"] for c in merged] == ["fail", "fail"]
    assert merged[0]["detail"] == {MALWARE: sorted([MALWARE, other["id"]])}


def test_a_missing_attachment_fails(files, install):
    tmp_path, bundle, token = files
    install(FakeOpenCTI(attach=False))
    out = tmp_path / "out"
    assert script.main(argv(bundle, token, out)) == 1
    report = report_of(out)
    attached = [c for c in report["checks"] if "file attached once" in c["check"]]
    assert [c["status"] for c in attached] == ["fail", "fail"]
    assert attached[0]["observed"] == "not attached"


def test_a_missing_endpoint_of_a_relationship_fails(files, install):
    tmp_path, bundle, token = files
    install(FakeOpenCTI(unseen=[IDENT]))
    out = tmp_path / "out"
    assert script.main(argv(bundle, token, out)) == 1
    report = report_of(out)
    assert "fail" in status_of(report, "each relationship joins the objects the bundle names")
    assert {m["id"] for m in report["missing"]} == {IDENT}


def test_two_reports_in_the_bundle_fail(tmp_path, install):
    second = {"type": "report", "id": REPORT_TWO, "name": "Second report", "published": "2026-11-08T00:00:00Z",
              "object_refs": [MALWARE], "created_by_ref": IDENT}
    bundle = write_bundle(tmp_path / "bundle.json", bundle_objects() + [second])
    token = tmp_path / "token.txt"
    token.write_text(TOKEN, encoding="utf-8")
    install(FakeOpenCTI())
    out = tmp_path / "out"
    assert script.main(argv(bundle, token, out)) == 1
    report = report_of(out)
    assert status_of(report, "one Report in the bundle") == ["fail"]


def test_a_bundle_without_a_report_leaves_the_report_checks_not_checked(tmp_path, install):
    bundle = write_bundle(tmp_path / "bundle.json", without(bundle_objects(), REPORT))
    token = tmp_path / "token.txt"
    token.write_text(TOKEN, encoding="utf-8")
    install(FakeOpenCTI())
    out = tmp_path / "out"
    assert script.main(argv(bundle, token, out)) == 1
    report = report_of(out)
    assert report["not_checked"] == ["the Report holds the bundle's references"]
    assert [c["status"] for c in report["checks"] if c["check"] == "the Report holds the bundle's references"] \
        == ["not_checked"]
    assert status_of(report, "one Report in the bundle") == ["fail"]
    assert report["passed"] is False


def test_a_reading_that_never_settles_fails(files, install):
    tmp_path, bundle, token = files
    install(FakeOpenCTI(churn=True))
    out = tmp_path / "out"
    assert script.main(argv(bundle, token, out, "--timeout", "0.05")) == 1
    report = report_of(out)
    assert status_of(report, "every reading of the platform settled") == ["fail"]


def test_the_image_digest_is_recorded_when_given(files, install):
    tmp_path, bundle, token = files
    install(FakeOpenCTI())
    out = tmp_path / "out"
    assert script.main(argv(bundle, token, out, "--image-digest", DIGEST)) == 0
    assert report_of(out)["image_digest"] == DIGEST
    assert DIGEST in (out / "report.md").read_text(encoding="utf-8")


def test_a_malformed_image_digest_exits_two_and_writes_nothing(files, install, capsys):
    tmp_path, bundle, token = files
    install(FakeOpenCTI())
    out = tmp_path / "out"
    assert script.main(argv(bundle, token, out, "--image-digest", "latest")) == 2
    assert not out.exists()
    assert "--image-digest" in capsys.readouterr().err


def test_a_bundle_without_objects_exits_two_and_writes_nothing(files, install):
    tmp_path, _, token = files
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"type": "bundle", "objects": []}), encoding="utf-8")
    install(FakeOpenCTI())
    out = tmp_path / "out"
    assert script.main(argv(empty, token, out)) == 2
    assert not out.exists()


def test_a_relationship_without_its_ends_exits_two(tmp_path, install, capsys):
    broken = [o for o in bundle_objects() if o["type"] != "relationship"]
    broken.append({"type": "relationship", "id": RELATIONSHIP, "relationship_type": "uses", "source_ref": MALWARE})
    bundle = write_bundle(tmp_path / "bundle.json", broken)
    token = tmp_path / "token.txt"
    token.write_text(TOKEN, encoding="utf-8")
    install(FakeOpenCTI())
    assert script.main(argv(bundle, token, tmp_path / "out")) == 2
    assert "cannot read the bundle" in capsys.readouterr().err


def test_an_unreachable_opencti_exits_two_with_one_line(files, monkeypatch, capsys):
    tmp_path, bundle, token = files

    def unreachable(url, token):
        raise ConnectionError("connection refused")

    monkeypatch.setattr(script.check, "make_client", unreachable)
    assert script.main(argv(bundle, token, tmp_path / "out")) == 2
    err = capsys.readouterr().err
    assert "the import stopped at" in err and "ConnectionError" in err
    assert "Traceback" not in err


def test_the_token_comes_from_a_bare_file_or_an_env_style_file(tmp_path):
    bare = tmp_path / "bare.txt"
    bare.write_text("  " + TOKEN + "\n", encoding="utf-8")
    assert script.read_token(bare) == TOKEN

    env = tmp_path / "env.txt"
    env.write_text(f"OPENCTI_HOST=x\nOPENCTI_ADMIN_TOKEN={TOKEN}\n", encoding="utf-8")
    assert script.read_token(env) == TOKEN

    two = tmp_path / "two.txt"
    two.write_text(f"{TOKEN}\nanother line\n", encoding="utf-8")
    with pytest.raises(script.CannotRun) as info:
        script.read_token(two)
    assert TOKEN not in str(info.value)


def test_a_token_file_missing_or_empty_is_reported_without_the_token(tmp_path):
    with pytest.raises(script.CannotRun, match="cannot read the token file"):
        script.read_token(tmp_path / "absent.txt")
    empty = tmp_path / "empty.txt"
    empty.write_text("OPENCTI_ADMIN_TOKEN=\n", encoding="utf-8")
    with pytest.raises(script.CannotRun, match="is empty"):
        script.read_token(empty)


def test_an_unreadable_bundle_exits_two(tmp_path, install, capsys):
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    token = tmp_path / "token.txt"
    token.write_text(TOKEN, encoding="utf-8")
    install(FakeOpenCTI())
    assert script.main(argv(broken, token, tmp_path / "out")) == 2
    assert "cannot read the bundle" in capsys.readouterr().err
