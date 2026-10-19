"""ATT&CK version mapping: gold labels from an older ATT&CK against today's.

AnnoCTR was annotated against the ATT&CK of 2022; the pipeline predicts ids
from its own index (pipeline/data/mitre_index.json).  Between the two,
techniques were revoked (merged into another id), deprecated, or split into
sub-techniques.  Without a mapping, a pipeline that answers with the current id
is scored as wrong — a taxonomy gap read as a model error.

`mapping(gold_ids)` gives, for every gold id: its status in the current bundle,
the id it resolves to (following `revoked-by` chains), and whether the pipeline
can emit it at all.  Gold ids that resolve to nothing the pipeline knows are
reported and left out of the primary score, never silently counted as misses.

The mapping is made against one ATT&CK release (ADR-0087): `Catalogue.for_release`
finds that release's enterprise bundle by its sha256, never by its file name.
`release_diff` and `release_change` say what differs between two releases, to tell
a taxonomy effect from a system effect when two runs ran on different ones.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from pipeline import attack_data

_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BUNDLE = _ROOT / "data" / "enterprise-attack.json"
PIPELINE_INDEX = _ROOT / "pipeline" / "data" / "mitre_index.json"

ACTIVE, REVOKED, DEPRECATED, UNKNOWN = "active", "revoked", "deprecated", "unknown"


def parent(tid: str) -> str:
    return tid.split(".", 1)[0].upper()


@dataclass
class Resolution:
    gold_id: str
    status: str                 # status of gold_id in the current bundle
    canonical: str | None       # the id to score against (None = out of scope)
    in_pipeline: bool           # can the pipeline emit `canonical`?

    def as_dict(self) -> dict:
        return {"gold_id": self.gold_id, "status": self.status,
                "canonical": self.canonical, "in_pipeline": self.in_pipeline}


class Catalogue:
    def __init__(self, bundle_path: Path = DEFAULT_BUNDLE, pipeline_index: Path = PIPELINE_INDEX):
        if not bundle_path.exists():
            raise FileNotFoundError(
                f"{bundle_path} missing — run: python scripts/download_attack.py")
        raw = bundle_path.read_bytes()
        self.bundle_sha256 = hashlib.sha256(raw).hexdigest()
        self.release: attack_data.Release | None = None      # set by for_release
        objects = json.loads(raw)["objects"]

        self.status: dict[str, str] = {}
        stix_to_tid: dict[str, str] = {}
        latest_modified = ""
        for o in objects:
            if o.get("type") != "attack-pattern":
                continue
            tid = next((r["external_id"] for r in o.get("external_references", [])
                        if r.get("source_name") == "mitre-attack"), None)
            if not tid:
                continue
            tid = tid.upper()
            stix_to_tid[o["id"]] = tid
            latest_modified = max(latest_modified, o.get("modified", ""))
            if o.get("revoked"):
                self.status[tid] = REVOKED
            elif o.get("x_mitre_deprecated"):
                self.status[tid] = DEPRECATED
            else:
                self.status.setdefault(tid, ACTIVE)
        self.latest_modified = latest_modified

        self.revoked_by: dict[str, str] = {}
        for o in objects:
            if o.get("type") == "relationship" and o.get("relationship_type") == "revoked-by":
                src, dst = stix_to_tid.get(o.get("source_ref", "")), stix_to_tid.get(o.get("target_ref", ""))
                if src and dst:
                    self.revoked_by[src] = dst

        index = json.loads(pipeline_index.read_text(encoding="utf-8"))
        self.pipeline_ids = {t["id"].upper() for t in index.get("techniques", [])
                             if str(t.get("id", "")).upper().startswith("T")}

    @classmethod
    def for_release(cls, version: str | None = None, *, data_dir: Path = _ROOT / "data") -> Catalogue:
        """The catalogue of one ATT&CK release: its enterprise bundle from
        `data_dir` and the index of the pipeline track that release names.
        `version` is spelled as ATTACK_RELEASE is ("" the default track) and
        refused the same way; None is the release ATTACK_RELEASE selects."""
        rel = attack_data.current() if version is None else attack_data.release(version)
        cat = cls(_enterprise_bundle(rel, data_dir), rel.directory / "mitre_index.json")
        cat.release = rel
        return cat

    def resolve(self, gold_id: str) -> Resolution:
        gid = gold_id.upper()
        status = self.status.get(gid, UNKNOWN)
        canonical: str | None = gid
        seen = set()
        while canonical in self.revoked_by and canonical not in seen:
            seen.add(canonical)
            canonical = self.revoked_by[canonical]
        if status == DEPRECATED or (status == REVOKED and canonical == gid):
            canonical = None
        if status == UNKNOWN:
            # Not in the current bundle at all; the pipeline may still know it.
            canonical = gid if gid in self.pipeline_ids else None
        return Resolution(gid, status, canonical,
                          canonical is not None and canonical in self.pipeline_ids)

    def mapping(self, gold_ids: set[str]) -> dict[str, Resolution]:
        return {g: self.resolve(g) for g in sorted(gold_ids)}

    def summary(self) -> dict:
        return {"release": self.release.version if self.release else None,
                "bundle_sha256": self.bundle_sha256[:16],
                "bundle_latest_modified": self.latest_modified,
                "pipeline_index_ids": len(self.pipeline_ids)}


# ── Which bundle, which release ──────────────────────────────────────────────

def default_release() -> str:
    """The version of the default track (pipeline/data/)."""
    return attack_data.release("").version


def release_version(value: str) -> str:
    """"v19.2" and "19.2" are 19.2.  The value becomes a directory name, so
    anything but an ATT&CK version raises ValueError."""
    name = value.strip()
    name = name[1:] if name[:1] in ("v", "V") else name
    if not attack_data.is_version(name):
        raise ValueError(f"{value!r} is not an ATT&CK version (19.2, 20.0, ...)")
    return name


def release_dir(version: str, data_dir: Path = _ROOT / "data") -> Path:
    """Where `scripts/download_attack.py --release` keeps a release's bundles."""
    return data_dir / "attack-stix" / f"v{release_version(version)}"


def _enterprise_bundle(rel: attack_data.Release, data_dir: Path) -> Path:
    """The enterprise bundle `rel` was built from, found by content.

    On the default track `data/enterprise-attack.json` is the mitre/cti copy its
    manifest recorded, or else the attack-stix-data asset it is equivalent to;
    a file that is neither (a later download) never maps the gold in its
    place.  Any other track has the asset its manifest names."""
    source: dict = next((s for s in rel.manifest.get("sources") or []
                         if s.get("domain") == "enterprise-attack"), {})
    asset = release_dir(rel.version, data_dir) / "enterprise-attack.json"
    wanted = [(asset, source.get("sha256"))]
    if rel.default:
        wanted = [(data_dir / "enterprise-attack.json", source.get("sha256")),
                  (asset, (source.get("equivalent_release_asset") or {}).get("sha256"))]
    tried = []
    for path, expected in wanted:
        found = attack_data.sha256(path)
        if expected and found == expected:
            return path
        state = "is missing" if found is None else "has sha256 " + found[:8]
        tried.append(f"{path} {state}, the manifest of {rel.version} records {(expected or '?')[:8]}")
    raise FileNotFoundError(
        f"no enterprise-attack.json matches ATT&CK {rel.version}: {'; '.join(tried)} — run: "
        f"python scripts/download_attack.py --release {rel.version}")


# ── Between two releases ─────────────────────────────────────────────────────

DOMAINS = ("enterprise-attack", "mobile-attack", "ics-attack")
_ATTACK_SOURCES = ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack")
_SOFTWARE_AND_GROUPS = ("malware", "tool", "intrusion-set", "campaign")


def _external_id(obj: dict) -> str | None:
    return next((r.get("external_id") for r in obj.get("external_references", [])
                 if r.get("source_name") in _ATTACK_SOURCES), None)


def _status(obj: dict) -> str:
    return REVOKED if obj.get("revoked") else DEPRECATED if obj.get("x_mitre_deprecated") else ACTIVE


def _read_domain(directory: Path, domain: str) -> dict:
    objects = json.loads((directory / f"{domain}.json").read_bytes())["objects"]
    techniques: dict[str, dict] = {}
    by_stix: dict[str, str] = {}
    software: dict[str, dict] = {}
    for o in objects:
        eid = _external_id(o)
        if o["type"] == "attack-pattern" and eid:
            by_stix[o["id"]] = eid
            techniques[eid] = {"status": _status(o), "name": o.get("name", ""),
                               "description": o.get("description", ""),
                               "tactics": sorted(p["phase_name"] for p in o.get("kill_chain_phases", []))}
        elif o["type"] in _SOFTWARE_AND_GROUPS and eid:
            software[eid] = {"name": o.get("name"), "status": _status(o),
                             "aliases": sorted(set(o.get("aliases") or o.get("x_mitre_aliases") or []))}
    procedures: Counter[str] = Counter()
    revoked_by: dict[str, str] = {}
    for o in objects:
        if o["type"] != "relationship" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        if o["relationship_type"] == "uses" and o.get("target_ref") in by_stix and o.get("description"):
            procedures[by_stix[o["target_ref"]]] += 1
        if o["relationship_type"] == "revoked-by" and o.get("source_ref") in by_stix \
                and o.get("target_ref") in by_stix:
            revoked_by[by_stix[o["source_ref"]]] = by_stix[o["target_ref"]]
    return {"techniques": techniques, "procedures": procedures, "revoked_by": revoked_by,
            "software": software,
            "tactics": sorted([_external_id(o) or "", o.get("x_mitre_shortname") or ""]
                              for o in objects if o["type"] == "x-mitre-tactic"),
            "collections": [[o.get("x_mitre_version"), o.get("modified")]
                            for o in objects if o["type"] == "x-mitre-collection"]}


def release_diff(old_dir: Path, new_dir: Path) -> dict:
    """What changed, technique by technique, between two attack-stix-data
    releases (a directory each, holding the three domains' bundles).

    Per domain: the techniques that became active (`new_active`) or stopped
    being (`no_longer_active`, with the id that replaced a revoked one), those
    renamed, with another description or other tactics, those with more
    procedures (`more_procedures`; a procedure is a non-revoked `uses`
    relationship that has a description), and the same for software and groups."""
    report = {}
    for domain in DOMAINS:
        old, new = _read_domain(old_dir, domain), _read_domain(new_dir, domain)
        ot, nt, op, np_ = old["techniques"], new["techniques"], old["procedures"], new["procedures"]
        act_o = {k for k, v in ot.items() if v["status"] == ACTIVE}
        act_n = {k for k, v in nt.items() if v["status"] == ACTIVE}
        both = act_o & act_n
        osw, nsw = old["software"], new["software"]
        more = sorted(k for k in act_n if np_[k] > op[k])
        r = {
            "collections": {"old": old["collections"], "new": new["collections"]},
            "active": {"old": len(act_o), "new": len(act_n)},
            "new_ids": sorted(set(nt) - set(ot)),
            "new_active": sorted(act_n - act_o),
            "no_longer_active": {k: {"status": nt.get(k, {}).get("status", "absent"),
                                     "revoked_by": new["revoked_by"].get(k), "name": ot[k]["name"]}
                                 for k in sorted(act_o - act_n)},
            "renamed": {k: [ot[k]["name"], nt[k]["name"]] for k in sorted(both)
                        if ot[k]["name"] != nt[k]["name"]},
            "description_changed": sorted(k for k in both if ot[k]["description"] != nt[k]["description"]),
            "tactics_changed": {k: [ot[k]["tactics"], nt[k]["tactics"]] for k in sorted(both)
                                if ot[k]["tactics"] != nt[k]["tactics"]},
            "procedures": {"old": sum(op.values()), "new": sum(np_.values()),
                           "techniques_with_more": len(more),
                           "techniques_with_fewer": len([k for k in act_n if np_[k] < op[k]])},
            "more_procedures": more,
            "new_revoked_by": {k: v for k, v in sorted(new["revoked_by"].items())
                               if old["revoked_by"].get(k) != v},
            "tactics": {"old": old["tactics"], "new": new["tactics"],
                        "same": old["tactics"] == new["tactics"]},
            "software_groups": {
                "new": {k: v["name"] for k, v in sorted(nsw.items())
                        if k not in osw and v["status"] == ACTIVE},
                "no_longer_active": {k: v["name"] for k, v in sorted(osw.items())
                                     if v["status"] == ACTIVE and nsw.get(k, {}).get("status") != ACTIVE},
                "renamed": {k: [osw[k]["name"], nsw[k]["name"]] for k in sorted(set(osw) & set(nsw))
                            if osw[k]["name"] != nsw[k]["name"]},
                "aliases_changed": len([k for k in set(osw) & set(nsw)
                                        if osw[k]["aliases"] != nsw[k]["aliases"]])},
        }
        r["new_active_names"] = {k: nt[k]["name"] for k in r["new_active"]}
        report[domain] = r
    return report


CHANGE_CLASSES = ("new_technique", "new_subtechnique", "status_changed", "content_changed", "unchanged")


def release_change(diff: dict) -> Callable[[str], str]:
    """`release_diff` as a function from a technique id to why its parent is
    not the same in both releases: the first of CHANGE_CLASSES that applies to
    it or to one of its sub-techniques.  new_technique: the parent was not
    active before; new_subtechnique: it is active in both and a sub-technique
    is new; status_changed: it or a sub-technique was revoked or deprecated;
    content_changed: it or a sub-technique has another name, description or
    tactics, or more procedures."""
    new: set[str] = set()
    gone: set[str] = set()
    changed: set[str] = set()
    for r in diff.values():
        new |= set(r["new_active"])
        gone |= set(r["no_longer_active"])
        changed |= {*r["renamed"], *r["description_changed"], *r["tactics_changed"], *r["more_procedures"]}
    with_new_sub = {parent(i) for i in new if "." in i}
    with_gone = {parent(i) for i in gone}
    with_change = {parent(i) for i in changed}

    def classify(tid: str) -> str:
        t = parent(tid)
        if t in new:
            return "new_technique"
        if t in with_new_sub and t not in gone:
            return "new_subtechnique"
        if t in with_gone:
            return "status_changed"
        if t in with_change:
            return "content_changed"
        return "unchanged"
    return classify
