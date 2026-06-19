#!/usr/bin/env python3
"""
Build all data indexes used by the cti-to-stix NLP pipeline.

Generates three files under pipeline/data/:

  mitre_index.json        (~430 KB)
    Compact lookup table of all ATT&CK techniques + tactics across Enterprise,
    Mobile, ICS, and CAPEC.  Used by stage3c_mitre.py for TTP normalization
    and by the React frontend for inline ATT&CK search.

  gazetteer.json          (~194 KB)
    Dictionary of 1,700+ known malware families, offensive tools, and APT group
    names (including all canonical names and aliases) extracted from the MITRE
    STIX bundles.  Used by stage2b_gazetteer.py for dictionary NER.

  mitre_embeddings.npy    (~2.3 MB)
  mitre_embeddings_meta.json
    Pre-computed sentence-transformer embeddings for all MITRE technique
    descriptions.  Used by stage2c_ttp_semantic.py for semantic TTP detection.

Usage:
    # Auto-discover bundle files in the default locations
    python scripts/build_indexes.py

    # Specify bundle paths explicitly
    python scripts/build_indexes.py \\
        --enterprise  /path/to/enterprise-attack.json \\
        --mobile      /path/to/mobile-attack.json \\
        --ics         /path/to/ics-attack.json \\
        --capec       /path/to/stix-capec.json

    # Rebuild only specific indexes
    python scripts/build_indexes.py --only mitre
    python scripts/build_indexes.py --only gazetteer
    python scripts/build_indexes.py --only embeddings

Prerequisites:
    pip install sentence-transformers numpy

The MITRE ATT&CK bundle files are NOT included in this repository.
Download them from:
    https://github.com/mitre/cti
or place them in ~/Downloads/ — the script will auto-detect them there.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_REPO_ROOT   = Path(__file__).parent.parent
_DATA_DIR    = _REPO_ROOT / "pipeline" / "data"

_INDEX_PATH     = _DATA_DIR / "mitre_index.json"
_GAZ_PATH       = _DATA_DIR / "gazetteer.json"
_EMB_PATH       = _DATA_DIR / "mitre_embeddings.npy"
_META_PATH      = _DATA_DIR / "mitre_embeddings_meta.json"
_MANIFEST_PATH  = _DATA_DIR / "mitre_embeddings_manifest.json"

# Default bundle locations to search (in priority order)
_DEFAULT_SEARCH_DIRS = [
    _REPO_ROOT / "data",
    Path.home() / "Downloads",
    Path.home() / "Documents",
    Path("/tmp"),
]

_BUNDLE_NAMES = {
    "enterprise": ["enterprise-attack.json"],
    "mobile":     ["mobile-attack.json"],
    "ics":        ["ics-attack.json"],
    "capec":      ["stix-capec.json", "capec.json"],
}


def _find_bundle(key: str) -> Path | None:
    for search_dir in _DEFAULT_SEARCH_DIRS:
        for name in _BUNDLE_NAMES[key]:
            p = search_dir / name
            if p.exists():
                return p
    return None


# ---------------------------------------------------------------------------
# MITRE index builder
# ---------------------------------------------------------------------------

def _load_bundle(path: Path) -> list[dict]:
    """Load a STIX bundle and return its objects list."""
    print(f"  Loading {path.name} ({path.stat().st_size / 1e6:.1f} MB)…", flush=True)
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("objects", [])


def _domain_from_path(path: Path) -> str:
    name = path.stem.lower()
    if "enterprise" in name:
        return "enterprise-attack"
    if "mobile" in name:
        return "mobile-attack"
    if "ics" in name:
        return "ics-attack"
    if "capec" in name:
        return "capec"
    return "unknown"


def build_mitre_index(bundles: dict[str, Path | None]) -> None:
    """Build pipeline/data/mitre_index.json from MITRE STIX bundles."""
    print("\n[1/3] Building mitre_index.json…")

    techniques: list[dict] = []
    tactics: list[dict] = []
    seen_ids: set[str] = set()

    for key, path in bundles.items():
        if path is None:
            print(f"  WARN  {key} bundle not found — skipping")
            continue

        domain = _domain_from_path(path)
        objects = _load_bundle(path)

        # Tactics
        for obj in objects:
            if obj.get("type") == "x-mitre-tactic":
                mid = None
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") in ("mitre-attack", "mitre-mobile-attack",
                                                   "mitre-ics-attack"):
                        mid = ref.get("external_id")
                        break
                if not mid or mid in seen_ids:
                    continue
                seen_ids.add(mid)
                tactics.append({
                    "id":        mid,
                    "name":      obj.get("name", ""),
                    "domain":    domain,
                    "shortname": obj.get("x_mitre_shortname", ""),
                })

        # Techniques (attack-pattern)
        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("x_mitre_deprecated") or obj.get("revoked"):
                continue

            mid = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") in ("mitre-attack", "mitre-mobile-attack",
                                               "mitre-ics-attack", "capec"):
                    mid = ref.get("external_id")
                    break
            if not mid or mid in seen_ids:
                continue
            seen_ids.add(mid)

            # Tactic phase names
            tactic_phases = [
                phase.get("phase_name", "")
                for phase in obj.get("kill_chain_phases", [])
            ]

            is_sub = bool(obj.get("x_mitre_is_subtechnique", False))
            parent_id: str | None = None
            if is_sub and "." in mid:
                parent_id = mid.rsplit(".", 1)[0]

            # Use full description for embeddings; truncate for compact index
            full_desc = obj.get("description", "")
            short_desc = full_desc[:300] if full_desc else ""

            techniques.append({
                "id":              mid,
                "name":            obj.get("name", ""),
                "domain":          domain,
                "tactics":         tactic_phases,
                "is_subtechnique": is_sub,
                "parent_id":       parent_id,
                "description":     short_desc,
                "shortname":       obj.get("name", "").lower().replace(" ", "-"),
            })

    # Sort for determinism
    techniques.sort(key=lambda x: x["id"])
    tactics.sort(key=lambda x: x["id"])

    index = {"techniques": techniques, "tactics": tactics}
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    _INDEX_PATH.write_text(json.dumps(index, ensure_ascii=False, separators=(",", ":")),
                           encoding="utf-8")

    size_kb = _INDEX_PATH.stat().st_size / 1024
    print(f"  DONE  {len(techniques)} techniques + {len(tactics)} tactics "
          f"→ {_INDEX_PATH.name} ({size_kb:.0f} KB)")


# ---------------------------------------------------------------------------
# Gazetteer builder
# ---------------------------------------------------------------------------

def build_gazetteer(bundles: dict[str, Path | None]) -> None:
    """Build pipeline/data/gazetteer.json from MITRE STIX bundles."""
    print("\n[2/3] Building gazetteer.json…")

    entries: list[dict] = []
    seen_canonicals: set[str] = set()  # "etype::canonical_lower::name_lower" dedup keys

    type_map = {
        "intrusion-set":  "threat_actor",
        "malware":        "malware",
        "tool":           "tool",
    }

    for key, path in bundles.items():
        if path is None:
            continue
        if key == "capec":
            continue   # CAPEC has attack patterns, not named groups/malware

        domain = _domain_from_path(path)
        objects = _load_bundle(path)

        for obj in objects:
            obj_type = obj.get("type", "")
            etype = type_map.get(obj_type)
            if not etype:
                continue
            if obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue

            canonical_name: str = obj.get("name", "").strip()
            if not canonical_name:
                continue

            # Get MITRE ID from external references
            mitre_id: str | None = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") in ("mitre-attack", "mitre-mobile-attack",
                                               "mitre-ics-attack"):
                    mitre_id = ref.get("external_id")
                    break

            canonical_lower = canonical_name.lower()

            # Build alias list (canonical + all known aliases)
            aliases: list[str] = obj.get("aliases", []) or obj.get("x_mitre_aliases", [])
            all_names: list[str] = [canonical_name] + [
                a for a in aliases if a and a.strip() and a.strip() != canonical_name
            ]

            for name in all_names:
                name = name.strip()
                if not name or len(name) < 4:
                    continue

                entry = {
                    "name":        name.lower(),    # match key (lowercase)
                    "canonical":   canonical_name,
                    "entity_type": etype,
                    "mitre_id":    mitre_id,
                    "domain":      domain,
                }

                # Avoid exact-duplicate entries (same canonical already added)
                entry_key = f"{etype}::{canonical_lower}::{name.lower()}"
                if entry_key in seen_canonicals:
                    continue
                seen_canonicals.add(entry_key)

                entries.append(entry)

    # Sort longest-first so longer names match before shorter overlapping names
    entries.sort(key=lambda e: len(e["name"]), reverse=True)

    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    _GAZ_PATH.write_text(json.dumps(entries, ensure_ascii=False, indent=2),
                         encoding="utf-8")

    size_kb = _GAZ_PATH.stat().st_size / 1024
    n_unique = len({e["canonical"].lower() for e in entries})
    print(f"  DONE  {len(entries)} name variants ({n_unique} unique entities) "
          f"→ {_GAZ_PATH.name} ({size_kb:.0f} KB)")


# ---------------------------------------------------------------------------
# Embedding builder
# ---------------------------------------------------------------------------

def build_embeddings(bundles: dict[str, Path | None]) -> None:
    """
    Build mitre_embeddings.npy + mitre_embeddings_meta.json + manifest.

    The embedding model is read from the TTP_EMBEDDING_MODEL environment variable
    (or .env file).  Defaults to all-MiniLM-L6-v2 for backward compatibility.

    Recommended upgrade (ADR-004 P1-A — CTiKG paper):
      TTP_EMBEDDING_MODEL=ehsanaghaei/SecureBERT-Plus
      → security-domain BERT, +8-12% TTP F1 on cybersecurity text
    """
    import os

    from dotenv import load_dotenv
    load_dotenv()

    model_id = os.getenv("TTP_EMBEDDING_MODEL", "all-MiniLM-L6-v2")
    print(f"\n[3/3] Building mitre_embeddings.npy  (model: {model_id})…")

    # Require sentence-transformers + numpy
    try:
        import numpy as np
        from sentence_transformers import SentenceTransformer
    except ImportError as e:
        print(f"  SKIP  Missing dependency: {e}")
        print("        Install with:  pip install sentence-transformers numpy")
        print("        If using the project venv, run:")
        print("          source .venv/bin/activate")
        print("          pip install sentence-transformers numpy")
        print("          python scripts/build_indexes.py --only embeddings")
        return

    # Load mitre_index.json (must already exist — built in step 1)
    if not _INDEX_PATH.exists():
        print("  SKIP  mitre_index.json not found — build the MITRE index first.")
        return

    index = json.loads(_INDEX_PATH.read_text(encoding="utf-8"))
    techniques: list[dict] = index.get("techniques", [])

    if not techniques:
        print("  SKIP  No techniques found in mitre_index.json.")
        return

    # Prepare texts to embed: "Name. Description" or just "Name" if no description
    texts: list[str] = []
    meta: list[dict] = []

    for t in techniques:
        desc  = (t.get("description") or "").strip()
        name  = t["name"]
        text  = f"{name}. {desc}" if desc else name
        texts.append(text)
        meta.append({
            "id":              t["id"],
            "name":            name,
            "domain":          t.get("domain", ""),
            "tactics":         t.get("tactics", []),
            "is_subtechnique": t.get("is_subtechnique", False),
        })

    print(f"  Loading model '{model_id}'…")
    try:
        model = SentenceTransformer(model_id)
    except Exception as e:
        print(f"  ERROR  Could not load model '{model_id}': {e}")
        if model_id != "all-MiniLM-L6-v2":
            print("  INFO   Retrying with fallback: all-MiniLM-L6-v2")
            try:
                model = SentenceTransformer("all-MiniLM-L6-v2")
                model_id = "all-MiniLM-L6-v2"
            except Exception as e2:
                print(f"  SKIP  Fallback also failed: {e2}")
                return
        else:
            return

    print(f"  Embedding {len(texts)} technique descriptions…")
    embeddings = model.encode(
        texts,
        batch_size=64,
        show_progress_bar=True,
        convert_to_numpy=True,
    )

    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    np.save(str(_EMB_PATH), embeddings)
    _META_PATH.write_text(json.dumps(meta, ensure_ascii=False, separators=(",", ":")),
                          encoding="utf-8")

    # Write manifest — records which model built this cache so stage2c can detect
    # stale caches when TTP_EMBEDDING_MODEL changes (ADR-004 P1-A)
    dims = int(embeddings.shape[1])
    manifest = {"model": model_id, "dims": dims, "num_techniques": len(texts)}
    _MANIFEST_PATH.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    size_mb = _EMB_PATH.stat().st_size / 1e6
    print(f"  DONE  shape={embeddings.shape}  dims={dims}")
    print(f"        {_EMB_PATH.name}       ({size_mb:.1f} MB)")
    print(f"        {_META_PATH.name}  ({_META_PATH.stat().st_size / 1024:.0f} KB)")
    print(f"        {_MANIFEST_PATH.name}  (model={model_id})")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--enterprise", type=Path, help="Path to enterprise-attack.json")
    parser.add_argument("--mobile",     type=Path, help="Path to mobile-attack.json")
    parser.add_argument("--ics",        type=Path, help="Path to ics-attack.json")
    parser.add_argument("--capec",      type=Path, help="Path to stix-capec.json")
    parser.add_argument(
        "--only", choices=["mitre", "gazetteer", "embeddings"],
        help="Rebuild only the specified index",
    )
    args = parser.parse_args()

    # Resolve bundle paths
    bundles: dict[str, Path | None] = {
        "enterprise": args.enterprise or _find_bundle("enterprise"),
        "mobile":     args.mobile     or _find_bundle("mobile"),
        "ics":        args.ics        or _find_bundle("ics"),
        "capec":      args.capec      or _find_bundle("capec"),
    }

    print("cti-to-stix — Index Builder")
    print("=" * 42)
    for key, path in bundles.items():
        status = str(path) if path else "NOT FOUND"
        print(f"  {key:12s}: {status}")
    print()

    if not any(bundles.values()):
        print("ERROR: No MITRE bundle files found.")
        print()
        print("Download them from:  https://github.com/mitre/cti")
        print("Then place them in one of:")
        for d in _DEFAULT_SEARCH_DIRS:
            print(f"  {d}")
        print()
        print("Or pass paths explicitly:")
        print("  python scripts/build_indexes.py --enterprise /path/to/enterprise-attack.json")
        sys.exit(1)

    _DATA_DIR.mkdir(parents=True, exist_ok=True)

    only = args.only
    if only is None or only == "mitre":
        build_mitre_index(bundles)
    if only is None or only == "gazetteer":
        build_gazetteer(bundles)
    if only is None or only == "embeddings":
        build_embeddings(bundles)

    print()
    print("Done.  Index files written to:", _DATA_DIR)


if __name__ == "__main__":
    main()
