"""
CTI Report → STIX 2.1 Pipeline

Usage — single file:
    python main.py input/rapport_apt29.pdf

Usage — all files in input/:
    python main.py --input-dir input/

Usage — custom output:
    python main.py input/rapport.pdf --output output/apt29_bundle.json
"""
import argparse
import hashlib
import sys
from pathlib import Path

from models.schemas import RawEntity
from pipeline.stage1_ingestion import chunk_text, ingest
from pipeline.stage2_extraction import extract_entities, refang
from pipeline.stage3_llm import enrich_all_chunks
from pipeline.stage4_stix_mapping import build_stix_bundle, verify_ioc_coverage
from pipeline.stage5_validation import print_bundle_summary, validate_and_export

SUPPORTED_EXTENSIONS = {".pdf", ".docx", ".html", ".htm", ".txt", ".md"}


def run_pipeline(input_file: str, output_file: str) -> bool:
    report_name = Path(input_file).stem

    print(f"\n{'='*50}")
    print(f"  Rapport : {Path(input_file).name}")
    print(f"  Sortie  : {output_file}")
    print(f"{'='*50}\n")

    # Stage 1 — Ingestion
    print("[1/5] Ingestion du document...")
    try:
        raw_text = ingest(input_file)
    except (FileNotFoundError, ValueError) as e:
        print(f"      [ERREUR] {e}")
        return False

    # Refang so entity values match between extraction and annotation
    text = refang(raw_text)
    chunks = chunk_text(text, max_chars=3000)
    print(f"      {len(text)} caractères extraits → {len(chunks)} chunks")

    # Stage 2 — Extraction déterministe
    print("\n[2/5] Extraction déterministe (IoCs, NER)...")
    entities_per_chunk = [extract_entities(chunk) for chunk in chunks]
    # Dedup across chunks (the 400-char chunk overlap re-extracts boundary IoCs)
    # by (value, type), keeping the highest-confidence occurrence — mirrors the
    # API worker so counts and the bundle match between the CLI and the server.
    _best: dict[tuple, RawEntity] = {}
    for chunk_ents in entities_per_chunk:
        for e in chunk_ents:
            key = (e.value.lower(), e.entity_type)
            if key not in _best or e.confidence > _best[key].confidence:
                _best[key] = e
    all_entities = list(_best.values())

    type_counts: dict[str, int] = {}
    for e in all_entities:
        type_counts[e.entity_type.value] = type_counts.get(e.entity_type.value, 0) + 1
    for t, c in sorted(type_counts.items()):
        print(f"      {t:<20} {c}")
    print(f"      Total : {len(all_entities)} entités")

    # Stage 3 — Enrichissement LLM
    print("\n[3/5] Enrichissement LLM (TTPs, relations, contexte)...")
    llm_result = enrich_all_chunks(chunks, entities_per_chunk)
    print(f"      Threat actors  : {len(llm_result.threat_actors)}")
    print(f"      Malwares       : {len(llm_result.malware_families)}")
    print(f"      TTPs           : {len(llm_result.ttps)}")
    print(f"      Relations      : {len(llm_result.relationships)}")

    # Stage 4 — Mapping STIX
    print("\n[4/5] Mapping STIX 2.1...")
    # Compute SHA-256 of the source file for the artifact SCO
    try:
        h = hashlib.sha256()
        with open(input_file, "rb") as fh:
            for block in iter(lambda: fh.read(65536), b""):
                h.update(block)
        source_hash: str | None = h.hexdigest()
    except OSError:
        source_hash = None

    bundle = build_stix_bundle(
        all_entities, llm_result, report_name,
        report_text=text,
        original_filename=Path(input_file).name,
        source_hash=source_hash,
    )

    # Verify every regex/defang-extracted IoC became a STIX observable + Indicator
    cov = verify_ioc_coverage(all_entities, bundle)
    if cov["ok"]:
        print(f"      IoC coverage : {cov['total_iocs']}/{cov['total_iocs']} observables → SCO + Indicator")
    else:
        print(f"      IoC coverage : {cov['with_indicator']}/{cov['total_iocs']} IoCs have an Indicator "
              f"({len(cov['missing_indicator'])} missing)")
        for m in cov["missing_indicator"][:10]:
            print(f"        [!] no indicator: [{m['type']}] {m['value']}")

    # Stage 5 — Validation & export
    print("\n[5/5] Validation & export...")
    valid = validate_and_export(bundle, output_file)
    print_bundle_summary(bundle)

    from pipeline.stage5_validation import _schemas_installed
    if valid and not _schemas_installed():
        status = "OK (validation skipped — schemas missing)"
    elif valid:
        status = "OK"
    else:
        status = "VALIDATION ERRORS"
    print(f"  [{status}] {Path(input_file).name}")

    return valid


def run_directory(input_dir: str, output_dir: str) -> None:
    """Process all supported files found in input_dir."""
    input_path = Path(input_dir)
    output_path = Path(output_dir)

    if not input_path.exists():
        print(f"[ERREUR] Dossier introuvable : {input_dir}")
        sys.exit(1)

    files = sorted([
        f for f in input_path.iterdir()
        if f.is_file() and f.suffix.lower() in SUPPORTED_EXTENSIONS
    ])

    if not files:
        print(f"[INFO] Aucun fichier supporté trouvé dans {input_dir}")
        print(f"       Formats acceptés : {', '.join(SUPPORTED_EXTENSIONS)}")
        sys.exit(0)

    print(f"\n{len(files)} fichier(s) trouvé(s) dans {input_dir}/")
    for f in files:
        print(f"  - {f.name}")

    output_path.mkdir(parents=True, exist_ok=True)

    results: list[tuple[str, bool]] = []

    for file in files:
        output_file = output_path / f"{file.stem}_bundle.json"
        success = run_pipeline(str(file), str(output_file))
        results.append((file.name, success))

    # Final summary
    print(f"\n{'='*50}")
    print(f"  RÉSUMÉ — {len(files)} rapport(s) traité(s)")
    print(f"{'='*50}")
    for name, ok in results:
        icon = "✔" if ok else "✖"
        print(f"  {icon}  {name}")
    print()

    failed = [name for name, ok in results if not ok]
    if failed:
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convertit des rapports CTI en bundles STIX 2.1",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  # Traiter un seul fichier
  python main.py input/rapport_apt29.pdf

  # Traiter tous les fichiers du dossier input/
  python main.py --input-dir input/

  # Spécifier le dossier de sortie
  python main.py --input-dir input/ --output-dir output/
        """,
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "file",
        nargs="?",
        help="Chemin vers un rapport CTI (pdf, docx, html, txt)",
    )
    group.add_argument(
        "--input-dir",
        metavar="DIR",
        help="Traiter tous les fichiers supportés d'un dossier (défaut : input/)",
    )

    parser.add_argument(
        "--output",
        default="output/bundle.json",
        help="Fichier de sortie pour un traitement unitaire (défaut : output/bundle.json)",
    )
    parser.add_argument(
        "--output-dir",
        default="output",
        help="Dossier de sortie pour le traitement par lot (défaut : output/)",
    )

    args = parser.parse_args()

    if args.input_dir:
        run_directory(args.input_dir, args.output_dir)
    else:
        success = run_pipeline(args.file, args.output)
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
