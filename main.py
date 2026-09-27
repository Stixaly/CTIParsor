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
import json
import sys
from pathlib import Path

from dotenv import load_dotenv

# Before any project import.  api.logging_config reads LOG_LEVEL, LOG_FORMAT,
# LOG_FILE, MAX_LOG_SIZE and LOG_BACKUP_COUNT at import time, and the only
# load_dotenv() on this path used to be the one inside stage3_llm, which runs
# later: those five were ignored by this CLI when set in .env.  A variable
# already set in the environment still wins (override=False).
load_dotenv(Path(__file__).resolve().parent / ".env")

from pipeline.orchestrator import (  # noqa: E402
    STAGE_LABELS,
    Document,
    Hooks,
    RunOptions,
    RunResult,
    StageRequired,
    run_document,
)
from pipeline.stage5_validation import print_bundle_summary  # noqa: E402

SUPPORTED_EXTENSIONS = {".pdf", ".docx", ".html", ".htm", ".txt", ".md"}


class _ConsoleHooks(Hooks):
    """The CLI's side of a run: print each stage as it completes, and apply
    the same relationship policy the API worker would (ADR-0059)."""

    def __init__(self, policy_source: str = "db"):
        self.policy_source = policy_source

    def policy(self) -> dict | None:
        src = self.policy_source
        if src == "none":
            print("      Politique de relations : aucune (--policy none)")
            return None
        if src != "db":
            policy = json.loads(Path(src).read_text(encoding="utf-8"))
            print(f"      Politique de relations : {src}")
            return policy
        from api.db import load_relationship_policy
        try:
            policy = load_relationship_policy()
        except Exception as exc:
            print(f"      Politique de relations : aucune — base injoignable ({type(exc).__name__}); "
                  "le worker, lui, appliquerait la politique enregistrée")
            return None
        print("      Politique de relations : " +
              ("celle enregistrée dans la base" if policy else "aucune enregistrée"))
        return policy

    def progress(self, event: str, data: dict) -> None:
        if event != "stage":
            return
        stage = data.get("stage")
        if stage == 1:
            print(f"[1/5] Ingestion : {data['chars']} caractères → {data['chunks']} chunks")
        elif stage == 2:
            print(f"[2/5] Extraction : {data['entities']} entités "
                  f"(gazetteer {data['gazetteer']}, TTP sémantiques {data['semantic_ttps']}, "
                  f"CyNER {data['cyner']}, GLiNER {data['gliner']}, alias {data['alias_list']})")
        elif stage == 3:
            print(f"\r[3/5] LLM : chunk {data['chunk']}/{data['total']}", end="", flush=True)
            if data["chunk"] == data["total"]:
                print()
        elif stage == 4:
            cov = data["ioc_coverage"]
            print(f"[4/5] STIX 2.1 : {data['objects']} objets — IoC avec Indicator : "
                  f"{cov['with_indicator']}/{cov['total']}")
        elif stage == 5:
            print(f"[5/5] Validation : {'OK' if data['valid'] else 'ERREURS'}")


def _print_stages(result: RunResult) -> None:
    print("\n  Étapes :")
    for o in result.stages:
        detail = o.reason or ", ".join(f"{k}={v}" for k, v in o.counts.items())
        print(f"    {o.stage:<5}{STAGE_LABELS.get(o.stage, ''):<27}{o.status:<9}{detail}")


def run_pipeline(input_file: str, output_file: str, options: RunOptions | None = None,
                 policy_source: str = "db") -> bool:
    """One report through the same pipeline the API worker runs (ADR-0059)."""
    print(f"\n{'='*50}")
    print(f"  Rapport : {Path(input_file).name}")
    print(f"  Sortie  : {output_file}")
    print(f"{'='*50}\n")

    document = Document(file_path=input_file, original_filename=Path(input_file).name,
                        output_path=output_file)
    try:
        result = run_document(document, options or RunOptions.from_env(), _ConsoleHooks(policy_source))
    except (FileNotFoundError, ValueError, StageRequired) as exc:
        print(f"      [ERREUR] {exc}")
        return False

    type_counts: dict[str, int] = {}
    for e in result.entities:
        type_counts[e.entity_type.value] = type_counts.get(e.entity_type.value, 0) + 1
    for t, c in sorted(type_counts.items()):
        print(f"      {t:<20} {c}")
    llm = result.llm_result
    if llm is not None and result.ran("3"):
        print(f"      LLM — Threat actors : {len(llm.threat_actors)} — Malwares : "
              f"{len(llm.malware_families)} — TTPs : {len(llm.ttps)} — "
              f"Relations : {len(llm.relationships)}")
    cov = result.ioc_coverage or {}
    for m in cov.get("missing_indicator", [])[:10]:
        print(f"        [!] no indicator: [{m['type']}] {m['value']}")
    if result.bundle is not None:
        print_bundle_summary(result.bundle)
    _print_stages(result)

    from pipeline.stage5_validation import _schemas_installed
    valid = bool(result.valid)
    if valid and not _schemas_installed():
        status = "OK (validation skipped — schemas missing)"
    elif valid:
        status = "OK"
    else:
        status = "VALIDATION ERRORS"
    print(f"  [{status}] {Path(input_file).name}")

    return valid


def run_directory(input_dir: str, output_dir: str, options: RunOptions | None = None,
                  policy_source: str = "db") -> None:
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
        success = run_pipeline(str(file), str(output_file), options, policy_source)
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

    parser.add_argument(
        "--disable-stage", action="append", default=[], metavar="ID",
        help="Désactiver une étape (répétable ou séparé par des virgules), p. ex. 2d,2e. "
             "Identifiants : " + ", ".join(STAGE_LABELS),
    )
    parser.add_argument(
        "--require-stage", action="append", default=[], metavar="ID",
        help="Échouer si cette étape ne s'exécute pas (p. ex. 3 pour exiger le LLM)",
    )
    parser.add_argument(
        "--policy", default="db", metavar="db|none|FICHIER",
        help="Politique de relations : celle enregistrée dans la base (défaut, comme le worker), "
             "aucune, ou un fichier JSON",
    )
    parser.add_argument(
        "--no-llm", action="store_true",
        help="Ne pas appeler le LLM (équivaut à --disable-stage 3)",
    )

    args = parser.parse_args()

    def _ids(values: list[str]) -> set[str]:
        return {v.strip() for raw in values for v in raw.split(",") if v.strip()}

    disabled = _ids(args.disable_stage) | ({"3"} if args.no_llm else set())
    try:
        options = RunOptions.from_env(disabled=disabled, required=_ids(args.require_stage))
    except ValueError as exc:
        parser.error(str(exc))

    if args.input_dir:
        run_directory(args.input_dir, args.output_dir, options, args.policy)
    else:
        success = run_pipeline(args.file, args.output, options, args.policy)
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
