"""
Stage Registry — loads all Stage-2 extractors declaratively.

Usage:
    from pipeline.registry import StageRegistry
    from models.config import PipelineConfig

    registry = StageRegistry(PipelineConfig())
    entities = registry.run_all(text)
    print("Active stages:", registry.active_stages)
"""
from __future__ import annotations

import importlib
import logging

from pipeline.base import BaseExtractionStage
from models.config import PipelineConfig
from models.schemas import RawEntity

logger = logging.getLogger(__name__)

# (module_path, class_name) in the order they should run
_STAGE_CANDIDATES: list[tuple[str, str]] = [
    ("pipeline.stage2_extraction",   "RegexExtractionStage"),
    ("pipeline.stage2b_gazetteer",   "GazetteerStage"),
    ("pipeline.stage2c_ttp_semantic","SemanticTTPStage"),
    ("pipeline.stage2d_cyner",       "CyNERStage"),
    ("pipeline.stage2e_gliner",      "GLiNERStage"),
]


class StageRegistry:
    """
    Loads extraction stages lazily and reports which ones are active.

    Stages that fail to import or whose model is not available are silently
    skipped with a WARNING — they do not crash the pipeline.
    """

    def __init__(self, config: PipelineConfig | None = None) -> None:
        self._config = config or PipelineConfig()
        self._stages: list[BaseExtractionStage] = []
        self._load_stages()

    def _load_stages(self) -> None:
        for module_path, class_name in _STAGE_CANDIDATES:
            try:
                mod = importlib.import_module(module_path)
                cls = getattr(mod, class_name)
                stage: BaseExtractionStage = cls(config=self._config)
                if stage.available():
                    self._stages.append(stage)
                    logger.info("Stage loaded: %s", stage.name)
                else:
                    logger.warning(
                        "Stage unavailable (model not loaded or disabled): %s", stage.name
                    )
            except ImportError as exc:
                logger.warning("Could not import stage %s: %s", class_name, exc)
            except AttributeError as exc:
                logger.warning("Class %s not found in %s: %s", class_name, module_path, exc)
            except Exception:
                logger.exception("Unexpected error loading stage %s", class_name)

    def run_all(self, text: str) -> list[RawEntity]:
        """
        Run all available extraction stages and return the merged entity list.

        Only ValueError / TypeError from individual stages are caught — these
        signal bad data, not bugs. Other exceptions propagate so bugs surface
        clearly in tests and logs.
        """
        all_entities: list[RawEntity] = []
        for stage in self._stages:
            try:
                new = stage.extract(text)
                all_entities = BaseExtractionStage.merge_into(all_entities, new)
            except (ValueError, TypeError) as exc:
                logger.error(
                    "Stage %s raised %s: %s — skipping",
                    stage.name, type(exc).__name__, exc,
                )
        return all_entities

    @property
    def active_stages(self) -> list[str]:
        return [s.name for s in self._stages]
