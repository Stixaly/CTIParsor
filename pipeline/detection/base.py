"""RuleCorpusAdapter — the pluggable seam for detection-rule formats (ADR-0006)."""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable
from pathlib import Path

from models.detection import DetectionRule


class RuleCorpusAdapter(ABC):
    """Parses a corpus of detection rules into normalized `DetectionRule` records.

    One adapter per *format*, not per corpus — many Sigma repos share one
    `SigmaAdapter`.  Adapters are pure: they read local files and emit records;
    they never touch the network (fetching/cloning is a separate sync step so
    credentials stay out of CTIParsor — see ADR-0006 Option A).
    """

    #: short format key matching the `adapter:` field in detection_corpora.yaml
    format: str = ""

    @abstractmethod
    def parse(
        self,
        root: Path,
        *,
        corpus: str,
        license: str = "unknown",
        on_file_error: Callable[[Path, str], None] | None = None,
    ) -> Iterable[DetectionRule]:
        """Yield a `DetectionRule` for each rule found under `root`.

        Args:
            root:    local directory of an already-fetched corpus clone.
            corpus:  registry name, used to namespace rule IDs.
            license: SPDX-ish license from the registry entry, stamped on each rule.
            on_file_error: called with (path, message) for each file that could not
                be read or only partly read (#373). Adapters keep no state for it:
                the same instance serves every corpus. None ignores such files.
        """
        raise NotImplementedError
