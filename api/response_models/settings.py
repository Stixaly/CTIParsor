"""Response models of `api/routes/settings.py`.

A corpus is a registry entry (committed YAML merged with the local overlay) plus
`rules` and `adapter_available`, which the route adds.  The optional fields are
absent from entries that do not set them: the routes that return corpora use
`response_model_exclude_unset=True`, so an absent key stays absent.
"""
from __future__ import annotations

from pydantic import Field, JsonValue

from api.response_models import Response


class CorpusOut(Response):
    name: str = Field(description="The corpus name: the {name} segment of its routes.")
    adapter: str = Field(description="The format the corpus is parsed as (sigma, suricata, yara).")
    enabled: bool
    rules: int = Field(description="Rules ingested for this corpus, 0 until it is synced or rebuilt.")
    adapter_available: bool = Field(description="False when no parser for the format is compiled in.")
    git: str | None = Field(default=None, description="The https remote the corpus is cloned from.")
    tarball: str | None = Field(default=None, description="The URL the corpus archive is downloaded from.")
    path: str | None = Field(default=None, description="The local directory, under corpora/.")
    subdir: str | None = Field(default=None, description="The directory inside the corpus that is parsed.")
    license: str | None = None
    priority: JsonValue = Field(
        default=None,
        description="Dedup priority as the registry wrote it; a non-int falls back to a default.",
    )
    private: bool | None = None


class CorporaOut(Response):
    corpora: list[CorpusOut]


class FormatOut(Response):
    format: str
    available: bool = Field(description="True when a parser for the format is compiled in.")
    corpora: int = Field(description="Configured corpora in this format.")
    rules: int = Field(description="Rules ingested in this format.")


class FormatsOut(Response):
    formats: list[FormatOut]


class CorporaResult(Response):
    """Result of a change to the overlay: the corpora after it."""

    ok: bool
    corpora: list[CorpusOut]


class CorpusCreated(Response):
    ok: bool
    warning: str | None = Field(description="Set when the adapter has no parser in this build.")
    corpora: list[CorpusOut]


class FileError(Response):
    path: str = Field(description="The file, relative to the corpus root.")
    error: str


class SyncOut(Response):
    ok: bool
    detail: str = Field(description="What the fetch did, as the sync step reported it.")
    rules: int = Field(description="Rules written for this corpus by the rebuild.")
    file_errors: list[FileError]
    corpora: list[CorpusOut]


class DedupSummary(Response):
    total: int
    clusters: int
    canonical: int
    duplicates: int
    provenance_edges: int
    merged_by_provenance: int


class RuleTextSummary(Response):
    rows: int
    empty_bodies: int = Field(description="Rules skipped for an empty body.")


class CorpusCount(Response):
    corpus: str
    license: str | None
    rules: int
    canonical: int = Field(description="Rules kept after dedup; the rest are copies of a canonical rule.")


class RebuildOut(Response):
    written: dict[str, int] = Field(description="Rules written per corpus.")
    skipped: list[str] = Field(description="Corpora whose clone was missing or not parsed.")
    skip_reasons: dict[str, str] = Field(description="Why each skipped corpus was skipped.")
    removed: list[str] = Field(description="Corpora no longer enabled whose rules were cleared.")
    file_errors: dict[str, list[FileError]]
    total: int
    dedup: DedupSummary
    rule_text: RuleTextSummary
    counts: list[CorpusCount]
