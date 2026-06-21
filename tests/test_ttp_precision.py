"""
Tests for the TTP-precision enhancements (ADR precision §2-3):

  Phase A — Stage 2c model-aware thresholds + margin gate; Stage 3c stops
            medium-confidence semantic matches from overriding the LLM.
  Phase B — Stage 3f TTP self-verification drops unsupported technique claims.
  Phase C — Stage 3c subsumes a parent technique when a sub-technique is present.

All LLM calls are mocked; no API key or heavy model is required.
"""
from __future__ import annotations

import pytest

from pipeline.stage3_llm import LLMEnrichmentResult, TTPExtracted


# ── small RawEntity-like stub for semantic matches ──────────────────────────────

class _SemEnt:
    """Minimal stand-in for a Stage 2c RawEntity (value/mitre_id/confidence/context)."""
    def __init__(self, value, mitre_id, confidence, context=""):
        self.value = value
        self.mitre_id = mitre_id
        self.confidence = confidence
        self.context = context


# ── Phase A — Stage 2c threshold resolution ─────────────────────────────────────

class TestThresholdResolution:
    def test_per_model_default_minilm(self, monkeypatch):
        import pipeline.stage2c_ttp_semantic as s2c
        monkeypatch.setattr(s2c, "_TTP_EMBEDDING_MODEL", "all-MiniLM-L6-v2")
        monkeypatch.delenv("TTP_HIGH_THRESHOLD", raising=False)
        monkeypatch.delenv("TTP_MEDIUM_THRESHOLD", raising=False)
        monkeypatch.setattr(s2c, "_MANIFEST_PATH", s2c._MANIFEST_PATH.with_name("__absent__.json"))
        high, medium = s2c._thresholds()
        assert (high, medium) == (0.62, 0.48)

    def test_securebert_has_higher_cutpoints(self, monkeypatch):
        import pipeline.stage2c_ttp_semantic as s2c
        monkeypatch.setattr(s2c, "_TTP_EMBEDDING_MODEL", "ehsanaghaei/SecureBERT-Plus")
        monkeypatch.delenv("TTP_HIGH_THRESHOLD", raising=False)
        monkeypatch.delenv("TTP_MEDIUM_THRESHOLD", raising=False)
        monkeypatch.setattr(s2c, "_MANIFEST_PATH", s2c._MANIFEST_PATH.with_name("__absent__.json"))
        high, _ = s2c._thresholds()
        assert high > 0.62

    def test_env_override_wins(self, monkeypatch):
        import pipeline.stage2c_ttp_semantic as s2c
        monkeypatch.setattr(s2c, "_TTP_EMBEDDING_MODEL", "all-MiniLM-L6-v2")
        monkeypatch.setattr(s2c, "_MANIFEST_PATH", s2c._MANIFEST_PATH.with_name("__absent__.json"))
        monkeypatch.setenv("TTP_HIGH_THRESHOLD", "0.80")
        monkeypatch.setenv("TTP_MEDIUM_THRESHOLD", "0.55")
        high, medium = s2c._thresholds()
        assert (high, medium) == (0.80, 0.55)

    def test_high_confidence_threshold_exposed(self):
        from pipeline.stage2c_ttp_semantic import high_confidence_threshold
        assert isinstance(high_confidence_threshold(), float)


# ── Phase A — Stage 3c: medium semantic must NOT override the LLM ───────────────

class TestSemanticDoesNotOverrideLLM:
    def test_high_confidence_semantic_wins(self):
        from pipeline.stage3c_mitre import normalize_ttps
        # High-confidence semantic match for T1059.001 should keep its canonical
        # name even though the LLM proposed a different (paraphrased) name.
        sem = [_SemEnt("PowerShell", "T1059.001", 0.90, context="ran powershell")]
        llm = [TTPExtracted(technique_name="PS scripting", mitre_id="T1059.001",
                            description="a much longer description from the llm")]
        out = normalize_ttps(llm, semantic_entities=sem)
        entry = next(t for t in out if t.mitre_id == "T1059.001")
        assert entry.technique_name == "PowerShell"          # semantic canonical name
        assert "longer description" in entry.description      # but richer LLM desc

    def test_medium_confidence_semantic_does_not_override_llm_name(self):
        from pipeline.stage3c_mitre import normalize_ttps
        # A medium-confidence semantic match must not replace the LLM's entry.
        sem = [_SemEnt("Command and Scripting Interpreter", "T1059", 0.50,
                       context="weakly matched sentence")]
        llm = [TTPExtracted(technique_name="PowerShell", mitre_id="T1059.001",
                            description="actor ran powershell to execute commands")]
        out = normalize_ttps(llm, semantic_entities=sem)
        ids = {t.mitre_id for t in out}
        # The sub-technique from the LLM survives; the medium parent is subsumed.
        assert "T1059.001" in ids
        assert "T1059" not in ids

    def test_medium_semantic_kept_when_llm_silent(self):
        from pipeline.stage3c_mitre import normalize_ttps
        sem = [_SemEnt("LSASS Memory", "T1003.001", 0.50, context="dumped lsass")]
        out = normalize_ttps([], semantic_entities=sem)
        assert any(t.mitre_id == "T1003.001" for t in out)


# ── Phase C — parent/sub-technique subsumption ──────────────────────────────────

class TestParentSubsumption:
    def test_parent_dropped_when_subtechnique_present(self):
        from pipeline.stage3c_mitre import _subsume_parent_techniques
        ttps = [
            TTPExtracted(technique_name="Command and Scripting Interpreter", mitre_id="T1059"),
            TTPExtracted(technique_name="PowerShell", mitre_id="T1059.001"),
        ]
        out = _subsume_parent_techniques(ttps)
        ids = {t.mitre_id for t in out}
        assert ids == {"T1059.001"}

    def test_parent_kept_when_no_subtechnique(self):
        from pipeline.stage3c_mitre import _subsume_parent_techniques
        ttps = [TTPExtracted(technique_name="Command and Scripting Interpreter", mitre_id="T1059")]
        out = _subsume_parent_techniques(ttps)
        assert {t.mitre_id for t in out} == {"T1059"}

    def test_unrelated_techniques_untouched(self):
        from pipeline.stage3c_mitre import _subsume_parent_techniques
        ttps = [
            TTPExtracted(technique_name="PowerShell", mitre_id="T1059.001"),
            TTPExtracted(technique_name="Phishing", mitre_id="T1566"),
        ]
        out = _subsume_parent_techniques(ttps)
        assert {t.mitre_id for t in out} == {"T1059.001", "T1566"}


# ── Phase B — Stage 3f TTP verification ─────────────────────────────────────────

def _verifier(verdicts: dict[int, bool]):
    """Build a fake llm_fn returning a verification array for the given verdicts."""
    import json

    def _fn(system: str, user: str) -> str:
        arr = [
            {"n": n, "verified": v, "quote": ("found it" if v else None)}
            for n, v in verdicts.items()
        ]
        return json.dumps(arr)
    return _fn


class TestTTPVerification:
    def test_disabled_by_default_returns_unchanged(self, monkeypatch):
        import pipeline.stage3f_ttp_verify as v
        monkeypatch.setattr(v, "_VERIFY_ENABLED", False)
        result = LLMEnrichmentResult(ttps=[TTPExtracted(technique_name="X", mitre_id="T1001")])
        out = v.verify_ttps("text", result, _verifier({1: False}))
        assert len(out.ttps) == 1

    def test_unsupported_ttp_removed(self, monkeypatch):
        import pipeline.stage3f_ttp_verify as v
        monkeypatch.setattr(v, "_VERIFY_ENABLED", True)
        result = LLMEnrichmentResult(ttps=[
            TTPExtracted(technique_name="Real", mitre_id="T1059.001"),
            TTPExtracted(technique_name="Hallucinated", mitre_id="T1486"),
        ])
        out = v.verify_ttps("text", result, _verifier({1: True, 2: False}))
        ids = {t.mitre_id for t in out.ttps}
        assert ids == {"T1059.001"}

    def test_corroborated_ttp_skipped_not_verified(self, monkeypatch):
        import pipeline.stage3f_ttp_verify as v
        monkeypatch.setattr(v, "_VERIFY_ENABLED", True)
        # T1059.001 is corroborated → trusted even though the verifier would
        # mark claim 1 unverified (the verifier only sees the single-signal one).
        result = LLMEnrichmentResult(ttps=[
            TTPExtracted(technique_name="PowerShell", mitre_id="T1059.001"),
            TTPExtracted(technique_name="Guess", mitre_id="T1486"),
        ])
        out = v.verify_ttps(
            "text", result, _verifier({1: False}),
            corroborated_ids={"T1059.001"},
        )
        ids = {t.mitre_id for t in out.ttps}
        # corroborated kept; the single-signal T1486 was marked unverified → dropped
        assert "T1059.001" in ids
        assert "T1486" not in ids

    def test_unparseable_response_keeps_all(self, monkeypatch):
        import pipeline.stage3f_ttp_verify as v
        monkeypatch.setattr(v, "_VERIFY_ENABLED", True)
        result = LLMEnrichmentResult(ttps=[TTPExtracted(technique_name="X", mitre_id="T1001")])
        out = v.verify_ttps("text", result, lambda s, u: "not json")
        assert len(out.ttps) == 1
