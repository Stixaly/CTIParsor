"""
Tests for the TTP-precision enhancements (ADR precision §2-3):

  Phase A — Stage 2c model-aware thresholds + margin gate; Stage 3c stops
            medium-confidence semantic matches from overriding the LLM.
  Phase B — Stage 3f TTP self-verification drops unsupported technique claims.
  Phase C — Stage 3c subsumes a parent technique when a sub-technique is present.

All LLM calls are mocked; no API key or heavy model is required.
"""
from __future__ import annotations

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


# ── Advisory/table-caption content gate ─────────────────────────────────────
# Stage 2c's keyword gate lets mitigation-advice sentences ("Enforce phishing-
# resistant MFA...") and PDF table captions ("Table 1: Indicators of
# compromise...") through, because they legitimately contain TTP vocabulary --
# they then get matched with high confidence to a technique despite never
# describing observed adversary behaviour.  These are real cases produced by
# the pipeline on real reports (Breeze Comet, UNC6671), not hypothetical.

class TestAdvisoryContentGate:
    def test_positive_mandate_mfa(self, monkeypatch):
        import pipeline.stage2c_ttp_semantic as s2c
        monkeypatch.delenv("TTP_ADVISORY_GATE", raising=False)
        sentence = (
            "Mandate phishing-resistant multifactor authentication (MFA) and "
            "lockout controls across all remote access services."
        )
        assert s2c._is_advisory_noise(sentence) is True, f"Failed positive case 1: {sentence}"

    def test_positive_block_egress(self, monkeypatch):
        import pipeline.stage2c_ttp_semantic as s2c
        monkeypatch.delenv("TTP_ADVISORY_GATE", raising=False)
        sentence = (
            "Block non-essential egress ports and protocols (e.g., outbound "
            "Internet Control Message Protocol)."
        )
        assert s2c._is_advisory_noise(sentence) is True, f"Failed positive case 2: {sentence}"

    def test_positive_enforce_mfa(self, monkeypatch):
        import pipeline.stage2c_ttp_semantic as s2c
        monkeypatch.delenv("TTP_ADVISORY_GATE", raising=False)
        sentence = (
            "Enforce Phishing-Resistant Multi-factor Authentication: Mandate "
            "phishing-resistant authentication platforms."
        )
        assert s2c._is_advisory_noise(sentence) is True, f"Failed positive case 3: {sentence}"

    def test_positive_utilize_token(self, monkeypatch):
        import pipeline.stage2c_ttp_semantic as s2c
        monkeypatch.delenv("TTP_ADVISORY_GATE", raising=False)
        sentence = (
            "Utilize token theft mitigations within authentication platforms "
            "such as IP session binding."
        )
        assert s2c._is_advisory_noise(sentence) is True, f"Failed positive case 4: {sentence}"

    def test_positive_deploy_endpoint(self, monkeypatch):
        import pipeline.stage2c_ttp_semantic as s2c
        monkeypatch.delenv("TTP_ADVISORY_GATE", raising=False)
        sentence = (
            "Deploy Endpoint and Browser Credential Guarding: Enable Google "
            "Workspace Password Alert to detect credential reuse."
        )
        assert s2c._is_advisory_noise(sentence) is True, f"Failed positive case 5: {sentence}"

    def test_positive_ad_restriction(self, monkeypatch):
        import pipeline.stage2c_ttp_semantic as s2c
        monkeypatch.delenv("TTP_ADVISORY_GATE", raising=False)
        sentence = (
            "Active Directory & Credential Hardening Restrict administrative "
            "utilities such as PsExec and WMI."
        )
        assert s2c._is_advisory_noise(sentence) is True, f"Failed positive case 6: {sentence}"

    def test_positive_table_caption_1(self, monkeypatch):
        import pipeline.stage2c_ttp_semantic as s2c
        monkeypatch.delenv("TTP_ADVISORY_GATE", raising=False)
        sentence = (
            "Table 1: Indicators of compromise Network Infrastructure and "
            "Exfiltration Observables IP Address."
        )
        assert s2c._is_advisory_noise(sentence) is True, f"Failed positive case 7: {sentence}"

    def test_positive_table_caption_2(self, monkeypatch):
        import pipeline.stage2c_ttp_semantic as s2c
        monkeypatch.delenv("TTP_ADVISORY_GATE", raising=False)
        sentence = (
            "AS19108 Optimum / Suddenlink (United States) Table 2: Network "
            "infrastructure and exfiltration observables."
        )
        assert s2c._is_advisory_noise(sentence) is True, f"Failed positive case 8: {sentence}"

    def test_positive_verb_starts_with_a_or_z(self, monkeypatch):
        # Regression: an earlier implementation stripped edge characters with
        # str.strip("^[a-zA-Z]|[a-zA-Z]$"), which treats its argument as a
        # character SET, not a regex -- it strips a single leading/trailing
        # 'a', 'A', 'z' or 'Z' literally.  "Adopt" -> "dopt" (lowercase-
        # starting), so the capitalisation check silently failed.  This
        # sentence only passes on a correct non-letter-stripping implementation.
        import pipeline.stage2c_ttp_semantic as s2c
        monkeypatch.delenv("TTP_ADVISORY_GATE", raising=False)
        sentence = (
            "Adopt a zero-trust architecture and avoid using shared "
            "administrator credentials across systems."
        )
        assert s2c._is_advisory_noise(sentence) is True, f"Failed 'Adopt'-prefix case: {sentence}"

    def test_positive_verb_with_trailing_punctuation(self, monkeypatch):
        # Regression: the same buggy strip() left trailing punctuation like
        # ":" attached ("Restrict:" != "restrict"), so a heading-style opener
        # was silently missed.
        import pipeline.stage2c_ttp_semantic as s2c
        monkeypatch.delenv("TTP_ADVISORY_GATE", raising=False)
        sentence = "Restrict: administrative utilities must not be exposed to the internet."
        assert s2c._is_advisory_noise(sentence) is True, f"Failed trailing-punctuation case: {sentence}"

    def test_negative_attacker_powershell(self, monkeypatch):
        import pipeline.stage2c_ttp_semantic as s2c
        monkeypatch.delenv("TTP_ADVISORY_GATE", raising=False)
        sentence = (
            "The attacker used PowerShell to download and execute a "
            "malicious payload on the compromised host."
        )
        assert s2c._is_advisory_noise(sentence) is False, f"Failed negative case 1: {sentence}"

    def test_negative_apt29_backdoor(self, monkeypatch):
        import pipeline.stage2c_ttp_semantic as s2c
        monkeypatch.delenv("TTP_ADVISORY_GATE", raising=False)
        sentence = "APT29 deployed a custom backdoor to maintain persistence on the network."
        assert s2c._is_advisory_noise(sentence) is False, f"Failed negative case 2: {sentence}"

    def test_negative_exfiltrate_creds(self, monkeypatch):
        import pipeline.stage2c_ttp_semantic as s2c
        monkeypatch.delenv("TTP_ADVISORY_GATE", raising=False)
        sentence = (
            "The malware exfiltrated stolen credentials to a remote command "
            "and control server over HTTPS."
        )
        assert s2c._is_advisory_noise(sentence) is False, f"Failed negative case 3: {sentence}"

    def test_negative_actor_enable_rdp(self, monkeypatch):
        import pipeline.stage2c_ttp_semantic as s2c
        monkeypatch.delenv("TTP_ADVISORY_GATE", raising=False)
        sentence = (
            "The actor was able to enable remote desktop access using "
            "stolen administrator credentials."
        )
        assert s2c._is_advisory_noise(sentence) is False, f"Failed negative case 4: {sentence}"

    def test_negative_lookup_table(self, monkeypatch):
        import pipeline.stage2c_ttp_semantic as s2c
        monkeypatch.delenv("TTP_ADVISORY_GATE", raising=False)
        sentence = (
            "The threat actor built a lookup table to store the decryption "
            "keys before encrypting the disk."
        )
        assert s2c._is_advisory_noise(sentence) is False, f"Failed negative case 5: {sentence}"

    def test_negative_empty_string(self, monkeypatch):
        import pipeline.stage2c_ttp_semantic as s2c
        monkeypatch.delenv("TTP_ADVISORY_GATE", raising=False)
        assert s2c._is_advisory_noise("") is False, "Failed negative case 6: empty string"

    def test_negative_none_input(self, monkeypatch):
        import pipeline.stage2c_ttp_semantic as s2c
        monkeypatch.delenv("TTP_ADVISORY_GATE", raising=False)
        assert s2c._is_advisory_noise(None) is False, "Failed negative case 7: None input"

    def test_advisory_gate_disabled_via_env(self, monkeypatch):
        import pipeline.stage2c_ttp_semantic as s2c
        monkeypatch.setenv("TTP_ADVISORY_GATE", "off")
        sentence = (
            "Mandate phishing-resistant multifactor authentication (MFA) and "
            "lockout controls across all remote access services."
        )
        assert s2c._is_advisory_noise(sentence) is False, "Gate disabled should let everything through"

    def test_select_candidates_excludes_advisory_sentence_with_keyword(self, monkeypatch):
        import pipeline.stage2c_ttp_semantic as s2c
        monkeypatch.delenv("TTP_ADVISORY_GATE", raising=False)
        adversary_sentence = (
            "The attacker used PowerShell to download and execute a "
            "malicious payload on the compromised host."
        )
        advisory_sentence = (
            "Enforce credential hardening and mandate multi-factor "
            "authentication for all privileged accounts."
        )
        text = adversary_sentence + " " + advisory_sentence
        result = s2c._select_candidates(text)
        assert adversary_sentence in result, "Adversary sentence should be present"
        assert advisory_sentence not in result, "Advisory sentence should be excluded"

    def test_sentence_gate_stats_matches_select_candidates(self, monkeypatch):
        import pipeline.stage2c_ttp_semantic as s2c
        monkeypatch.delenv("TTP_ADVISORY_GATE", raising=False)

        # Test 1: Concatenated text
        adversary_sentence = (
            "The attacker used PowerShell to download and execute a "
            "malicious payload on the compromised host."
        )
        advisory_sentence = (
            "Enforce credential hardening and mandate multi-factor "
            "authentication for all privileged accounts."
        )
        text1 = adversary_sentence + " " + advisory_sentence
        stats1 = s2c.sentence_gate_stats(text1)
        candidates1 = s2c._select_candidates(text1)
        assert stats1["scored"] == len(candidates1), (
            f"Stats mismatch for text1: {stats1['scored']} != {len(candidates1)}"
        )

        # Test 2: Plain text with no matches
        text2 = "This is a plain text with no TTP keywords or advisory content."
        stats2 = s2c.sentence_gate_stats(text2)
        candidates2 = s2c._select_candidates(text2)
        assert stats2["scored"] == len(candidates2), (
            f"Stats mismatch for text2: {stats2['scored']} != {len(candidates2)}"
        )
