# ADR-0074: Report text reaches the model as delimited data, and the sanitiser deletes nothing

**Status:** Accepted
**Date:** 2026-10-03
**Deciders:** maintainer
**Supersedes:** the redaction rules of `_sanitize_text_for_prompt` (SECURITY.md §1 before this ADR)

## Context

Every LLM call of the pipeline embeds report text, which an attacker can
write. Until now the defence was `_sanitize_text_for_prompt`, applied to the
whole user message in `_call_llm`:

1. strip HTML/XML tags (BeautifulSoup);
2. replace four phrasings by `[REDACTED]`, among them
   `\b(ignore|forget|disregard)\b.*\b(previous|above|prior)\b`;
3. remove control characters, normalise whitespace, cap the length.

The October 2026 audit (B 8.2.3) reproduced what this costs and what it
misses, and a check on the Qwen3.8 vLLM server on 2026-10-03 added a third
finding:

- **It deletes intelligence.** "The loader is configured to ignore any host
  joined to a domain, and deletes files created prior to installation" — a
  description of execution guardrails (T1480) — came out as "The loader is
  configured to [REDACTED] to installation". `powershell -enc <base64blob>`
  lost its argument to the tag stripping.
  `<iframe src="https://…">`, which is an indicator in a skimming report,
  disappeared with its URL.
- **It stops nothing that matters.** The same instruction in French, with a
  synonym ("set aside the earlier guidance"), or with a zero-width space
  inside a keyword passes untouched.
- **It misses the strongest injection.** vLLM renders the chat template to
  text and tokenizes it whole, so a report containing `<|im_end|>` produces
  the real end-of-turn token (id 248046) and `<|im_start|>system` opens a new
  system turn (248045). `<think>`, `</think>`, `<tool_call>` and
  `<|endoftext|>` are single tokens too. BeautifulSoup does not treat `<|` as
  a tag, so none of these was touched. Ollama and LM Studio template the
  same way.

## Decision

1. **Spotlighting.** Every prompt that embeds report text — chunk extraction,
   the document-level relation pass, 3d, 3f verify, 3f select and 4c — goes
   through `llm_parse.fit_report`. The text sits between two marker lines,
   `<<<REPORT n>>>` and `<<<END REPORT n>>>`, and the system prompt gets one
   sentence (`SPOTLIGHT_RULE`) naming them and saying that what is between
   them is data, never instructions.
2. **The nonce is a hash of the text** (12 hex characters of SHA-256), not a
   random draw. The same text gives the same prompt, so a run at temperature
   0 stays reproducible and a response cache (B9) stays possible; a report
   cannot close its own block early without containing its own hash.
   `fit_report` cuts the text, never the closing marker or the question after
   it, like `fit_text`.
3. **The sanitiser deletes nothing a report says.** It keeps the control
   character removal, the whitespace normalisation and the length cap; it
   drops the tag stripping and the four redactions; it removes invisible
   characters (zero-width, direction marks, bidi embeddings, overrides and
   isolates, invisible operators, BOM); and it **defuses** chat-template
   markup by inserting a space after the first character (`<|im_end|>` →
   `< |im_end|>`, `<think>` → `< think>`, `[INST]` → `[ INST]`): still
   readable, no longer a token. Both changes are counted in `llm_stats`
   (`prompt_invisible_chars_removed`, `prompt_chat_markup_defused`), so a
   report that carries many of them shows in its stage report.
4. **The prompt fingerprints include `SPOTLIGHT_RULE`**, which is appended at
   call time and was therefore outside the hashed constants.

## Options rejected

- **A random nonce per call** (the audit's sketch). Equivalent protection, but
  two runs of the same report no longer send the same prompt: evaluation
  replicates stop being comparable at temperature 0.
- **Keep the redactions next to spotlighting.** They are the part that
  deletes intelligence, and they never covered a synonym or another language.
- **Strip every `<…>` tag, as before.** Deletes indicators and code; the
  dangerous strings are a short, known family per model, which defusing
  covers without removing anything.
- **Remove the chat markup instead of defusing it.** A report about LLM
  jailbreaks quotes these strings; the analyst should see them in the
  evidence the model returns.
- **Send the report as a separate message or a tool result.** Not supported
  the same way by all six providers; the markers work everywhere.

## Consequences

- Prompts change for every stage, so the prompt fingerprint changes
  (`114a2773…` on `d580e8c`). A comparison across the two prompts measures
  the prompt as well as the configuration: the ADR-0072 runs are compared on
  `d580e8c`, and the configuration they select needs one dev run with this
  prompt before the single test run.
- Names inside claims (3d, 3f, 4c) and entity lists stay outside the markers.
  They are short strings already checked against the text (Stage 3b); the
  invisible-character and markup rules still apply to them.
- A chunk whose prompt exceeds `LLM_MAX_PROMPT_LENGTH` now loses the end of
  the chunk, not the end of the answer format (the old code truncated the
  finished prompt).
- Tests: `tests/test_stage3.py` (`TestSanitizeKeepsIntelligence`,
  `TestSpotlighting`, `TestPromptVocabulary`), `tests/test_stage3_calls.py`.
