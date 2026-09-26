"""Request options for a vLLM server, shared by Stage 3 and Stage 1f.

One place because both stages talk to the same server and must agree: a
thinking switch honoured by the text calls but not the figure reads would be
half a setting.
"""
from __future__ import annotations

from pipeline.env_flags import env_bool


def vllm_extra_body() -> dict:
    """Extra body fields sent with every vLLM chat request.

    Qwen3-family chat templates think before answering unless told not to, and
    vLLM passes `chat_template_kwargs` straight to the template. Measured on
    Qwen3.8-27B served by vLLM 0.27: with thinking on, the Stage 3 extraction
    prompt spent the whole 8192-token output budget reasoning (31k characters)
    and returned no content after 431 s, so the chunk was skipped. With it off,
    the same chunk went through extraction, Stage 3d and Stage 3f in 106 s.

    Off unless VLLM_ENABLE_THINKING is true. A template that does not read
    `enable_thinking` ignores it, so the default is harmless for other models.
    """
    return {
        "chat_template_kwargs": {
            "enable_thinking": env_bool("VLLM_ENABLE_THINKING", default=False),
        },
    }
