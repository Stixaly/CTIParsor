"""Stage 2 stays linear in the size of the report (audit B 8.1.1).

`iocextract.extract_ipv4s` was called on the whole text and is quadratic:
45 KB of prose with a 2,000-address appendix took 39 s, 5,000 addresses about
four minutes — a botnet or proxy-network report, or a hostile paste, could
hold a worker for an hour.  The call was redundant (`_IPV4_PATTERN` runs on the
same refanged text) and is gone; this pins the budget so it cannot come back.
"""
from __future__ import annotations

import time

from models.schemas import EntityType
from pipeline.stage2_extraction import extract_entities


def _report_with_ip_appendix(n_ips: int) -> str:
    prose = "The intrusion set staged a loader, then moved laterally across the estate. " * 600   # ~45 KB
    ips = "\n".join(f"{10 + i % 200}.{i % 255}.{(i * 7) % 255}.{1 + i % 250}" for i in range(n_ips))
    return prose + "\n\nAppendix A - Network indicators\n" + ips


def test_stage2_is_linear_on_an_ip_appendix():
    text = _report_with_ip_appendix(5000)
    assert len(text) > 100_000
    t0 = time.perf_counter()
    entities = extract_entities(text)
    elapsed = time.perf_counter() - t0
    assert elapsed < 2.0, f"Stage 2 took {elapsed:.1f}s on {len(text) // 1024} KB with 5,000 IPs"
    ipv4 = {e.value for e in entities if e.entity_type == EntityType.IPV4}
    assert len(ipv4) >= 4900, len(ipv4)


def test_defanged_ipv4_recall_is_unchanged_without_iocextract():
    """The forms the removed call used to refang are the regexes' job."""
    text = ("Beacons to 185[.]220[.]101[.]45, 45(.)33(.)32(.)156 and 91 . 219 . 237 . 229; "
            "also 10[dot]0[dot]0[dot]5 and hxxp://198.51.100[.]7/x")
    ipv4 = {e.value for e in extract_entities(text) if e.entity_type == EntityType.IPV4}
    assert {"185.220.101.45", "45.33.32.156", "10.0.0.5", "198.51.100.7"} <= ipv4
