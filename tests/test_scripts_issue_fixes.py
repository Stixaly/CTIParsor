"""scripts/build_warninglists.py (#272) and scripts/lock_pypi_hashes.py (#273): a value
that reaches a URL is checked or quoted first. No test reaches the network: urlopen
is replaced, and a refused value must stop before it is ever called."""
from __future__ import annotations

import io
import sys
import urllib.request

import pytest

from scripts import build_warninglists as bw
from scripts import lock_pypi_hashes as lock


@pytest.fixture
def no_network(monkeypatch):
    """Every urlopen call is a test failure; the calls are recorded anyway."""
    calls: list = []

    def fail(url, *args, **kwargs):
        calls.append(url)
        raise AssertionError(f"network reached: {url}")

    monkeypatch.setattr(urllib.request, "urlopen", fail)
    return calls


def test_the_default_commit_passes_the_check_and_reaches_the_url_unchanged(monkeypatch):
    class Stop(Exception):
        pass

    urls: list = []

    def stop_at_once(url, *args, **kwargs):
        urls.append(url)
        raise Stop

    monkeypatch.setattr(urllib.request, "urlopen", stop_at_once)
    monkeypatch.setattr(sys, "argv", ["build_warninglists.py"])

    with pytest.raises(Stop):
        bw.main()
    assert urls == [f"https://raw.githubusercontent.com/MISP/misp-warninglists/{bw.COMMIT}"
                    "/lists/security-provider-blogpost/list.json"]


@pytest.mark.parametrize("value", ["af01b1d", "0123456789abcdef", "a" * 40])
def test_a_lower_case_hex_sha_of_7_to_40_digits_is_accepted(value):
    assert bw._commit(value) == value


@pytest.mark.parametrize("value", [
    "main",                                         # a branch name would move under the vendored data
    "af01b1",                                       # 6 digits
    "a" * 41,
    "AF01B1D67AE78B2064C2823EBFD9078D6E7828C9",     # upper case
    "af01b1d\n",                                    # `$` would have let a trailing newline through
    "af01b1d/../../../other",                       # a path, not a SHA
    "af01b1d?x=1",
    "https://example.org/x",
    "",
])
def test_a_value_that_is_not_a_sha_stops_before_any_request(value, monkeypatch, capsys, no_network):
    monkeypatch.setattr(sys, "argv", ["build_warninglists.py", "--commit", value])

    with pytest.raises(SystemExit) as exc:
        bw.main()

    assert exc.value.code == 2                      # argparse's usage error
    assert "not a commit SHA" in capsys.readouterr().err
    assert no_network == []


def test_pypi_url_keeps_name_and_version_as_single_path_segments(monkeypatch):
    urls: list = []

    def fake_urlopen(url, timeout=None):
        urls.append(url)
        return io.BytesIO(b'{"urls": [{"digests": {"sha256": "ab"}}]}')

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    assert lock.pypi_hashes("markupsafe", "3.0.2") == ["ab"]
    assert lock.pypi_hashes("pkg/../x", "1.0/../../y?z#w") == ["ab"]
    assert urls == [
        "https://pypi.org/pypi/markupsafe/3.0.2/json",
        "https://pypi.org/pypi/pkg%2F..%2Fx/1.0%2F..%2F..%2Fy%3Fz%23w/json",
    ]
