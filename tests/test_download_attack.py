"""scripts/download_attack.py --release: the three bundles of one attack-stix-data
release, each held to the sha256 GitHub publishes for it (ADR-0087).

urllib is replaced by a fake: no test reaches the network.
"""
from __future__ import annotations

import hashlib
import io
import json
import sys
import urllib.error

import pytest

from scripts import download_attack as da

DOWNLOADS = "https://github.com/mitre-attack/attack-stix-data/releases/download"
API = "https://api.github.com/repos/mitre-attack/attack-stix-data/releases/tags"
BODIES = {name: f"{name} bundle ".encode() * 200 for name in da._BUNDLES}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def metadata(version: str = "20.0", bodies: dict[str, bytes] | None = None) -> dict:
    """The API's answer for a release whose assets are `bodies`."""
    bodies = BODIES if bodies is None else bodies
    return {
        "tag_name": f"v{version}", "name": f"ATT&CK version {version}",
        "published_at": "2026-10-13T18:00:00Z",
        "html_url": f"https://github.com/mitre-attack/attack-stix-data/releases/tag/v{version}",
        "assets": [{"name": name, "size": len(body), "digest": f"sha256:{sha(body)}",
                    "browser_download_url": f"{DOWNLOADS}/v{version}/{name}"}
                   for name, body in bodies.items()],
    }


class Response(io.BytesIO):
    """What urlopen returns: a context manager with read([n])."""


class Network:
    """Stands in for urllib.request.urlopen: the API answer, then one body per URL."""

    def __init__(self, meta: dict, bodies: dict[str, bytes] | None = None, version: str = "20.0"):
        self.meta = meta
        self.version = version
        self.bodies = BODIES if bodies is None else bodies
        self.requests: list = []
        self.timeouts: list = []

    def __call__(self, req, timeout=None):
        self.requests.append(req)
        self.timeouts.append(timeout)
        if req.full_url == f"{API}/v{self.version}":
            return Response(json.dumps(self.meta).encode())
        for name, body in self.bodies.items():
            if req.full_url == f"{DOWNLOADS}/v{self.version}/{name}":
                return Response(body)
        raise urllib.error.URLError(f"unexpected request {req.full_url}")

    @property
    def urls(self) -> list[str]:
        return [r.full_url for r in self.requests]


@pytest.fixture
def net(monkeypatch, tmp_path):
    """The release 20.0 as GitHub publishes it, and a repository with no manifest."""
    network = Network(metadata())
    monkeypatch.setattr(da.urllib.request, "urlopen", network)
    monkeypatch.setattr(da, "_TRACKS_DIR", tmp_path / "tracks")
    monkeypatch.setattr(da, "_DEFAULT_MANIFEST", tmp_path / "default" / "attack_manifest.json")
    return network


def refused(version: str, out) -> None:
    with pytest.raises(SystemExit) as exc:
        da.download_release(version, out)
    assert exc.value.code == 1


def write_manifest(path, **manifest) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest), encoding="utf-8")


def test_the_bundles_and_release_json_are_written(net, tmp_path):
    out = tmp_path / "stix" / "v20.0"
    da.download_release("20.0", out)

    for name, body in BODIES.items():
        assert (out / name).read_bytes() == body
    assert sorted(p.name for p in out.iterdir()) == sorted([*BODIES, "release.json"])   # no .tmp
    release = json.loads((out / "release.json").read_text(encoding="utf-8"))
    assert list(release) == ["repository", "tag", "name", "published_at", "html_url", "fetched_at", "assets"]
    assert release["repository"] == "mitre-attack/attack-stix-data"
    assert release["tag"] == "v20.0"
    assert release["name"] == "ATT&CK version 20.0"
    assert release["published_at"] == "2026-10-13T18:00:00Z"
    assert release["html_url"].endswith("/releases/tag/v20.0")
    assert release["fetched_at"]
    assert release["assets"] == [{"name": name, "size": len(body), "digest": f"sha256:{sha(body)}",
                                  "url": f"{DOWNLOADS}/v20.0/{name}"}
                                 for name, body in BODIES.items()]


def test_the_requests_say_who_asks_and_do_not_wait_forever(net, tmp_path):
    da.download_release("20.0", tmp_path / "out")

    assert net.urls == [f"{API}/v20.0", *(f"{DOWNLOADS}/v20.0/{n}" for n in BODIES)]
    assert all(r.get_header("User-agent") for r in net.requests)
    assert net.requests[0].get_header("Accept") == "application/vnd.github+json"
    assert all(t for t in net.timeouts)


def test_the_default_out_is_data_attack_stix_vx_y(net, tmp_path, monkeypatch):
    monkeypatch.setattr(da, "_REPO_ROOT", tmp_path / "repo")
    da.download_release("20.0")

    assert (tmp_path / "repo" / "data" / "attack-stix" / "v20.0" / "enterprise-attack.json").is_file()


def test_a_different_digest_is_refused_and_nothing_is_left(net, tmp_path):
    net.bodies = {**BODIES, "mobile-attack.json": b"not the published bytes"}
    out = tmp_path / "stix" / "v20.0"

    refused("20.0", out)

    assert not (tmp_path / "stix").exists()      # not the verified enterprise bundle, no .tmp, no directory


def test_a_refusal_leaves_a_directory_that_was_already_there_as_it_was(net, tmp_path):
    net.bodies = {**BODIES, "ics-attack.json": b"not the published bytes"}
    out = tmp_path / "stix"
    out.mkdir()
    (out / "notes.txt").write_text("mine", encoding="utf-8")

    refused("20.0", out)

    assert [p.name for p in out.iterdir()] == ["notes.txt"]


def test_a_file_already_there_at_the_right_sha_is_not_fetched(net, tmp_path):
    out = tmp_path / "stix"
    out.mkdir()
    for name in ("enterprise-attack.json", "mobile-attack.json"):
        (out / name).write_bytes(BODIES[name])

    da.download_release("20.0", out)

    assert net.urls == [f"{API}/v20.0", f"{DOWNLOADS}/v20.0/ics-attack.json"]
    assert (out / "ics-attack.json").read_bytes() == BODIES["ics-attack.json"]


def test_all_three_present_means_only_the_metadata_is_read(net, tmp_path):
    out = tmp_path / "stix"
    out.mkdir()
    for name, body in BODIES.items():
        (out / name).write_bytes(body)

    da.download_release("20.0", out)

    assert net.urls == [f"{API}/v20.0"]
    assert (out / "release.json").is_file()


def test_a_file_with_other_content_is_replaced(net, tmp_path):
    out = tmp_path / "stix"
    out.mkdir()
    (out / "mobile-attack.json").write_bytes(b"an older download")

    da.download_release("20.0", out)

    assert (out / "mobile-attack.json").read_bytes() == BODIES["mobile-attack.json"]


@pytest.mark.parametrize("url", [
    "https://evil.example/mitre-attack/attack-stix-data/releases/download/v20.0/mobile-attack.json",
    "http://github.com/mitre-attack/attack-stix-data/releases/download/v20.0/mobile-attack.json",
    f"{DOWNLOADS}/v19.2/mobile-attack.json",                       # another release's asset
    f"{DOWNLOADS}/v20.0/../../../../other/repo/raw/mobile-attack.json",
    f"{DOWNLOADS}/v20.0/ics-attack.json",                          # another asset's file
])
def test_a_url_outside_the_release_is_refused(net, tmp_path, url):
    for asset in net.meta["assets"]:
        if asset["name"] == "mobile-attack.json":
            asset["browser_download_url"] = url

    refused("20.0", tmp_path / "stix")

    assert net.urls == [f"{API}/v20.0"]                            # nothing was downloaded
    assert not (tmp_path / "stix").exists()


@pytest.mark.parametrize("version", ["", "20", "20.0.1", "v20.0", "20.x", "../20.0", "20.0/..", "20.0\n",
                                     "\u0662\u0660.\u0660", "\uff12\uff10.\uff10"])   # Arabic-Indic, fullwidth
def test_a_release_that_is_not_x_dot_y_is_refused(net, tmp_path, version):
    refused(version, tmp_path / "stix")

    assert net.requests == []


@pytest.mark.parametrize("change", ["no asset", "no digest", "empty digest", "other algorithm",
                                    "short digest", "uppercase digest"])
def test_an_asset_without_a_sha256_digest_is_refused(net, tmp_path, change):
    assets = net.meta["assets"]
    ics = next(a for a in assets if a["name"] == "ics-attack.json")
    if change == "no asset":
        assets.remove(ics)
    elif change == "no digest":
        del ics["digest"]
    elif change == "empty digest":
        ics["digest"] = ""
    elif change == "other algorithm":
        ics["digest"] = "sha1:" + "ab" * 20
    elif change == "short digest":
        ics["digest"] = "sha256:abcd"
    else:
        ics["digest"] = "sha256:" + sha(BODIES["ics-attack.json"]).upper()

    refused("20.0", tmp_path / "stix")

    assert net.urls == [f"{API}/v20.0"]
    assert not (tmp_path / "stix").exists()


def test_metadata_for_another_tag_are_refused(net, tmp_path):
    net.meta["tag_name"] = "v19.2"

    refused("20.0", tmp_path / "stix")

    assert net.urls == [f"{API}/v20.0"]


def test_an_unreachable_api_is_refused(monkeypatch, tmp_path, capsys):
    def down(req, timeout=None):
        raise urllib.error.URLError("no route")

    monkeypatch.setattr(da.urllib.request, "urlopen", down)
    monkeypatch.setattr(da, "_TRACKS_DIR", tmp_path / "tracks")
    monkeypatch.setattr(da, "_DEFAULT_MANIFEST", tmp_path / "none.json")

    refused("20.0", tmp_path / "stix")

    assert "no route" in capsys.readouterr().out
    assert not (tmp_path / "stix").exists()


def test_a_track_manifest_that_disagrees_refuses_the_release_before_any_download(net, tmp_path):
    write_manifest(tmp_path / "tracks" / "20.0" / "attack_manifest.json", release="20.0", sources=[
        {"domain": "enterprise-attack", "sha256": sha(BODIES["enterprise-attack.json"])},
        {"domain": "mobile-attack", "sha256": "0" * 64},
        {"domain": "ics-attack", "sha256": sha(BODIES["ics-attack.json"])},
    ])

    refused("20.0", tmp_path / "stix")

    assert net.urls == [f"{API}/v20.0"]
    assert not (tmp_path / "stix").exists()


def test_a_track_manifest_that_agrees_lets_the_release_through(net, tmp_path):
    write_manifest(tmp_path / "tracks" / "20.0" / "attack_manifest.json", release="20.0", sources=[
        {"domain": name.removesuffix(".json"), "sha256": sha(body)} for name, body in BODIES.items()])

    da.download_release("20.0", tmp_path / "stix")

    assert (tmp_path / "stix" / "release.json").is_file()


def test_the_default_tracks_release_is_checked_against_its_equivalent_assets(monkeypatch, tmp_path):
    bodies = {name: f"{name} of 19.2 ".encode() * 200 for name in da._BUNDLES}
    network = Network(metadata("19.2", bodies), bodies, version="19.2")
    monkeypatch.setattr(da.urllib.request, "urlopen", network)
    monkeypatch.setattr(da, "_TRACKS_DIR", tmp_path / "tracks")
    manifest = tmp_path / "default" / "attack_manifest.json"
    monkeypatch.setattr(da, "_DEFAULT_MANIFEST", manifest)
    sources: list[dict] = [
        {"domain": name.removesuffix(".json"), "file": None, "sha256": None,
         "equivalent_release_asset": {"sha256": sha(body)}} for name, body in bodies.items()]
    sources[1]["equivalent_release_asset"]["sha256"] = "f" * 64
    write_manifest(manifest, release="19.2", sources=sources)

    refused("19.2", tmp_path / "stix")

    assert network.urls == [f"{API}/v19.2"]

    sources[1]["equivalent_release_asset"]["sha256"] = sha(bodies["mobile-attack.json"])
    write_manifest(manifest, release="19.2", sources=sources)
    da.download_release("19.2", tmp_path / "stix")

    assert (tmp_path / "stix" / "mobile-attack.json").read_bytes() == bodies["mobile-attack.json"]


def test_the_default_tracks_manifest_says_nothing_about_another_release(net, tmp_path):
    manifest = tmp_path / "default" / "attack_manifest.json"
    write_manifest(manifest, release="19.2", sources=[
        {"domain": "enterprise-attack", "equivalent_release_asset": {"sha256": "0" * 64}}])

    da.download_release("20.0", tmp_path / "stix")

    assert (tmp_path / "stix" / "release.json").is_file()


def test_the_command_line_takes_release_and_out(net, tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["download_attack.py", "--release", "20.0", "--out", str(tmp_path / "o")])

    da.main()

    assert (tmp_path / "o" / "ics-attack.json").read_bytes() == BODIES["ics-attack.json"]


@pytest.mark.parametrize("argv", [["--release", "20.0", "--check"], ["--release", "20.0", "--force"],
                                  ["--out", "somewhere"]])
def test_options_that_make_no_sense_together_are_a_usage_error(net, monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["download_attack.py", *argv])

    with pytest.raises(SystemExit) as exc:
        da.main()

    assert exc.value.code == 2
    assert net.requests == []


def test_without_release_the_master_bundle_is_downloaded_and_the_default_track_named(
        monkeypatch, tmp_path, capsys):
    bundle = json.dumps({"objects": [{"type": "attack-pattern"}]}).encode()
    requested = []

    def urlopen(req, timeout=None):
        requested.append(req.full_url)
        return Response(bundle)

    monkeypatch.setattr(da.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(da, "_OUT", tmp_path / "data" / "enterprise-attack.json")
    default = tmp_path / "attack_manifest.json"
    write_manifest(default, release="19.2")
    monkeypatch.setattr(da, "_DEFAULT_MANIFEST", default)
    monkeypatch.setattr(sys, "argv", ["download_attack.py"])

    da.main()

    assert requested == [da._URL]
    assert (tmp_path / "data" / "enterprise-attack.json").read_bytes() == bundle
    assert sorted(p.name for p in (tmp_path / "data").iterdir()) == ["enterprise-attack.json"]
    out = capsys.readouterr().out
    assert "latest release of mitre/cti" in out
    assert "default track" in out and "which is 19.2" in out
    assert "--release 19.2" in out
    assert "20.0" not in out                       # whatever the latest release is, it is not written here


def test_the_note_names_the_default_track_the_manifest_gives(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(da.urllib.request, "urlopen", lambda req, timeout=None: Response(b'{"objects": []}'))
    monkeypatch.setattr(da, "_OUT", tmp_path / "data" / "enterprise-attack.json")
    default = tmp_path / "attack_manifest.json"
    write_manifest(default, release="21.3")
    monkeypatch.setattr(da, "_DEFAULT_MANIFEST", default)
    monkeypatch.setattr(sys, "argv", ["download_attack.py"])

    da.main()

    assert "which is 21.3" in capsys.readouterr().out


# ── The size GitHub publishes bounds the download ────────────────────────────

class Counting(io.BytesIO):
    """A response that counts the 1 MiB blocks it gave."""
    blocks = 0

    def read(self, n=-1):
        block = super().read(n)
        if len(block) == 1 << 20:
            Counting.blocks += 1
        return block


def _asset(net, name):
    return next(a for a in net.meta["assets"] if a["name"] == name)


def test_a_stream_that_goes_past_the_published_size_is_cut_off_and_nothing_is_left(
        net, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys.modules[__name__], "Response", Counting)
    Counting.blocks = 0
    net.bodies = {**BODIES, "mobile-attack.json": b"x" * (5 << 20)}         # 5 blocks of 1 MiB
    _asset(net, "mobile-attack.json")["size"] = 1 << 20

    refused("20.0", tmp_path / "stix")

    out = capsys.readouterr().out
    assert "mobile-attack.json: download failed" in out and "goes past the 1048576 bytes" in out
    assert Counting.blocks == 2                     # it stopped reading; the digest was not what refused it
    assert not (tmp_path / "stix").exists()


@pytest.mark.parametrize("delta", [-1, 1])
def test_a_download_of_another_size_than_published_is_refused_even_with_the_right_digest(
        net, tmp_path, capsys, delta):
    mobile = _asset(net, "mobile-attack.json")
    mobile["size"] += delta                          # the digest is still the body's

    refused("20.0", tmp_path / "stix")

    assert "mobile-attack.json: download failed" in capsys.readouterr().out
    assert not (tmp_path / "stix").exists()


@pytest.mark.parametrize("size", ["missing", None, "1000", 0, -5, True, 1.5])
def test_an_asset_without_a_usable_size_is_refused(net, tmp_path, size):
    ics = _asset(net, "ics-attack.json")
    if size == "missing":
        del ics["size"]
    else:
        ics["size"] = size

    refused("20.0", tmp_path / "stix")

    assert net.urls == [f"{API}/v20.0"]              # nothing was downloaded
    assert not (tmp_path / "stix").exists()
