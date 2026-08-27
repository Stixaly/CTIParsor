from pipeline.detection.observables import observables_from_entities


def test_real_domains_survive_the_guard():
    rows = [
        {"value": "azurenetfiles.net", "entity_type": "domain"},
        {"value": "frontforce.org", "entity_type": "domain"},
        {"value": "example.co.uk", "entity_type": "domain"},
        {"value": "evil.ru", "entity_type": "domain"},
    ]
    obs = observables_from_entities(rows)
    domains = {o.value for o in obs if o.obs_class == "domain"}
    assert "azurenetfiles.net" in domains
    assert "frontforce.org" in domains
    assert "example.co.uk" in domains
    assert "evil.ru" in domains


def test_filename_shaped_domains_are_dropped():
    rows = [
        {"value": "agent.ashx", "entity_type": "domain"},
        {"value": "exfil.tar.zst", "entity_type": "domain"},
        {"value": "psemhub.war", "entity_type": "domain"},
        {"value": "kernel32.dll", "entity_type": "domain"},
    ]
    obs = observables_from_entities(rows)
    domains = {o.value for o in obs if o.obs_class == "domain"}
    assert "agent.ashx" not in domains
    assert "exfil.tar.zst" not in domains
    assert "psemhub.war" not in domains
    assert "kernel32.dll" not in domains


def test_two_letter_executable_suffix_is_not_a_cctld():
    rows = [
        {"value": "meshctrl.js", "entity_type": "domain"},
    ]
    obs = observables_from_entities(rows)
    domains = {o.value for o in obs if o.obs_class == "domain"}
    assert "meshctrl.js" not in domains


def test_url_keeps_its_url_observable_when_host_is_rejected():
    rows = [
        {"value": "http://psemhub.war/payload", "entity_type": "url"},
    ]
    obs = observables_from_entities(rows)
    urls = {o.value for o in obs if o.obs_class == "url"}
    domains = {o.value for o in obs if o.obs_class == "domain"}
    assert "http://psemhub.war/payload" in urls
    assert "psemhub.war" not in domains


def test_url_with_real_host_yields_both():
    rows = [
        {"value": "https://azurenetfiles.net/a/b", "entity_type": "url"},
    ]
    obs = observables_from_entities(rows)
    urls = {o.value for o in obs if o.obs_class == "url"}
    domains = {o.value for o in obs if o.obs_class == "domain"}
    assert "https://azurenetfiles.net/a/b" in urls
    assert "azurenetfiles.net" in domains


def test_email_host_passes_through_the_same_guard():
    rows = [
        {"value": "ops@azurenetfiles.net", "entity_type": "email"},
        {"value": "drop@psemhub.war", "entity_type": "email"},
    ]
    obs = observables_from_entities(rows)
    domains = {o.value for o in obs if o.obs_class == "domain"}
    assert "azurenetfiles.net" in domains
    assert "psemhub.war" not in domains


def test_non_domain_classes_are_untouched():
    rows = [
        {"value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "entity_type": "sha256"},
        {"value": "8.8.8.8", "entity_type": "ipv4"},
        {"value": "/opt/tools/meshagent64.exe", "entity_type": "file"},
        {"value": "meshagent", "entity_type": "tool"},
    ]
    obs = observables_from_entities(rows)
    hashes = {o.value for o in obs if o.obs_class == "hash"}
    ips = {o.value for o in obs if o.obs_class == "ip"}
    files = {o.value for o in obs if o.obs_class == "file"}
    images = {o.value for o in obs if o.obs_class == "image"}
    names = {o.value for o in obs if o.obs_class == "name"}

    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in hashes
    assert "8.8.8.8" in ips
    assert "/opt/tools/meshagent64.exe" in files
    assert "meshagent64.exe" in files
    assert "/opt/tools/meshagent64.exe" in images
    assert "meshagent64.exe" in images
    assert "meshagent" in names


def test_dot_com_domain_typed_as_a_file_is_not_an_executable():
    """`.com` is a DOS executable suffix AND the commonest TLD.

    The extractor emitted `pastebin.com` as both a `domain` and a `file` entity
    on a real report; the file branch then added an `image` observable because
    the value "ends in .com", turning one domain into three artifacts.

    ADR-0031 finishes the job: a hostname typed as a file is not a file at all,
    so it is re-routed to `domain` rather than kept as one. Measured on UNC6671,
    where all 78 `file` entities were the campaign's phishing domains and 77
    duplicated a `domain` observable already present — 175 observables became 97.
    Re-routing rather than dropping is what keeps the value when the extractor
    typed it ONLY as a file, as here.
    """
    obs = observables_from_entities([
        {"value": "pastebin.com", "entity_type": "file"},
    ])
    classes = {o.obs_class for o in obs}
    assert classes == {"domain"}


def test_real_dos_com_executable_still_yields_an_image():
    """The carve-out keys on hostname shape, not on the suffix alone."""
    obs = observables_from_entities([
        {"value": "c:/tools/scan.com", "entity_type": "file"},
    ])
    assert "image" in {o.obs_class for o in obs}


def test_exe_files_are_unaffected_by_the_carve_out():
    obs = observables_from_entities([
        {"value": "nircmd.exe", "entity_type": "file"},
    ])
    classes = {o.obs_class for o in obs}
    assert classes == {"file", "image"}
