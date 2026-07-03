"""Regression tests for ioc-extractor.py."""


def test_refang_common_formats(ioc_extractor):
    refang = ioc_extractor.refang
    assert refang("hxxp://evil[.]com/x") == "http://evil.com/x"
    assert refang("hxxps://evil[dot]com") == "https://evil.com"
    assert refang("1[.]2[.]3[.]4") == "1.2.3.4"
    assert refang("user[@]evil[.]com") == "user@evil.com"


def test_defanged_indicators_are_extracted(ioc_extractor):
    result = ioc_extractor.extract(
        "C2 at hxxps://bad-domain[.]example/gate.php and 203[.]0[.]113[.]77"
    )
    ind = result["indicators"]
    assert "https://bad-domain.example/gate.php" in ind["urls"]
    assert "bad-domain.example" in ind["domains"]
    assert "203.0.113.77" in ind["ipv4"]


def test_private_and_reserved_ips_excluded(ioc_extractor):
    text = ("attacker at 198.51.100.23, internal hosts 192.168.1.10, 10.0.0.5, "
            "172.16.0.1, 127.0.0.1, 169.254.10.10, multicast 224.0.0.1")
    ipv4 = ioc_extractor.extract(text)["indicators"]["ipv4"]
    assert ipv4 == ["198.51.100.23"]


def test_denylisted_and_filename_domains_excluded(ioc_extractor):
    text = "see google.com and microsoft.com; dropped payload.exe and readme.txt; C2 evil.example"
    domains = ioc_extractor.extract(text)["indicators"]["domains"]
    assert "google.com" not in domains
    assert "microsoft.com" not in domains
    assert "payload.exe" not in domains
    assert "readme.txt" not in domains
    assert "evil.example" in domains


def test_hash_lengths_do_not_overlap(ioc_extractor):
    sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    ind = ioc_extractor.extract(f"payload hash {sha256}")["indicators"]
    assert ind["sha256"] == [sha256]
    assert ind["md5"] == []
    assert ind["sha1"] == []


def test_registry_and_email_extraction(ioc_extractor):
    text = ("persistence at HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater "
            "from billing@invoice-delivery.example")
    ind = ioc_extractor.extract(text)["indicators"]
    assert ind["registry_paths"] == [
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"
    ]
    assert ind["emails"] == ["billing@invoice-delivery.example"]


def test_registry_path_with_interior_space(ioc_extractor):
    text = "shell set at HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell on the host"
    ind = ioc_extractor.extract(text)["indicators"]
    assert ind["registry_paths"] == [
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell"
    ]


def test_sample_report_end_to_end(ioc_extractor, sample_report_text):
    ind = ioc_extractor.extract(sample_report_text)["indicators"]
    assert "198.51.100.23" in ind["ipv4"]
    assert "192.168.1.10" not in ind["ipv4"]
    assert "10.0.0.5" not in ind["ipv4"]
    assert "c2-node1.example" in ind["domains"]
    assert "billing@invoice-delivery.example" in ind["emails"]
    assert len(ind["sha256"]) == 1
    assert len(ind["md5"]) == 1
    assert len(ind["registry_paths"]) == 1


def test_results_are_deduplicated_and_sorted(ioc_extractor):
    ind = ioc_extractor.extract("8.8.4.4 and 8.8.4.4 and 1.1.1.1")["indicators"]
    assert ind["ipv4"] == ["1.1.1.1", "8.8.4.4"]
