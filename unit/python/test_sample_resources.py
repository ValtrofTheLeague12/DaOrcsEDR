"""Generator resources and the factory features they feed.

The contract pinned here:

  * any http(s) URL is accepted, a github.com /blob/ page is rewritten to the
    raw one, and a redirect must still land on http(s);
  * each kind validates its own line shape - a real IP, a real hostname, a
    printable string - and counts what it skipped instead of guessing;
  * a failed refresh keeps the last good values and records the error, because
    a pool that silently empties is worse than one that says it is stale;
  * disabled resources are fetched but never sampled;
  * changing a URL or kind drops the cache, so yesterday's list cannot answer
    for the new address;
  * the factory only offers a resource-backed checkbox while its pool can
    honour it, and the composed source carries the values plus their provenance.

No real network and no real compiler: `_OPEN` and `_POPEN` are the modules' one
indirection each, the same discipline as test_sample_factory.
"""

from __future__ import annotations

import base64
import json
import re
import sys
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))

from panel import config  # noqa: E402
from panel import sample_factory as sf  # noqa: E402
from panel import sample_resources as sr  # noqa: E402


IP_URL = "https://raw.githubusercontent.com/lab/feeds/main/ips.txt"
DOMAIN_URL = "https://raw.githubusercontent.com/lab/feeds/main/domains.txt"
URL_URL = "https://raw.githubusercontent.com/lab/feeds/main/urls.txt"


@pytest.fixture()
def tree(tmp_path, monkeypatch):
    """A repo-shaped tree plus an isolated AppData root."""
    monkeypatch.setattr(config, "REPO", tmp_path)
    monkeypatch.setenv("IA_APPDATA_DIR", str(tmp_path / "appdata"))
    return tmp_path


@pytest.fixture()
def net(monkeypatch):
    """The network as a URL -> bytes map, with a record of what was fetched."""
    files: dict[str, bytes] = {}
    calls: list[str] = []

    class Response:
        headers = {}

        def __init__(self, body: bytes, url: str):
            self._body = body
            self._url = url

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def geturl(self) -> str:
            return self._url

        def read(self, limit: int) -> bytes:
            return self._body[:limit]

    def fake_open(request, timeout=None):
        calls.append(request.full_url)
        if request.full_url not in files:
            raise urllib.error.HTTPError(request.full_url, 404, "Not Found",
                                         {}, None)
        return Response(files[request.full_url], request.full_url)

    monkeypatch.setattr(sr, "_OPEN", fake_open)
    return files, calls


def add(kind: str, label: str, url: str, **extra) -> dict:
    return sr.add({"label": label, "kind": kind, "url": url, **extra})


# --- URL handling -------------------------------------------------------------


class TestUrls:
    @pytest.mark.parametrize("raw,expected", [
        (IP_URL, IP_URL),
        ("https://github.com/lab/feeds/blob/main/ips.txt", IP_URL),
        ("https://github.com/lab/feeds/raw/main/ips.txt", IP_URL),
        ("https://gist.githubusercontent.com/lab/abc/raw/x.txt",
         "https://gist.githubusercontent.com/lab/abc/raw/x.txt"),
        # Any host is fine: the panel does not arbitrate where a list lives.
        ("https://lists.example.com/ips.txt",
         "https://lists.example.com/ips.txt"),
        ("http://192.168.1.5:8080/list.txt",
         "http://192.168.1.5:8080/list.txt"),
    ])
    def test_urls_are_normalised(self, raw, expected):
        assert sr._clean_url(raw) == expected

    @pytest.mark.parametrize("raw,reason", [
        ("https://github.com/lab/feeds", "point at a file"),
        ("https://user:pw@raw.githubusercontent.com/lab/feeds/main/ips.txt",
         "credentials"),
        ("file:///etc/passwd", "http or https"),
        ("ftp://lists.example.com/ips.txt", "http or https"),
        ("https:///no-host.txt", "no host"),
    ])
    def test_unusable_urls_are_refused_by_reason(self, raw, reason):
        with pytest.raises(ValueError, match=reason):
            sr._clean_url(raw)


# --- parsing ------------------------------------------------------------------


class TestParsing:
    def test_ips_are_extracted_and_the_rest_counted(self):
        parsed = sr.parse_entries("ip", """
# a header comment
// another comment
1.2.3.4
1.2.3.4,2024-01-01
not-an-ip
2001:db8::1
""")
        assert parsed["entries"] == ["1.2.3.4", "2001:db8::1"]
        assert parsed["duplicates"] == 1
        assert parsed["invalid"] == 1
        assert parsed["lines"] == 4

    def test_domains_are_lowercased_and_wildcards_reduced(self):
        parsed = sr.parse_entries("domain", """
EVIL.example
*.Bad.Example
trailing.example.
1.2.3.4
not a domain
""")
        assert parsed["entries"] == ["evil.example", "bad.example",
                                     "trailing.example"]
        assert parsed["invalid"] == 2

    def test_hosts_file_lines_use_the_hostname(self):
        # The common community-list shape: the sink address is not the value.
        parsed = sr.parse_entries("domain", """
0.0.0.0 evil.example
127.0.0.1 localhost
::1 v6.example
""")
        assert parsed["entries"] == ["evil.example", "v6.example"]
        assert parsed["invalid"] == 1

    def test_blocking_and_loopback_addresses_are_not_malicious_ips(self):
        parsed = sr.parse_entries("ip", """
0.0.0.0
127.0.0.1
::1
fe80::1
8.8.8.8
""")
        assert parsed["entries"] == ["8.8.8.8"]
        assert parsed["invalid"] == 4

    def test_the_entry_cap_is_reported(self, monkeypatch):
        monkeypatch.setattr(sr, "MAX_ENTRIES", 2)
        parsed = sr.parse_entries("ip", "1.1.1.1\n8.8.8.8\n9.9.9.9\n")
        assert parsed["entries"] == ["1.1.1.1", "8.8.8.8"]
        assert parsed["truncated"] is True

    def test_urls_keep_their_path_and_query(self):
        parsed = sr.parse_entries("url", """
https://evil.example/gate.php?id=7
http://203.0.113.9:8080/a/b
ftp://evil.example/x
https://no-dot-host/x
not a url
""")
        assert parsed["entries"] == ["https://evil.example/gate.php?id=7",
                                     "http://203.0.113.9:8080/a/b"]
        assert parsed["invalid"] == 3

    def test_hashes_accept_all_three_lengths_and_any_column(self):
        sha1, sha256, sha512 = "1" * 40, "A" * 64, "c" * 128
        parsed = sr.parse_entries("hash", f"""
{sha1}
sha256:{sha256.lower()}
{"b" * 64},2024-01-01
{sha512}
SHA256,{sha256}
{"e" * 63}
""")
        assert parsed["entries"] == [sha1, "a" * 64, "b" * 64, sha512]
        assert parsed["duplicates"] == 1
        assert parsed["invalid"] == 1

    def test_a_sha1_feed_is_not_read_as_sha256_only(self):
        # threatview.io's SHA-HASH-FEED is 40-character SHA-1; the kind must
        # take it rather than reporting "no hashes in 4178 lines".
        parsed = sr.parse_entries("hash", "0009a66eab25c81f940e1c8324d848286d91e015\n"
                                           "002180a59724edba9ebd19c572d4c23fff8a78bc\n")
        assert parsed["entries"] == [
            "0009a66eab25c81f940e1c8324d848286d91e015",
            "002180a59724edba9ebd19c572d4c23fff8a78bc",
        ]


# --- definitions --------------------------------------------------------------


class TestDefinitions:
    def test_adding_a_resource_writes_the_file_and_the_snapshot(self, tree):
        record = add("ip", "Lab IPs", IP_URL)
        assert record["id"] == "lab-ips"
        assert sr.resources_path().is_file()
        snap = sr.snapshot()
        assert snap["exists"] is True
        assert snap["kinds"][0]["resources"][0]["label"] == "Lab IPs"
        assert snap["kinds"][0]["resources"][0]["current"] is False

    def test_ids_are_unique_and_kinds_are_named(self, tree):
        add("ip", "Lab IPs", IP_URL)
        with pytest.raises(ValueError, match="already exists"):
            add("ip", "Lab IPs", DOMAIN_URL)
        with pytest.raises(ValueError, match="kind"):
            add("asn", "Asns", IP_URL)
        with pytest.raises(ValueError, match="kind"):
            add("rot13", "Old pool", IP_URL)

    def test_unknown_fields_are_refused(self, tree):
        with pytest.raises(ValueError, match="unknown field"):
            add("ip", "Lab IPs", IP_URL, colour="red")

    def test_a_broken_file_is_reported_not_overwritten(self, tree):
        sr.resources_path().parent.mkdir(parents=True, exist_ok=True)
        sr.resources_path().write_text("{ not json", encoding="utf-8")
        snap = sr.snapshot()
        assert "not valid JSON" in snap["error"]
        with pytest.raises(ValueError, match="not valid JSON"):
            add("ip", "Lab IPs", IP_URL)

    def test_the_cap_refuses_more_resources(self, tree, monkeypatch):
        monkeypatch.setattr(sr, "MAX_RESOURCES", 1)
        add("ip", "One", IP_URL)
        with pytest.raises(ValueError, match="cap"):
            add("ip", "Two", DOMAIN_URL)

    def test_a_new_url_drops_the_cached_values(self, tree, net):
        files, _ = net
        files[IP_URL] = b"1.2.3.4\n"
        record = add("ip", "Lab IPs", IP_URL)
        assert sr.refresh(record["id"])["ok"]
        assert sr.pool_counts()["ip"] == 1

        sr.update(record["id"], {"url": DOMAIN_URL})
        assert not sr._meta_path(record["id"]).exists()
        assert not sr._dump_path(record["id"]).exists()
        assert sr.pool_counts()["ip"] == 0
        row = sr.snapshot()["kinds"][0]["resources"][0]
        assert row["current"] is False

    def test_removing_a_resource_deletes_its_cache(self, tree, net):
        files, _ = net
        files[IP_URL] = b"1.2.3.4\n"
        record = add("ip", "Lab IPs", IP_URL)
        sr.refresh(record["id"])
        assert sr._meta_path(record["id"]).exists()
        assert sr._dump_path(record["id"]).exists()

        sr.remove(record["id"])
        assert sr.snapshot()["kinds"][0]["resources"] == []
        assert not sr._meta_path(record["id"]).exists()
        assert not sr._dump_path(record["id"]).exists()

    def test_a_successful_fetch_keeps_the_dump_verbatim(self, tree, net):
        files, _ = net
        body = b"# comment\n1.2.3.4\n5.6.7.8\n"
        files[IP_URL] = body
        record = add("ip", "Lab IPs", IP_URL)
        assert sr.refresh(record["id"])["ok"]

        dump = sr._dump_path(record["id"])
        assert dump.read_bytes() == body
        row = sr.snapshot()["kinds"][0]["resources"][0]
        assert row["dump"] == dump.relative_to(tree).as_posix()
        assert sr.snapshot()["dump_dir"] == "ressources"

    def test_unknown_ids_are_lookup_errors(self, tree):
        with pytest.raises(LookupError):
            sr.update("nope", {"enabled": False})
        with pytest.raises(LookupError):
            sr.remove("nope")


# --- fetching -----------------------------------------------------------------


class TestRefresh:
    def test_a_successful_fetch_fills_the_pool(self, tree, net):
        files, calls = net
        files[IP_URL] = b"# feed\n1.2.3.4\n5.6.7.8\nbad\n"
        record = add("ip", "Lab IPs", IP_URL)
        result = sr.refresh(record["id"])

        assert result["ok"], result
        assert result["count"] == 2
        assert result["invalid"] == 1
        assert calls == [IP_URL]

        snap = sr.snapshot()
        row = snap["kinds"][0]["resources"][0]
        assert row["current"] is True
        assert row["count"] == 2
        assert row["preview"] == ["1.2.3.4", "5.6.7.8"]
        assert row["last_error"] is None
        assert snap["pools"]["ip"] == 2
        assert snap["features"]["iocs"]["available"] is False
        assert "domain" in snap["features"]["iocs"]["reason"]

    def test_a_disabled_resource_is_never_sampled(self, tree, net):
        files, _ = net
        files[IP_URL] = b"1.2.3.4\n"
        record = add("ip", "Lab IPs", IP_URL)
        sr.refresh(record["id"])
        sr.update(record["id"], {"enabled": False})

        assert sr.snapshot()["pools"]["ip"] == 0
        assert sr.pick("ip") is None
        # The values are still there to re-enable without another download.
        assert sr.snapshot()["kinds"][0]["resources"][0]["count"] == 1

    def test_a_failed_fetch_keeps_the_last_good_values(self, tree, net):
        files, _ = net
        files[IP_URL] = b"1.2.3.4\n"
        record = add("ip", "Lab IPs", IP_URL)
        assert sr.refresh(record["id"])["ok"]

        # The next fetch finds a 404.
        del files[IP_URL]
        failed = sr.refresh(record["id"])
        assert failed["ok"] is False
        assert "404" in failed["error"]
        assert failed["count"] == 1

        row = sr.snapshot()["kinds"][0]["resources"][0]
        assert row["count"] == 1
        assert row["current"] is True
        assert "404" in row["last_error"]
        assert sr.pool_counts()["ip"] == 1
        assert sr.pick("ip")["value"] == "1.2.3.4"

    def test_a_successful_fetch_clears_the_previous_error(self, tree, net):
        files, _ = net
        record = add("ip", "Lab IPs", IP_URL)
        sr.refresh(record["id"])  # 404: no body registered yet
        assert sr.snapshot()["kinds"][0]["resources"][0]["last_error"]

        files[IP_URL] = b"1.2.3.4\n"
        assert sr.refresh(record["id"])["ok"]
        row = sr.snapshot()["kinds"][0]["resources"][0]
        assert row["last_error"] is None
        assert row["count"] == 1

    def test_a_file_with_no_usable_values_is_refused(self, tree, net):
        files, _ = net
        files[IP_URL] = b"# just a header\n"
        record = add("ip", "Lab IPs", IP_URL)
        result = sr.refresh(record["id"])
        assert result["ok"] is False
        assert "no IP addresses" in result["error"]

    def test_binary_utf16_and_oversized_bodies_are_refused(self, tree, net):
        files, _ = net
        record = add("ip", "Lab IPs", IP_URL)

        files[IP_URL] = b"1.2.3.4\x00\n"
        assert "binary" in sr.refresh(record["id"])["error"]

        files[IP_URL] = "1.2.3.4\n".encode("utf-16")
        assert "UTF-8" in sr.refresh(record["id"])["error"]

        files[IP_URL] = b"1" * (sr.MAX_BYTES + 1)
        assert "cap" in sr.refresh(record["id"])["error"]

    def test_a_redirect_to_another_host_is_followed(self, tree, net, monkeypatch):
        record = add("ip", "Lab IPs", IP_URL)

        class Elsewhere:
            headers = {}

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def geturl(self):
                return "https://mirror.example.com/list.txt"

            def read(self, limit):
                return b"1.2.3.4\n"

        monkeypatch.setattr(sr, "_OPEN", lambda request, timeout=None: Elsewhere())
        result = sr.refresh(record["id"])
        assert result["ok"] is True
        assert result["count"] == 1

    def test_a_redirect_to_a_non_http_scheme_is_refused(self, tree, net,
                                                        monkeypatch):
        record = add("ip", "Lab IPs", IP_URL)

        class BadScheme:
            headers = {}

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def geturl(self):
                return "file:///etc/passwd"

            def read(self, limit):
                return b"1.2.3.4\n"

        monkeypatch.setattr(sr, "_OPEN", lambda request, timeout=None: BadScheme())
        result = sr.refresh(record["id"])
        assert result["ok"] is False
        assert "redirected" in result["error"]

    def test_the_network_error_is_a_sentence_not_a_trace(self, tree, monkeypatch):
        record = add("ip", "Lab IPs", IP_URL)

        def refuse(request, timeout=None):
            raise urllib.error.URLError("connection refused")

        monkeypatch.setattr(sr, "_OPEN", refuse)
        result = sr.refresh(record["id"])
        assert result["ok"] is False
        assert "could not reach raw.githubusercontent.com" in result["error"]

    def test_a_mid_download_break_is_a_sentence_too(self, tree, monkeypatch):
        import http.client

        record = add("ip", "Lab IPs", IP_URL)

        def broken(request, timeout=None):
            raise http.client.IncompleteRead(partial=b"1.2")

        monkeypatch.setattr(sr, "_OPEN", broken)
        result = sr.refresh(record["id"])
        assert result["ok"] is False
        assert "mid-download" in result["error"]


# --- factory integration ------------------------------------------------------


def fill_pools(net, *, ip="203.0.113.9", domain="evil.example") -> None:
    files, _ = net
    files[IP_URL] = f"{ip}\n".encode()
    files[DOMAIN_URL] = f"{domain}\n".encode()
    for kind, label, url in (
            ("ip", "Lab IPs", IP_URL), ("domain", "Lab domains", DOMAIN_URL)):
        record = add(kind, label, url)
        assert sr.refresh(record["id"])["ok"], kind


class TestFactoryOffer:
    def test_without_pools_the_features_are_named_as_unavailable(
            self, tree, net):
        catalog = sf.templates()
        assert "iocs" not in catalog["features"]["c"]
        assert "iocs" in catalog["feature_unavailable"]
        assert "malicious-IP" in catalog["feature_unavailable"]["iocs"]
        assert catalog["pools"] == {kind: 0 for kind in sr.KIND_ORDER}

        refused = sf.compose("c", None, ["iocs"])
        assert refused["ok"] is False
        assert "cannot be used" in refused["error"]
        assert "malicious-IP" in refused["error"]

    def test_a_filled_pool_offers_its_feature(self, tree, net):
        fill_pools(net)
        catalog = sf.templates()
        assert "iocs" in catalog["features"]["c"]
        assert "iocs" not in catalog["feature_unavailable"]
        assert catalog["pools"]["ip"] == 1
        assert catalog["pools"]["domain"] == 1

    def test_disabling_the_last_ip_source_disables_iocs(self, tree, net):
        fill_pools(net)
        record = next(r for r in sr.snapshot()["kinds"][0]["resources"])
        sr.update(record["id"], {"enabled": False})
        assert "iocs" in sf.templates()["feature_unavailable"]


class TestFactoryComposition:
    def test_iocs_carry_the_values_and_their_sources(self, tree, net):
        fill_pools(net)
        for language in sf.LANGUAGES:
            preview = sf.compose(language, None, ["iocs"], "plain")
            assert preview["ok"], (language, preview)
            assert "203.0.113.9" in preview["code"]
            assert "evil.example" in preview["code"]
            assert "never dialled" in preview["code"]
            kinds = {r["kind"]: r for r in preview["resources"]}
            assert kinds["ip"]["value"] == "203.0.113.9"
            assert kinds["ip"]["label"] == "Lab IPs"
            assert kinds["ip"]["encoding"] == "plain"
            assert kinds["domain"]["value"] == "evil.example"
            assert "resources: iocs<-lab-ips+lab-domains" in preview["code"]
            assert "encoding: plain" in preview["code"]

    def test_every_pool_kind_is_sampled_without_editing_the_loop(self, tree, net):
        # A kind added to sample_resources must be picked up by _ioc_uses()
        # without a second hardcoded list drifting out of date.
        files, _ = net
        fill_pools(net)
        files[URL_URL] = b"https://evil.example/gate.php?id=7\n"
        record = add("url", "Lab URLs", URL_URL)
        assert sr.refresh(record["id"])["ok"]
        preview = sf.compose("c", None, ["iocs"], "plain")
        assert preview["ok"], preview
        kinds = {r["kind"]: r for r in preview["resources"]}
        assert kinds["url"]["value"] == "https://evil.example/gate.php?id=7"
        assert kinds["url"]["label"] == "Lab URLs"
        assert "resource_ioc_url" in preview["code"]
        assert "https://evil.example/gate.php?id=7" in preview["code"]

    def test_the_features_compose_together_with_noise(self, tree, net):
        fill_pools(net)
        preview = sf.compose("c", None, ["strings", "noise", "iocs"], "plain")
        assert preview["ok"], preview
        assert "203.0.113." in preview["code"]  # noise
        assert "203.0.113.9" in preview["code"]  # resource IOC

    def test_ioc_xor_and_base64_change_the_source_shape(self, tree, net):
        fill_pools(net)
        xor = sf.compose("c", None, ["iocs"], "xor")
        assert xor["ok"], xor
        assert "203.0.113.9" not in xor["code"]
        assert re.search(r"const unsigned char enc\[\] = \{0x[0-9a-f]{2}",
                         xor["code"])
        assert re.search(r"\^ 0x[0-9a-f]{2}\)", xor["code"])

        b64 = sf.compose("c", None, ["iocs"], "base64")
        assert b64["ok"], b64
        encoded_ip = base64.b64encode(b"203.0.113.9").decode("ascii")
        assert encoded_ip in b64["code"]
        assert "val = (val << 6) | (unsigned)d;" in b64["code"]

    def test_each_ioc_encoding_keeps_its_plaintext_out(self, tree, net):
        fill_pools(net)
        for encoding in ("xor", "base64", "chained", "mixed"):
            preview = sf.compose("c", None, ["iocs"], encoding)
            assert preview["ok"], (encoding, preview)
            assert "203.0.113.9" not in preview["code"], encoding
            assert "evil.example" not in preview["code"], encoding
            assert all(r["encoding"] in ("rot13", "xor", "base64", "chained")
                       for r in preview["resources"]), encoding
            # Every encoded value is decoded at runtime, whichever shape it got.
            assert "resource_ioc_ip" in preview["code"]
            assert "resource_ioc_domain" in preview["code"]

    def test_rot13_is_a_fixed_point_for_an_all_digit_ip(self, tree, net):
        fill_pools(net)
        preview = sf.compose("c", None, ["iocs"], "rot13")
        assert preview["ok"], preview
        # Honest limitation, stated in the select's note: ROT13 rotates
        # letters, so the IPv4 literal is unchanged. The domain does change.
        assert "203.0.113.9" in preview["code"]
        assert sf._rot13("evil.example") in preview["code"]
        assert "evil.example" not in preview["code"]
        assert [r["encoding"] for r in preview["resources"]] == ["rot13", "rot13"]

    def test_chain_encoding_applies_rot13_base64_xor_in_order(self, tree, net):
        # The displayed literal must be the XOR of the Base64 of the ROT13
        # of the value - the challenge said "in order" and meant it.
        fill_pools(net)
        preview = sf.compose("c", None, ["iocs"], "chained")
        assert preview["ok"], preview
        assert all(r["encoding"] == "chained"
                   for r in preview["resources"])
        for r in preview["resources"]:
            rot = sf._rot13(r["value"])
            b64 = base64.b64encode(rot.encode("ascii"))
            var = ("resource_ioc_ip" if r["kind"] == "ip"
                   else "resource_ioc_domain")
            text = preview["code"][preview["code"].find(var):]
            match = re.search(r'const char enc\[\] = "((?:\\x[0-9a-f]{2})+)";',
                              text)
            assert match, r
            key = re.search(r"enc\[i\] \^ 0x([0-9a-f]{2})\);", text)
            assert key, r
            literal = bytes(int(h, 16)
                            for h in re.findall(r"\\x([0-9a-f]{2})",
                                                match.group(1)))
            chained = "".join("\\x%02x" % (b ^ int(key.group(1), 16))
                              for b in b64)
            encoded_equivalent = {
                "\\x%02x" % (byte ^ int(key.group(1), 16))
                for byte in b64
            }
            shown = re.findall(r"\\x([0-9a-f]{2})", match.group(1))
            # Every byte of the encoded rot13 base64 is present, XORed with
            # the key the decode loop uses - the reverse chain recovers it.
            translated = "".join(
                "%02x" % (int(h, 16) ^ int(key.group(1), 16)) for h in shown)
            assert translated == b64.hex(), (r, translated, b64.hex())
            # and the decode unwinds in reverse in the source
            assert "chain stage 1/3" in preview["code"]
            assert "chain stage 2/3" in preview["code"]
            assert "chain stage 3/3" in preview["code"]

    def test_use_suspicious_functions_feature_is_safe_and_presented(self,
                                                                   tree, net):
        fill_pools(net)
        for language in sf.LANGUAGES:
            preview = sf.compose(language, None, ["sus"], "plain")
            assert preview["ok"], (language, preview)
            code = preview["code"]
            # The read-only calls are really called...
            for fn in ("GetTickCount", "IsDebuggerPresent", "GetProcessHeap",
                       "HeapSize"):
                assert fn in code, (language, fn)
            # ...and the heavyweight names appear, but only as inert data.
            for name in ("VirtualAlloc", "WriteProcessMemory",
                         "CreateRemoteThread", "SetWindowsHookEx"):
                assert f'"{name}"' in code, (language, name)
            assert f"VirtualAlloc(" not in code, language
            # the guarded windows include is part of the offer
            assert "#include <windows.h>" in code
            assert "#ifdef _WIN32" in code
        # the vocabulary names it the way the operator asked
        catalog = sf.templates()
        assert "sus" in catalog["features"]["c"]
        assert "Use suspicious functions" in catalog["feature_notes"]["sus"]

    def test_chain_encoding_is_offered_by_the_catalog(self, tree, net):
        fill_pools(net)
        encodings = sf.templates()["encodings"]
        assert "chained" in encodings
        assert "ROT13 -> Base64 -> XOR" in encodings["chained"]

    def test_a_pool_emptied_after_the_page_loaded_is_a_sentence(
            self, tree, net):
        fill_pools(net)
        # Simulate the race by removing the source between the offer and the
        # press: the feature is known, so the refusal must explain the pool.
        for kind in sr.snapshot()["kinds"][0]["resources"]:
            sr.remove(kind["id"])
        preview = sf.compose("c", None, ["iocs"])
        assert preview["ok"] is False
        assert "malicious-IP" in preview["error"]

    def test_generate_reports_the_resources_it_used(self, tree, net,
                                                   monkeypatch):
        fill_pools(net)

        def fake_popen(argv, **kwargs):
            Path(argv[argv.index("-o") + 1]).write_bytes(b"MZ\0\0")
            proc = MagicMock()
            proc.returncode = 0
            proc.communicate = lambda timeout=None: ("ok", "")
            return proc

        monkeypatch.setattr(sf, "_POPEN", fake_popen)
        bin_dir = tree / "ucrt64" / "bin"
        bin_dir.mkdir(parents=True)
        (bin_dir / "gcc.exe").write_bytes(b"stub")
        (bin_dir / "g++.exe").write_bytes(b"stub")
        monkeypatch.setattr(sf.build, "UCRT64", tree / "ucrt64")

        result = sf.generate("c", None, ["iocs"], name="resource-bait",
                             encoding="plain")
        assert result["ok"], result
        assert result["resources"][0]["value"] == "203.0.113.9"
        assert result["encoding"] == "plain"
        written = (tree / result["source"]).read_text(encoding="utf-8")
        assert "203.0.113.9" in written


# --- composition options and post-compile steps -------------------------------


def _pe_image(*, magic=0x10B) -> bytes:
    """A PE header just complete enough for pe_tools to parse."""
    import struct

    data = bytearray(0x400)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    struct.pack_into("<H", data, coff, 0x8664 if magic == 0x20B else 0x14C)
    struct.pack_into("<H", data, coff + 2, 3)
    struct.pack_into("<H", data, coff + 16, 240)
    opt = coff + 20
    struct.pack_into("<H", data, opt, magic)
    if magic == 0x10B:
        count_offset, directory = opt + 92, opt + 96
    else:
        count_offset, directory = opt + 108, opt + 112
    struct.pack_into("<I", data, count_offset, 16)
    struct.pack_into("<II", data, directory + 1 * 8, 0x1000, 0x28)
    struct.pack_into("<II", data, directory + 12 * 8, 0x2000, 0x10)
    return bytes(data)


class TestCompositionOptions:
    def test_sleep_is_a_stated_duration_and_its_include(self, tree):
        for language in sf.LANGUAGES:
            preview = sf.compose(language, None, [], sleep_seconds=7)
            assert preview["ok"], (language, preview)
            assert "#include <windows.h>" in preview["code"]
            assert "Sleep(7000);" in preview["code"]
            assert "sleeping 7000 ms" in preview["code"]
            assert "sleep:    7000 ms" in preview["code"]
            assert preview["sleep_seconds"] == 7

        without = sf.compose("c", None, [])
        assert "#include <windows.h>" not in without["code"]
        assert "Sleep(" not in without["code"]

    def test_bad_encoding_and_sleep_are_refused(self, tree):
        bad = (
            {"encoding": "base32"},
            {"sleep_seconds": -1},
            {"sleep_seconds": sf.SLEEP_MAX + 1},
            {"sleep_seconds": 1.5},
            {"sleep_seconds": True},
        )
        for kwargs in bad:
            result = sf.compose("c", None, [], **kwargs)
            assert result["ok"] is False, kwargs
            assert result["error"], kwargs

    def test_the_catalog_names_the_encodings_and_the_upx_state(self, tree):
        catalog = sf.templates()
        assert list(catalog["encodings"]) == ["mixed", "plain", "rot13", "xor",
                                              "base64", "chained"]
        assert catalog["sleep_max"] == sf.SLEEP_MAX
        assert catalog["upx"]["ok"] is False
        assert "upx/upx.exe" in catalog["upx"]["error"]
        assert "ready" in catalog["eagle"]
        assert "artifacts" in catalog["eagle"]

        (tree / "upx").mkdir()
        (tree / "upx" / "upx.exe").write_bytes(b"stub")
        assert sf.templates()["upx"] == {"ok": True, "path": "upx/upx.exe"}

    def test_generate_refuses_non_boolean_flags(self, tree):
        result = sf.generate("c", None, [], upx="yes")
        assert result["ok"] is False
        assert "true or false" in result["error"]

    def test_a_bad_seed_is_refused(self, tree):
        for seed in (-1, 0x1_0000_0000, 1.5, True):
            result = sf.compose("c", None, [], seed=seed)
            assert result["ok"] is False, seed
            assert "seed" in result["error"], seed

    def test_the_seed_replays_the_preview_exactly(self, tree, net):
        fill_pools(net)
        first = sf.compose("c", None, ["iocs", "noise"], "mixed", 3)
        assert first["ok"], first
        for _ in range(3):
            again = sf.compose("c", None, ["iocs", "noise"], "mixed", 3,
                               first["seed"])
            assert again["ok"], again
            assert again["code"] == first["code"]
            assert again["noise"] == first["noise"]
            assert again["resources"] == first["resources"]
            assert again["seed"] == first["seed"]

    def test_generate_replays_the_preview_seed(self, tree, net, monkeypatch):
        fill_pools(net)
        preview = sf.compose("c", None, ["iocs", "noise"], "mixed", 2)
        assert preview["ok"], preview

        def fake_popen(argv, **kwargs):
            Path(argv[argv.index("-o") + 1]).write_bytes(b"MZ\0\0")
            proc = MagicMock()
            proc.returncode = 0
            proc.communicate = lambda timeout=None: ("ok", "")
            return proc

        monkeypatch.setattr(sf, "_POPEN", fake_popen)
        bin_dir = tree / "ucrt64" / "bin"
        bin_dir.mkdir(parents=True)
        (bin_dir / "gcc.exe").write_bytes(b"stub")
        (bin_dir / "g++.exe").write_bytes(b"stub")
        monkeypatch.setattr(sf.build, "UCRT64", tree / "ucrt64")

        result = sf.generate("c", None, ["iocs", "noise"], name="replay",
                             encoding="mixed", sleep_seconds=2,
                             seed=preview["seed"])
        assert result["ok"], result
        assert result["code"] == preview["code"]
        written = (tree / result["source"]).read_text(encoding="utf-8")
        assert written == preview["code"]


class TestPostCompile:
    def _stub_toolchain(self, tree, monkeypatch, *, image=None):
        calls: list[list[str]] = []

        def fake_popen(argv, **kwargs):
            calls.append(argv)
            proc = MagicMock()
            if str(argv[0]).lower().endswith("upx.exe"):
                Path(argv[-1]).write_bytes(
                    image if image is not None else b"MZ" + b"\0" * 10)
                proc.returncode = 0
                proc.communicate = lambda timeout=None: ("Packed 1 -> 2", "")
            else:
                Path(argv[argv.index("-o") + 1]).write_bytes(
                    image if image is not None else b"MZ" + b"\0" * 600)
                proc.returncode = 0
                proc.communicate = lambda timeout=None: ("gcc ok", "")
            return proc

        monkeypatch.setattr(sf, "_POPEN", fake_popen)
        bin_dir = tree / "ucrt64" / "bin"
        bin_dir.mkdir(parents=True)
        (bin_dir / "gcc.exe").write_bytes(b"stub")
        (bin_dir / "g++.exe").write_bytes(b"stub")
        monkeypatch.setattr(sf.build, "UCRT64", tree / "ucrt64")
        return calls

    def test_upx_refuses_when_the_tool_is_missing(self, tree, monkeypatch):
        calls = self._stub_toolchain(tree, monkeypatch)
        result = sf.generate("c", None, [], name="no-upx", upx=True)
        assert result["ok"] is False
        assert "upx/upx.exe" in result["error"]
        assert calls == []

    def test_upx_packs_and_reports_the_ratio(self, tree, monkeypatch):
        calls = self._stub_toolchain(tree, monkeypatch)
        (tree / "upx").mkdir()
        (tree / "upx" / "upx.exe").write_bytes(b"stub")

        result = sf.generate("c", None, [], name="packed", upx=True)
        assert result["ok"], result
        assert result["packed"]["before"] == 602
        assert result["packed"]["after"] == 12
        assert result["packed"]["ratio"] == round(12 / 602, 3)
        assert calls[-1][0].endswith("upx.exe")
        assert "--best" in calls[-1]
        assert "Packed 1 -> 2" in result["log"]

    def test_a_failed_upx_keeps_the_unpacked_exe(self, tree, monkeypatch):
        calls = self._stub_toolchain(tree, monkeypatch)
        (tree / "upx").mkdir()
        (tree / "upx" / "upx.exe").write_bytes(b"stub")

        real = sf._POPEN

        def fake_popen(argv, **kwargs):
            proc = real(argv, **kwargs)
            if str(argv[0]).lower().endswith("upx.exe"):
                proc.returncode = 1
                proc.communicate = lambda timeout=None: ("upx: cannot pack", "")
            return proc

        monkeypatch.setattr(sf, "_POPEN", fake_popen)
        result = sf.generate("c", None, [], name="pack-fails", upx=True)
        assert result["ok"] is False
        assert "UPX failed" in result["error"]
        assert Path(tree / result["exe"]).exists()
        assert result["code"]

    def _stub_eagle(self, tree, monkeypatch, *, ready=True):
        include = tree / "EagleVM" / "include"
        lib = tree / "EagleVM" / "out" / "build" / "x64-release"
        include.mkdir(parents=True, exist_ok=True)
        lib.mkdir(parents=True, exist_ok=True)
        (lib / "EagleVMStub.dll").write_bytes(b"dll")
        (lib / "libEagleVMStub.a").write_bytes(b"lib")
        seen: list[Path] = []

        monkeypatch.setattr(sf.eagle, "status", lambda: {
            "ok": ready, "ready": ready, "available": True,
            "reason": None if ready else "not built yet",
            "note": "ready to virtualise" if ready else "not built yet"})
        monkeypatch.setattr(sf.eagle, "toolchain", lambda: {
            "include": include,
            "lib": lib / "libEagleVMStub.a",
            "exe": lib / "EagleVM.exe",
            "stub_dll": lib / "EagleVMStub.dll"})

        def fake_virtualize(exe, cwd=None):
            seen.append(Path(exe))
            out = Path(cwd) / f"{Path(exe).stem}_protected.exe"
            out.write_bytes(Path(exe).read_bytes())
            return out, "EagleVM: virtualised 42 instructions"

        monkeypatch.setattr(sf.eagle, "virtualize", fake_virtualize)
        return seen

    def test_virtualisation_returns_the_protected_exe_and_flags(self, tree, monkeypatch):
        self._stub_toolchain(tree, monkeypatch)
        seen = self._stub_eagle(tree, monkeypatch)

        result = sf.generate("c", None, [], name="virt", virtualize=True)
        assert result["ok"], result
        assert seen and seen[0].name == "virt.exe"
        assert result["virtualized"]["from"] == "virt.exe"
        assert result["virtualized"]["to"] == "virt_protected.exe"
        assert result["exe"].endswith("virt_protected.exe")
        assert Path(tree / result["exe"]).exists()
        assert result["flags"] == {"upx": False, "virtualize": True,
                                   "makefile": False}
        # The compiled source carries the markers EagleVM looks for.
        assert "fnEagleVMBegin();" in result["code"]
        assert "fnEagleVMEnd();" in result["code"]

    def test_virtualisation_is_refused_when_eagle_is_not_built(self, tree, monkeypatch):
        calls = self._stub_toolchain(tree, monkeypatch)
        self._stub_eagle(tree, monkeypatch, ready=False)

        result = sf.generate("c", None, [], name="unbuilt", virtualize=True)
        assert result["ok"] is False
        assert "EagleVM is not built" in result["error"]
        assert calls == []
        assert not (tree / "samples" / "unbuilt.exe").exists()

    def test_both_flags_virtualise_then_pack(self, tree, monkeypatch):
        calls = self._stub_toolchain(tree, monkeypatch, image=_pe_image())
        self._stub_eagle(tree, monkeypatch)
        (tree / "upx").mkdir()
        (tree / "upx" / "upx.exe").write_bytes(b"stub")

        result = sf.generate("c", None, [], name="both", upx=True,
                             virtualize=True)
        assert result["ok"], result
        assert result["packed"]["after"] == 0x400
        assert result["virtualized"]["to"] == "both_protected.exe"
        # gcc, then EagleVM (not a subprocess here), then upx on the protected exe.
        assert calls[-1][0].endswith("upx.exe")
        assert calls[-1][-1].endswith("both_protected.exe")
        assert len(calls) == 2
