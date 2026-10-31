"""The hardening endpoints: one payload, a strict write, and the failure modes.

`GET/PUT /api/build/hardening` is the panel side of config/hardening.json. The
two halves of the response are not independent - the card's whole job is to
compare what the NEXT build is asked for against what the CURRENT binary
carries - so the tests pin them arriving together, and pin that a refusal is a
400 with a sentence rather than a 500 or, worse, a 200 that wrote something
nobody asked for.

The app is built here rather than imported from a fixture: the routes live
inside create_app()'s closure, so create_app() IS the unit. Sessions are
bypassed the way the real panel bypasses them for a local operator (see
auth.py's require), which is why nothing here concerns itself with login.

config.REPO is pointed at a tmp tree, and app._gate is left to read whatever it
reads; what must NOT be reachable is the real config/hardening.json - a test
that wrote to it would change the protections the next real build asks for. A
failing test must never be able to weaken a binary.
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))

from panel import build_checks, config, hardening  # noqa: E402

ALL_BITS = 0x0160  # HIGH_ENTROPY_VA | DYNAMIC_BASE | NX_COMPAT


def pe_image(*, dll_characteristics=ALL_BITS, trailing=b"\x00__stack_chk_guard\x00") -> bytes:
    data = bytearray(0x200)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    struct.pack_into("<H", data, coff, 0x8664)
    struct.pack_into("<H", data, coff + 2, 3)
    struct.pack_into("<H", data, coff + 16, 240)
    opt = coff + 20
    struct.pack_into("<H", data, opt, 0x20B)
    struct.pack_into("<H", data, opt + 70, dll_characteristics)
    return bytes(data) + trailing


@pytest.fixture
def client(tmp_path, monkeypatch):
    """A Flask test client over a repo that is a tmp tree.

    config.REPO and build_checks.EXE are both redirected: hardening.py resolves
    its settings path per call through config.REPO (deliberately, so this is
    possible), and the compliance half reads build_checks.EXE.
    """
    monkeypatch.setattr(config, "REPO", tmp_path)
    monkeypatch.setattr(build_checks, "EXE", tmp_path / "static_analyzer.exe")

    from panel.app import create_app
    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client()


def settings_on_disk(repo: Path) -> dict:
    path = repo / "config" / "hardening.json"
    return json.loads(path.read_text(encoding="utf-8"))


class TestRead:
    def test_the_two_halves_arrive_together(self, client, tmp_path):
        (tmp_path / "static_analyzer.exe").write_bytes(pe_image())

        body = client.get("/api/build/hardening").get_json()

        assert set(body) == {"settings", "compliance"}
        # The settings half describes the FILE; the compliance half describes
        # the BINARY. A page that could get one without the other could render
        # a green toggle beside a binary built before it.
        assert body["settings"]["path"] == "config/hardening.json"
        assert body["compliance"]["available"] is True

    def test_an_unbuilt_analyzer_is_reported_not_an_error(self, client):
        response = client.get("/api/build/hardening")

        assert response.status_code == 200
        body = response.get_json()
        assert body["compliance"]["available"] is False
        assert "not built" in body["compliance"]["reason"]

    def test_a_binary_matching_the_defaults_is_compliant(self, client, tmp_path):
        (tmp_path / "static_analyzer.exe").write_bytes(pe_image())

        body = client.get("/api/build/hardening").get_json()

        assert body["compliance"]["compliant"] is True


class TestWrite:
    def test_a_partial_patch_leaves_the_other_settings_alone(self, client, tmp_path):
        response = client.put("/api/build/hardening", json={"aslr": False})

        assert response.status_code == 200
        assert settings_on_disk(tmp_path)["aslr"] is False
        assert settings_on_disk(tmp_path)["dep_nx"] is True

    def test_the_response_is_the_same_payload_as_the_read(self, client, tmp_path):
        (tmp_path / "static_analyzer.exe").write_bytes(pe_image())

        body = client.put("/api/build/hardening", json={"dep_nx": False}).get_json()

        # So the card re-renders from what is on disk rather than from what was
        # asked for - which is the difference between a saved write and a
        # refused one.
        assert set(body) == {"settings", "compliance"}
        assert body["settings"]["settings"]["dep_nx"] is False
        # ...and the binary is still the old one, so the two disagree: the
        # expected "rebuild" state, not an error.
        assert body["compliance"]["compliant"] is False

    def test_a_stringified_boolean_is_refused_with_400(self, client, tmp_path):
        response = client.put("/api/build/hardening", json={"aslr": "false"})

        assert response.status_code == 400
        assert "true or false" in response.get_json()["error"]
        # Nothing was written: a refused request must not leave a file the
        # next build reads as intent.
        assert not (tmp_path / "config" / "hardening.json").exists()

    def test_an_unknown_key_is_refused_with_400(self, client, tmp_path):
        response = client.put("/api/build/hardening", json={"cfg": True})

        assert response.status_code == 400
        assert "cfg" in response.get_json()["error"]
        assert not (tmp_path / "config" / "hardening.json").exists()

    def test_a_non_object_body_is_refused_with_400(self, client):
        response = client.put("/api/build/hardening", json=["aslr"])

        assert response.status_code == 400
        assert "JSON object" in response.get_json()["error"]

    def test_a_body_that_is_not_json_at_all_is_refused(self, client):
        response = client.put("/api/build/hardening", data="aslr=true",
                              content_type="text/plain")

        assert response.status_code == 400


class TestHermetic:
    """The tests must not be able to touch the real settings file.

    A unit test that wrote config/hardening.json in the repository would change
    which protections the next real build asks for - a test that can weaken the
    artefact is worse than no test.
    """

    def test_the_real_settings_file_is_untouched(self, client, tmp_path):
        real = REPO / "config" / "hardening.json"
        before = real.read_bytes() if real.is_file() else None

        client.put("/api/build/hardening", json={"aslr": False})
        client.get("/api/build/hardening")

        after = real.read_bytes() if real.is_file() else None
        assert after == before
        # And the write really did land somewhere: in the tmp tree.
        assert settings_on_disk(tmp_path)["aslr"] is False

    def test_the_endpoint_resolves_the_repo_per_call(self, tmp_path, monkeypatch):
        # hardening.config_path is a function rather than a module constant for
        # exactly this reason; if it ever became a constant the fixture above
        # would silently start writing to the repository.
        monkeypatch.setattr(config, "REPO", tmp_path)
        assert hardening.config_path(config.REPO) == \
            tmp_path / "config" / "hardening.json"
