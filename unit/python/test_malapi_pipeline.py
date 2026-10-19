"""Unit tests for python/malapi_pipeline.py.

MalAPI is the component most likely to be quietly wrong, because almost none of
it fails loudly. The pipeline regenerates a 544-route API from vendored rules,
and the failure modes are a route that 404s, a rule that silently drops out, or
a generator that reports success while producing nothing. So these cover the
pure decision functions and the count/route mapping, not the subprocess stages -
which are integration and belong under tests/.

The route mapping is the highest-value case here, because the thing it protects
against is invisible: `functionName` is the Python view function's identifier
and never appears in the URL, so probing it 404s a perfectly good server. A
test that pins the exact URL shape is the only cheap guard against that coming
back.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))

import malapi_pipeline as mp  # noqa: E402


class TestRouteForApi:
    """The URL the analyzer actually dials."""

    def test_route_is_the_verbatim_api_name(self):
        # malapi.cpp builds "/malapi/" + the IAT entry verbatim. The route has
        # to be built from the same string, or every lookup 404s.
        assert mp.route_for_api("CreateRemoteThread") == "/malapi/CreateRemoteThread/"

    @pytest.mark.parametrize("name", [
        "CreateRemoteThread",
        "NtUnmapViewOfSection",
        "RegSetValueExA",
        "InternetOpenA",
        "CryptEncrypt",
    ])
    def test_every_route_keeps_the_name_verbatim(self, name):
        # No lowercasing, no slug conversion, no stripping of a prefix. The
        # analyzer sends the import name exactly as the PE records it.
        route = mp.route_for_api(name)
        assert route == f"/malapi/{name}/"

    def test_route_has_exactly_one_pair_of_separating_slashes(self):
        # "/malapi/X/" - leading, one between each segment, trailing. An empty
        # or malformed name must not produce "/malapi//" or a missing tail
        # slash, both of which the analyzer's client would treat as a miss.
        route = mp.route_for_api("X")
        assert route.startswith("/malapi/")
        assert route.endswith("/")
        assert "//" not in route

    def test_route_does_not_use_the_lowercased_identifier(self):
        # The bug this guards: functionName is the Python view function's
        # identifier and never appears in the URL. If someone "fixes" route_for_api
        # to use it, every MalAPI lookup silently stops matching - and silently is
        # the whole problem, because the server is healthy and returns 404.
        name = "CreateRemoteThread"
        route = mp.route_for_api(name)
        assert name.lower() not in route
        assert name in route


class TestCountPages:
    """Page counting for the generation stages."""

    def test_counts_index_files_recursively(self, tmp_path):
        (tmp_path / "a").mkdir()
        (tmp_path / "a" / "index.html").write_text("<html>", encoding="utf-8")
        (tmp_path / "index.html").write_text("<html>", encoding="utf-8")
        # A non-index page must not count: the number is "how many entries", not
        # "how many files".
        (tmp_path / "readme.html").write_text("<html>", encoding="utf-8")
        assert mp.count_pages(tmp_path) == 2

    def test_empty_directory_is_zero_not_an_error(self, tmp_path):
        # Called before generation has written anything. Raising here would make
        # a first run impossible.
        assert mp.count_pages(tmp_path) == 0

    def test_missing_directory_is_zero_not_an_error(self, tmp_path):
        # The rules directory may legitimately be absent in a partial checkout.
        assert mp.count_pages(tmp_path / "not-here") == 0


class TestPortProbe:
    def test_an_unused_port_reports_free(self):
        # Bind and immediately release a port, so we know nothing is on it.
        import socket

        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        assert mp._free_port_in_use(port) is False

    def test_a_listening_port_reports_in_use(self):
        import socket

        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            s.listen(1)
            port = s.getsockname()[1]
            assert mp._free_port_in_use(port) is True


class TestLayout:
    """Constants that the rest of the pipeline resolves paths from."""

    def test_repo_root_is_the_parent_of_python(self):
        assert mp.REPO_ROOT == REPO

    @pytest.mark.parametrize("name", ["MAP_SCRIPT", "API_SCRIPT", "SERVER_SCRIPT", "MANIFEST"])
    def test_declared_scripts_are_absolute(self, name):
        # A relative script path would resolve against whatever cwd the panel
        # happened to be started in.
        assert Path(getattr(mp, name)).is_absolute()

    def test_generated_files_are_all_inside_the_repo(self):
        for path in mp.GENERATED:
            assert Path(path).is_relative_to(REPO) if hasattr(Path, "is_relative_to") \
                else str(path).startswith(str(REPO))