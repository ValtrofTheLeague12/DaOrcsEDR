"""Unit tests for the Containers panel's endpoint join.

The Containers panel reads docker and never sees a service Spec, so "where do I
open this" has to be joined from what docker published. That join fails quietly:
an unmatched container simply omits the line and the reader goes back to the
compose file. A join that *guesses* is worse than one that finds nothing, so
these pin the three decisions rather than the shape of the code:

  - the published HOST port wins over the name, because it is the one thing
    that cannot drift from reality;
  - the name is still a fallback, because a container that does not exist yet
    has no ports row at all and its endpoint is the answer to "how do I start
    this";
  - no match is None, never a URL guessed from the image name.

`_specs` is replaced rather than the .env read underneath it. An operator's own
ports are not this test's business, and a test asserting a literal 60001 passes
on one machine and fails on another.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))

from panel.host import containers, services  # noqa: E402


@pytest.fixture
def index(monkeypatch) -> services.EndpointIndex:
    """A fixed set of specs: one HTTP API, one browser UI, one TCP broker.

    The three kinds because each is a different promise to the reader - two are
    openable in a browser, one is not, and the UI renders them differently.
    """
    specs = [
        services.Spec(key="cyberchef", name="CyberChef API",
                      description="", host="127.0.0.1", port=60001,
                      routes=("/bake", "/magic")),
        services.Spec(key="cyberchef-ui", name="CyberChef UI",
                      description="", host="127.0.0.1", port=8081,
                      health_path="/", ui_path="/"),
        services.Spec(key="kafka", name="Kafka broker",
                      description="", host="127.0.0.1", port=9092,
                      scheme="tcp", kind="tcp"),
    ]
    monkeypatch.setattr(services, "_specs", lambda: specs)
    return services.endpoint_index()


# --- the Ports column --------------------------------------------------------

class TestHostPorts:
    """docker publishes NAT mappings, not addresses. Only the host half is one."""

    def test_host_side_of_every_mapping(self):
        assert containers._host_ports([
            "127.0.0.1:60001->3000/tcp",
            "0.0.0.0:8081->8080/tcp",
            ":::61000->8080/tcp",
        ]) == [60001, 8081, 61000]

    def test_container_only_port_is_not_an_address(self):
        # "3000/tcp" says the port exists inside the container. It says nothing
        # about reaching it from the host, so it must not join to a service.
        assert containers._host_ports(["3000/tcp"]) == []

    def test_nothing_published(self):
        assert containers._host_ports([]) == []

    def test_ipv6_wildcard_keeps_its_port(self):
        # The triple colon is the trap: a naive split on ":" yields empty
        # strings and an empty host part, and the port goes with them.
        assert containers._host_ports([":::61000->8080/tcp"]) == [61000]


# --- the join ----------------------------------------------------------------

class TestResolve:
    def test_by_published_port(self, index):
        got = services.resolve(index, ports=[60001])
        assert got is not None
        assert got["key"] == "cyberchef"
        assert got["url"] == "http://127.0.0.1:60001/health"

    def test_by_name_when_nothing_is_published(self, index):
        # The not-yet-created container: no ports row, so the name is all there
        # is, and losing the endpoint here is losing "how do I start this".
        got = services.resolve(index, service="cyberchef-ui")
        assert got is not None
        assert got["url"] == "http://127.0.0.1:8081/"

    def test_compose_name_that_differs_from_the_key(self, index):
        # compose.yaml calls this service "cyberchef-api"; the panel's key is
        # "cyberchef". This is the one name in the repo that does not match, and
        # it is exactly the case a fuzzy match would have had to catch.
        got = services.resolve(index, service="cyberchef-api")
        assert got is not None
        assert got["key"] == "cyberchef"

    def test_port_beats_a_name_that_points_elsewhere(self, index):
        # Deliberately mismatched inputs. The port is what docker bound, so it
        # is the fact that cannot be stale, and it is what wins.
        got = services.resolve(index, ports=[8081], service="cyberchef")
        assert got is not None
        assert got["key"] == "cyberchef-ui"

    def test_a_tcp_service_keeps_its_kind(self, index):
        # The UI renders http as a link and tcp as text. Losing this would put a
        # link in front of a URL no browser can open.
        got = services.resolve(index, ports=[9092])
        assert got is not None
        assert got["kind"] == "tcp"
        assert got["url"] == "tcp://127.0.0.1:9092"

    def test_unknown_container_gets_nothing(self, index):
        # A one-off `podman run`, an image nobody wrote a spec for. None means
        # the card shows no endpoint; a guess means a wrong link that looks
        # authoritative.
        assert services.resolve(index, service="iaproject-clamav") is None
        assert services.resolve(index, ports=[5432]) is None
        assert services.resolve(index) is None

    def test_ui_url_only_where_a_page_exists(self, index):
        # The API publishes no page to open; the UI is nothing but its page.
        assert services.resolve(index, ports=[60001])["ui_url"] is None
        assert services.resolve(index, ports=[8081])["ui_url"] == "http://127.0.0.1:8081/"


class TestIndex:
    def test_unconfigured_optional_service_is_not_indexed(self, monkeypatch):
        # An absent vm_info.json is a setup state, not an outage. It has no
        # address, and indexing it would hand out host:0.
        specs = [
            services.Spec(key="qiling-vm", name="Analysis VM", description="",
                          host="", port=0, scheme="tcp", kind="tcp",
                          optional=True),
        ]
        monkeypatch.setattr(services, "_specs", lambda: specs)
        idx = services.endpoint_index()
        assert idx.by_port == {}
        assert services.resolve(idx, ports=[0]) is None

    def test_a_contested_port_is_deterministic(self, monkeypatch):
        # Two services on one port is a misconfiguration. It must not make the
        # page flicker between two different URLs on consecutive polls.
        specs = [
            services.Spec(key="first", name="First", description="",
                          host="127.0.0.1", port=60001),
            services.Spec(key="second", name="Second", description="",
                          host="127.0.0.1", port=60001),
        ]
        monkeypatch.setattr(services, "_specs", lambda: specs)
        assert services.endpoint_index().by_port[60001]["key"] == "first"