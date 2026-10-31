"""Unit tests for the panel's GPU inventory merge.

`panel.host.system.gpu()` folds two independent sources into one row per card:

  * `_video_controllers()` - CIM/Win32_VideoController, the inventory side
    (name, driver, mode). Read by shelling out to PowerShell.
  * `_nvidia()` - nvidia-smi, the live side (utilisation, VRAM, temperature,
    power). Read by shelling out to a second process.

Those two sources are independent, and that is the whole point of the tests
here. The merge used to spread the matched CIM adapter unconditionally:

    merged.append({**adapter, **dev, ...})

`_match_adapter()` returns None whenever CIM did not answer at all (the
PowerShell call timed out, or returned something that is not JSON) or simply
named the card differently. Spreading None raises

    TypeError: 'NoneType' object is not a mapping

which took down the whole of /api/system - not just the GPU section - because
`system.info()` calls `gpu()` directly. One unreadable CIM query meant a blank
System page, and the traceback pointed at a dict literal rather than at the
missing adapter.

The tests pin the behaviour of every branch, because the failure mode is
"works on the developer's box, dies on the operator's": on a machine where the
two names happen to agree, the crash is unreachable and the suite would be
green while the panel is broken.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))

from panel.host import system  # noqa: E402


def _adapter(name: str, driver: str = "1.2.3") -> dict:
    """A row shaped like `_video_controllers()` output."""
    return {
        "name": name,
        "vendor": "NVIDIA",
        "driver_version": driver,
        "mode": None,
        "status": "OK",
        "vram_bytes": 4293918720,
        "vram_source": "wmi-adapterram-approx",
    }


def _device(name: str, total_bytes: int = 4294967296) -> dict:
    """A row shaped like `_nvidia()` output."""
    return {
        "name": name,
        "memory_used_bytes": 425721856,
        "memory_total_bytes": total_bytes,
        "memory_percent": 9.9,
        "utilization_percent": 14.0,
        "memory_utilization_percent": 0.0,
        "temperature_c": 57,
        "power_draw_w": 12.33,
        "power_limit_w": None,
        "clock_mhz": 1500,
    }


@pytest.fixture
def gpu_sources(monkeypatch):
    """Replace both sources and drop the cache, per test.

    gpu() memoises for _GPU_CACHE_TTL, so without clearing it the second test
    would assert against the first test's payload.
    """

    def _install(adapters, devices):
        monkeypatch.setattr(system, "_video_controllers", lambda: adapters)
        monkeypatch.setattr(system, "_nvidia", lambda: devices)
        monkeypatch.setitem(system._gpu_cache, "payload", None)
        monkeypatch.setitem(system._gpu_cache, "at", 0.0)

    return _install


# ---------------------------------------------------------------------------
# The regression
# ---------------------------------------------------------------------------

def test_no_cim_adapters_does_not_raise(gpu_sources):
    """CIM unreadable while nvidia-smi answers: the reported crash.

    This is the exact shape that produced the traceback - PowerShell timed out,
    so `_video_controllers()` returned [], while the driver was perfectly able
    to answer nvidia-smi.
    """
    gpu_sources([], [_device("NVIDIA GeForce RTX 3050 Laptop GPU")])

    payload = system.gpu()  # must not raise

    assert payload["available"] is True
    assert payload["count"] == 1
    assert payload["live_count"] == 1


def test_unmatched_device_keeps_its_live_metrics(gpu_sources):
    """A card CIM did not name still gets a row, with the live half intact.

    The live numbers are the more valuable half of the merge, so losing them
    because the inventory half was missing would trade one bug for another.
    """
    gpu_sources([], [_device("NVIDIA GeForce RTX 3050 Laptop GPU")])

    row = system.gpu()["adapters"][0]

    assert row["name"] == "NVIDIA GeForce RTX 3050 Laptop GPU"
    assert row["live"] is True
    assert row["utilization_percent"] == 14.0
    assert row["temperature_c"] == 57
    assert row["vram_bytes"] == 4294967296
    assert row["vram_source"] == "nvidia-smi"


def test_unmatched_device_reports_no_driver_rather_than_omitting_it(gpu_sources):
    """`driver_version` is present and None, not absent.

    The UI distinguishes "no driver version reported" from a field that was
    never sent; a missing key would render as an empty cell either way but
    would break a consumer that reads it directly.
    """
    gpu_sources([], [_device("NVIDIA GeForce RTX 3050 Laptop GPU")])

    row = system.gpu()["adapters"][0]

    assert "driver_version" in row
    assert row["driver_version"] is None


def test_differently_named_device_and_adapter_both_appear(gpu_sources):
    """A name CIM and nvidia-smi disagree on yields two rows, not a crash.

    Loose prefix matching usually pairs the card, but a driver suffix or a
    vendor prefix it does not anticipate is a legitimate miss. The device row
    and the inventory row are then both true and both kept.
    """
    gpu_sources([_adapter("Some Vendor Adapter XYZ")],
                [_device("NVIDIA GeForce RTX 3050 Laptop GPU")])

    payload = system.gpu()

    assert payload["count"] == 2
    assert payload["live_count"] == 1
    live = [r for r in payload["adapters"] if r["live"]]
    inventory = [r for r in payload["adapters"] if not r["live"]]
    assert [r["name"] for r in live] == ["NVIDIA GeForce RTX 3050 Laptop GPU"]
    assert [r["name"] for r in inventory] == ["Some Vendor Adapter XYZ"]


# ---------------------------------------------------------------------------
# The merge itself, which must not regress while fixing the crash
# ---------------------------------------------------------------------------

def test_matched_adapter_is_folded_into_one_row(gpu_sources):
    """The happy path still merges: one row per card, inventory + live."""
    gpu_sources([_adapter("NVIDIA GeForce RTX 3050 Laptop GPU")],
                [_device("NVIDIA GeForce RTX 3050 Laptop GPU")])

    payload = system.gpu()

    assert payload["count"] == 1
    assert payload["live_count"] == 1
    row = payload["adapters"][0]
    assert row["live"] is True
    assert row["status"] == "OK"                  # from the adapter
    assert row["utilization_percent"] == 14.0     # from the device
    assert row["driver_version"] == "1.2.3"


def test_nvidia_smi_vram_wins_over_the_cim_uint32(gpu_sources):
    """VRAM comes from nvidia-smi, not the clamped CIM AdapterRAM.

    AdapterRAM is a uint32, so it caps at 4 GB and is wrong for anything
    larger. The module says nvidia-smi is authoritative; this pins that.
    """
    big = 12 * 1024 * 1024 * 1024
    gpu_sources([_adapter("NVIDIA GeForce RTX 3050 Laptop GPU")],
                [_device("NVIDIA GeForce RTX 3050 Laptop GPU", total_bytes=big)])

    row = system.gpu()["adapters"][0]

    assert row["vram_bytes"] == big
    assert row["vram_source"] == "nvidia-smi"
    assert row["vram_bytes"] != 4293918720


def test_igpu_without_nvidia_metrics_is_inventory_only(gpu_sources):
    """An Intel/AMD adapter nvidia-smi never mentions is listed, live=False."""
    gpu_sources([_adapter("AMD Radeon(TM) Graphics", driver="31.0.21924.61")], [])

    payload = system.gpu()

    assert payload["count"] == 1
    assert payload["live_count"] == 0
    row = payload["adapters"][0]
    assert row["live"] is False
    assert row["vram_source"] == "wmi-adapterram-approx"
    assert row["driver_version"] == "31.0.21924.61"


def test_no_sources_at_all_reports_unavailable(gpu_sources):
    """Neither side answering is an empty inventory, not an error.

    A box with no readable display adapter must still serve /api/system.
    """
    gpu_sources([], [])

    payload = system.gpu()

    assert payload["available"] is False
    assert payload["count"] == 0
    assert payload["live_count"] == 0
    assert "Windows" in payload["note"]


def test_note_mentions_nvidia_when_anything_is_listed(gpu_sources):
    """The note explains why a non-NVIDIA card shows no live numbers."""
    gpu_sources([_adapter("AMD Radeon(TM) Graphics")], [])

    note = system.gpu()["note"]

    assert "nvidia-smi" in note


# ---------------------------------------------------------------------------
# _match_adapter's contract, since the crash was a None it legitimately returns
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("device_name, adapter_name, expected", [
    ("NVIDIA GeForce RTX 3050 Laptop GPU", "NVIDIA GeForce RTX 3050 Laptop GPU", True),
    # Case and surrounding whitespace are normalised before comparing.
    ("nvidia geforce rtx 3050", "NVIDIA GeForce RTX 3050 Laptop GPU", True),
    # Prefix containment in either direction is the documented matching rule.
    ("NVIDIA GeForce RTX 3050", "NVIDIA GeForce RTX 3050 Laptop GPU", True),
    ("NVIDIA GeForce RTX 3050 Laptop GPU", "NVIDIA GeForce RTX 3050", True),
    # A genuine miss is the input that used to crash gpu().
    ("NVIDIA GeForce RTX 3050", "AMD Radeon(TM) Graphics", False),
])
def test_match_adapter_pairing(device_name, adapter_name, expected):
    device = {"name": device_name}
    adapters = [{"name": adapter_name}]

    matched = system._match_adapter(device, adapters)

    assert (matched is not None) is expected


def test_match_adapter_returns_none_for_a_nameless_device():
    """No name cannot prefix-match anything, so it must not match adapter #1."""
    assert system._match_adapter({"name": ""}, [{"name": "Anything"}]) is None
    assert system._match_adapter({}, [{"name": "Anything"}]) is None


def test_match_adapter_returns_none_with_no_adapters():
    """The empty-inventory case, which is what makes `adapter or {}` load-bearing."""
    assert system._match_adapter({"name": "NVIDIA GeForce RTX 3050"}, []) is None
