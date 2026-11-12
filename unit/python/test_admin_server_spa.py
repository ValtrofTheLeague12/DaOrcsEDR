"""The SPA fallback must not let a browser keep yesterday's build.

Vite writes hashed asset names, so a chunk is safe to cache forever - but
index.html names which hashes are current. Letting that one be cached is
what makes a rebuilt dashboard keep showing the old CSS and old panels until
someone clears the cache by hand.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python"))

import admin_server  # noqa: E402
from flask import Flask  # noqa: E402


def _client(tmp_path):
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html><div id=root></div>",
                                     encoding="utf-8")
    (dist / "assets" / "app-abc123.js").write_text("console.log(1)",
                                                   encoding="utf-8")
    (dist / "assets" / "app-abc123.css").write_text(":root{}", encoding="utf-8")
    app = Flask(__name__)
    admin_server._serve_spa(app, dist)
    return app.test_client()


def test_index_is_never_cached(tmp_path):
    response = _client(tmp_path).get("/")
    assert response.status_code == 200
    assert "no-store" in response.headers["Cache-Control"]


def test_a_deep_link_falls_back_to_an_uncached_index(tmp_path):
    response = _client(tmp_path).get("/panel/threat-intelligence")
    assert response.status_code == 200
    assert "no-store" in response.headers["Cache-Control"]


def test_hashed_assets_may_be_cached_forever(tmp_path):
    client = _client(tmp_path)
    for name in ("app-abc123.js", "app-abc123.css"):
        response = client.get(f"/assets/{name}")
        assert response.status_code == 200
        assert "immutable" in response.headers["Cache-Control"]
