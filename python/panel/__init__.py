"""Admin orchestration panel - Flask backend.

    python python/admin_server.py

A thin proxy over services that already exist in this repo. Nothing here
reimplements analysis logic or duplicates a probe: every endpoint forwards to
a real service API or reads a real artefact on disk.

One import rule, because getting it wrong is expensive: modules under this
package are NEVER imported for their side effects. Specifically, do not import
`panel` anything that pulls in `_configure_qiling.py`, `scan_remote.py` or
`_collect_clamd_artifacts.py` - the first calls full_pipeline() at module
scope (no __main__ guard), so importing it opens an SSH session to the analysis
VM and pushes a 116 MB rootfs. Those are subprocess-only.
"""

__all__ = ["config", "services", "app"]