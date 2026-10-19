"""Make the project's Python packages importable from unit/.

The modules under test - panel, mega, malapi_pipeline, yara_gen - all live at
the repository root or under python/, and each resolves its own paths relative to
__file__. So the only thing needed here is the two roots on sys.path; nothing
else about the import machinery has to be faked.

Kept separate from a pytest.ini / pyproject entry so the suite runs identically
whether it is invoked from the repo root, from unit/python, or by the panel's
"Run tests" button.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

for _root in (REPO, REPO / "python"):
    _path = str(_root)
    if _path not in sys.path:
        sys.path.insert(0, _path)