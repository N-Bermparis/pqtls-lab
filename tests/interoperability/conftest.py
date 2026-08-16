"""Fixtures for the interoperability suite.

The shared test harness lives in tests/integration/conftest.py.  It is loaded
under a unique module name so that this conftest does not recursively import
itself as the top-level ``conftest`` module.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


INTEGRATION_CONFTEST = (
    Path(__file__).resolve().parent.parent / "integration" / "conftest.py"
)

_MODULE_NAME = "pqtls_integration_conftest"

_spec = importlib.util.spec_from_file_location(
    _MODULE_NAME,
    INTEGRATION_CONFTEST,
)

if _spec is None or _spec.loader is None:
    raise ImportError(
        f"could not load integration test harness from {INTEGRATION_CONFTEST}"
    )

_integration = importlib.util.module_from_spec(_spec)

# Required for classes/dataclasses and other code that resolves its module
# through sys.modules while the file is being executed.
sys.modules[_MODULE_NAME] = _integration

_spec.loader.exec_module(_integration)

# Re-export the integration harness.  This keeps the existing interoperability
# tests that use `from conftest import ...` working without duplicating helpers.
for _name in dir(_integration):
    if not _name.startswith("_"):
        globals()[_name] = getattr(_integration, _name)
