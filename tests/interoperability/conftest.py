"""Fixtures for the interoperability suite.

The harness lives in tests/integration/conftest.py. Rather than duplicating it,
this module puts that directory on sys.path and re-exports the fixtures pytest
needs to see in this package.
"""

from __future__ import annotations

import sys
from pathlib import Path

INTEGRATION_DIR = Path(__file__).resolve().parent.parent / "integration"
if str(INTEGRATION_DIR) not in sys.path:
    sys.path.insert(0, str(INTEGRATION_DIR))

# Re-exported so pytest registers them as fixtures in this package too.
from conftest import (  # noqa: E402,F401
    capabilities,
    certs,
    pytest_configure,
    pytest_report_header,
    require_binaries,
)
