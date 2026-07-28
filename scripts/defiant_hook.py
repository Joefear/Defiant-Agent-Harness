"""Repository-local launcher for the Defiant agent hook."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from defiant_agent_harness.hooks.copilot import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
