#!/usr/bin/env python3
"""purragent entry point — thin launcher; logic lives in the purragent_core package."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from purragent_core.repl import main  # noqa: E402

if __name__ == "__main__":
    main()
