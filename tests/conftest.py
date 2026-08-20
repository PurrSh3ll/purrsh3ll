"""Shared pytest configuration for the PurrSh3ll test suite.

The application is not installed as a package and several of its modules live in
flat directories that are imported by filename at runtime (the terminal tools in
``appdata/terminal_modules`` and the MCP servers in ``appdata/mcp_servers``).
To import those modules from tests exactly the way the app does, we put those
directories — plus the project root — on ``sys.path`` here, once, for every test.

This touches nothing in the application itself; it only affects how tests
resolve imports.
"""

import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Order matters: project root first (so ``core.*`` / ``file_loaders.*`` packages
# import normally), then the flat tool/server dirs for bare ``import toolkit_server``.
_EXTRA_PATHS = [
    PROJECT_ROOT,
    os.path.join(PROJECT_ROOT, "appdata", "terminal_modules"),
    os.path.join(PROJECT_ROOT, "appdata", "mcp_servers"),
]

for _p in _EXTRA_PATHS:
    if _p not in sys.path:
        sys.path.insert(0, _p)
