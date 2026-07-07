"""Launch external openers without leaking their stdio onto the console.

``xdg-open``, ``webbrowser.open`` and ``QDesktopServices.openUrl`` all fork a
child that inherits PurrSh3ll's stdout/stderr (fd 1/2), so a noisy handler
prints straight to the launching terminal. The most common offender is Firefox
under software rendering in a VM, which spams ``[GFX1-]: RenderCompositorSWGL
failed mapping default framebuffer …`` on startup.

Routing the child's stdio to ``/dev/null`` in a detached session
(``start_new_session=True``) keeps the console clean without affecting the
opened application.
"""

import logging
import os
import shutil
import subprocess

logger = logging.getLogger(__name__)


def _spawn(target: str) -> bool:
    """Open ``target`` (path or URL) via xdg-open, detached and silenced."""
    opener = shutil.which("xdg-open")
    if not opener:
        logger.debug("xdg-open not found; cannot open %s", target)
        return False
    try:
        subprocess.Popen(
            [opener, target],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        return True
    except Exception:
        logger.debug("failed to launch xdg-open for %s", target, exc_info=True)
        return False


def open_path(path) -> bool:
    """Open a local file or directory with the system default handler."""
    return _spawn(os.fspath(path))


def open_url(url) -> bool:
    """Open an http(s) (or other) URL with the system default handler."""
    return _spawn(str(url))
