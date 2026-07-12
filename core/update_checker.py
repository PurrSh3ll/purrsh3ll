"""Update checking for PurrSh3ll.

Read-only version check — it never touches the working tree, so a user's saved
settings and data are never at risk (see the update analysis: the only safe
update path today is "notify, don't pull").

Strategy (Method B + fallback):
  1. Local version  : nearest git tag reachable from HEAD (`git describe`),
                      falling back to the ``__version__`` constant below when the
                      install has no ``.git`` (e.g. someone unzipped a release).
  2. Latest version : newest ``v*`` tag on the remote via ``git ls-remote``
                      (no GitHub API, no token, no rate limit), falling back to
                      the GitHub Tags REST API when git is unavailable.

The comparison itself uses ``packaging.version`` so ``1.10.0`` correctly sorts
above ``1.9.0``.
"""

import logging
import os
import shutil
import subprocess

from PyQt6.QtCore import QThread, pyqtSignal

logger = logging.getLogger(__name__)

# Fallback local version used only when the install has no git metadata.
# Keep this in step with the window title / release tags.
__version__ = "1.3.0"

REPO_OWNER = "PurrSh3ll"
REPO_NAME = "purrsh3ll"
REPO_URL = f"https://github.com/{REPO_OWNER}/{REPO_NAME}.git"
RELEASES_URL = f"https://github.com/{REPO_OWNER}/{REPO_NAME}/releases"
API_TAGS_URL = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/tags"

_GIT_TIMEOUT = 8      # seconds — local git and ls-remote
_HTTP_TIMEOUT = 6     # seconds — API fallback


def _git_exe() -> str | None:
    return shutil.which("git")


def _normalize(tag: str) -> str:
    """Strip a leading ``v`` and surrounding whitespace from a tag name."""
    return tag.strip().lstrip("vV").strip()


def _parse(tag: str):
    """Return a comparable Version, or None if the tag is not PEP 440-ish."""
    try:
        from packaging.version import Version, InvalidVersion
    except Exception:  # packaging always ships in the venv; be defensive anyway
        return None
    try:
        return Version(_normalize(tag))
    except Exception:
        return None


def _highest_tag(tags):
    """Pick the highest version tag from an iterable of raw tag strings."""
    best_raw, best_ver = None, None
    for raw in tags:
        raw = raw.strip()
        if not raw:
            continue
        ver = _parse(raw)
        if ver is None:
            continue
        if best_ver is None or ver > best_ver:
            best_raw, best_ver = raw, ver
    return best_raw


def get_local_version(base_path: str) -> str:
    """Nearest tag reachable from HEAD, or the bundled ``__version__``."""
    git = _git_exe()
    if git and os.path.isdir(os.path.join(base_path, ".git")):
        try:
            out = subprocess.run(
                [git, "-C", base_path, "describe", "--tags", "--abbrev=0"],
                capture_output=True, text=True, timeout=_GIT_TIMEOUT,
            )
            tag = out.stdout.strip()
            if out.returncode == 0 and tag:
                return _normalize(tag)
        except Exception:
            logger.debug("git describe failed", exc_info=True)
    return _normalize(__version__)


def _remote_version_via_git(base_path: str) -> str | None:
    git = _git_exe()
    if not git or not os.path.isdir(os.path.join(base_path, ".git")):
        return None
    try:
        out = subprocess.run(
            [git, "-C", base_path, "ls-remote", "--tags", REPO_URL, "refs/tags/v*"],
            capture_output=True, text=True, timeout=_GIT_TIMEOUT,
        )
        if out.returncode != 0:
            return None
        tags = []
        for line in out.stdout.splitlines():
            parts = line.split("refs/tags/")
            if len(parts) == 2:
                # Drop the dereferenced-tag suffix (e.g. "v1.1.0^{}").
                tags.append(parts[1].replace("^{}", ""))
        return _highest_tag(tags)
    except Exception:
        logger.debug("git ls-remote failed", exc_info=True)
        return None


def _remote_version_via_api() -> str | None:
    try:
        import requests
    except Exception:
        return None
    try:
        resp = requests.get(
            API_TAGS_URL,
            timeout=_HTTP_TIMEOUT,
            headers={"Accept": "application/vnd.github+json"},
        )
        if resp.status_code != 200:
            logger.debug("GitHub tags API returned %s", resp.status_code)
            return None
        names = [item.get("name", "") for item in resp.json()]
        return _highest_tag(names)
    except Exception:
        logger.debug("GitHub tags API request failed", exc_info=True)
        return None


def get_remote_version(base_path: str) -> str | None:
    """Newest ``v*`` tag on the remote (git first, REST API fallback)."""
    remote = _remote_version_via_git(base_path)
    if remote:
        return _normalize(remote)
    remote = _remote_version_via_api()
    return _normalize(remote) if remote else None


def check_for_updates(base_path: str) -> dict:
    """Blocking check. Meant to be called from a worker thread.

    Returns a dict with:
        status : "up_to_date" | "update_available" | "unknown" | "error"
        local  : local version string (may be None)
        latest : latest remote version string (may be None)
    """
    local = get_local_version(base_path)
    latest = get_remote_version(base_path)

    if not latest:
        return {"status": "error", "local": local, "latest": None}

    local_ver, latest_ver = _parse(local), _parse(latest)
    if local_ver is not None and latest_ver is not None:
        status = "update_available" if latest_ver > local_ver else "up_to_date"
    else:
        # Can't parse one side — compare normalized strings as a last resort.
        status = "update_available" if _normalize(local) != _normalize(latest) else "unknown"
    return {"status": status, "local": local, "latest": latest}


class UpdateCheckWorker(QThread):
    """Runs :func:`check_for_updates` off the GUI thread."""

    result = pyqtSignal(dict)

    def __init__(self, base_path: str, parent=None):
        super().__init__(parent)
        self.base_path = base_path

    def run(self):
        try:
            self.result.emit(check_for_updates(self.base_path))
        except Exception as e:
            logger.debug("update check worker crashed", exc_info=True)
            self.result.emit({"status": "error", "local": None, "latest": None, "error": str(e)})
