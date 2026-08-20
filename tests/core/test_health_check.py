"""Tests for the startup dependency probe (core/health_check).

The probe inspects system tools/libs (environment-dependent) plus runtime paths
(which we control via base_path). We assert the result's structure, the
deterministic path logic and the "missing" list, and that optional
tools/libraries are never counted as degraded — without asserting anything about
which real binaries happen to be installed on the test host.
"""

from core import health_check as hc


# --------------------------------------------------------------------------- #
# _lib_available
# --------------------------------------------------------------------------- #
def test_lib_available_true_for_stdlib():
    assert hc._lib_available("json") is True
    assert hc._lib_available("os") is True


def test_lib_available_false_for_missing():
    assert hc._lib_available("no_such_module_xyz_123") is False


# --------------------------------------------------------------------------- #
# run_health_check — structure
# --------------------------------------------------------------------------- #
def test_result_has_expected_shape(tmp_path):
    res = hc.run_health_check(str(tmp_path))
    for key in ("tools", "optional_tools", "terminal", "libs",
                "optional_libs", "paths", "missing"):
        assert key in res
    assert isinstance(res["missing"], list)
    # Probed names match the module's declared sets.
    assert set(res["tools"]) == {n for n, _ in hc._TOOLS}
    assert set(res["libs"]) == {n for n, _ in hc._LIBS}


# --------------------------------------------------------------------------- #
# run_health_check — path logic (deterministic via base_path)
# --------------------------------------------------------------------------- #
def test_missing_paths_reported_when_appdata_absent(tmp_path):
    res = hc.run_health_check(str(tmp_path))     # no appdata tree
    assert res["paths"]["appdata writable"] is False
    assert res["paths"]["config readable"] is False
    assert any("appdata writable" in m for m in res["missing"])


def test_paths_ok_when_tree_present(tmp_path):
    appdata = tmp_path / "appdata"
    (appdata / "logs").mkdir(parents=True)
    (appdata / "app_config.json").write_text("{}")
    res = hc.run_health_check(str(tmp_path))
    assert res["paths"]["appdata writable"] is True
    assert res["paths"]["logs writable"] is True
    assert res["paths"]["config readable"] is True
    assert not any(m.startswith("path:") for m in res["missing"])


# --------------------------------------------------------------------------- #
# optional deps are never counted as degraded
# --------------------------------------------------------------------------- #
def test_optional_deps_not_in_missing(tmp_path):
    res = hc.run_health_check(str(tmp_path))
    optional_names = ({n for n, _ in hc._OPTIONAL_TOOLS}
                      | {n for n, _ in hc._OPTIONAL_LIBS})
    for name in optional_names:
        assert not any(name in m for m in res["missing"])


# --------------------------------------------------------------------------- #
# log_health_summary smoke
# --------------------------------------------------------------------------- #
def test_log_health_summary_returns_result(tmp_path):
    res = hc.log_health_summary(str(tmp_path))
    assert isinstance(res, dict) and "missing" in res
