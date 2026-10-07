"""Share the explicit completed-build input between package functional suites."""

from pathlib import Path

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    """Expose build selection without requiring it for tests that do not consume a build."""
    parser.addoption("--build-dir", type=Path, help="Existing completed Release build for package functional tests")


@pytest.fixture(scope="session")
def package_build_directory(pytestconfig: pytest.Config) -> Path:
    """Resolve the required configured build; consuming fixtures verify their artifacts."""
    selected = pytestconfig.getoption("build_dir")
    if selected is None:
        pytest.exit("package functional tests require --build-dir", returncode=pytest.ExitCode.USAGE_ERROR)
    try:
        build_dir = selected.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        pytest.exit(f"cannot resolve --build-dir: {exc}", returncode=pytest.ExitCode.USAGE_ERROR)
    if not (build_dir / "CMakeCache.txt").is_file():
        pytest.exit("--build-dir must name an existing configured build", returncode=pytest.ExitCode.USAGE_ERROR)
    return build_dir
