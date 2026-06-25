import os
import pytest

@pytest.fixture(scope="session")
def mock_db():
    """
    Skeleton fixture for DB integration tests.
    Runs only when TEST_DATABASE_URL points at a reachable Postgres
    (e.g. a throwaway container).

    Usage:
    export TEST_DATABASE_URL="postgresql://warp:warp@127.0.0.1:5432/warp_test"
    """
    if "TEST_DATABASE_URL" not in os.environ:
        pytest.skip("Integration tests disabled by default. Set TEST_DATABASE_URL to run them.")

    os.environ["DATABASE_URL"] = os.environ["TEST_DATABASE_URL"]

    yield
