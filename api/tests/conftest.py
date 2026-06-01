import os
import pytest

@pytest.fixture(scope="session")
def mock_db():
    """
    Skeleton fixture for DB integration tests.
    In the future, this can be configured to start a local postgres instance 
    or connect to a test Supabase project.
    
    Usage:
    export TEST_SUPABASE_URL="https://test.supabase.co"
    export TEST_SUPABASE_KEY="test_key"
    """
    if "TEST_SUPABASE_URL" not in os.environ:
        pytest.skip("Integration tests disabled by default. Set TEST_SUPABASE_URL to run them.")
    
    # Original config overriding for tests
    os.environ["SUPABASE_URL"] = os.environ["TEST_SUPABASE_URL"]
    os.environ["SUPABASE_KEY"] = os.environ["TEST_SUPABASE_KEY"]
    
    # You could also set up setup/teardown for test data here
    yield
    
    # cleanup
