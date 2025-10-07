"""Pytest configuration and shared fixtures."""

import pytest
import os
from dotenv import load_dotenv

# Load environment variables for testing
load_dotenv()


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Set up test environment."""
    # Set test environment variables if needed
    os.environ.setdefault("LOG_LEVEL", "DEBUG")
    os.environ.setdefault("TEMPERATURE", "0.0")
    
    yield
    
    # Cleanup after tests
    pass
