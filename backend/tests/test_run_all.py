"""Run all tests - Main test runner"""
import pytest
import sys

if __name__ == "__main__":
    # Run all tests with verbose output
    exit_code = pytest.main(["-v", "--tb=short", "tests/"])
    sys.exit(exit_code)

