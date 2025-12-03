#!/bin/bash
# Test runner script

echo "🧪 Running Honeypot Platform Tests"
echo "===================================="

# Run all tests
pytest tests/ -v --tb=short

# Run with coverage (if pytest-cov is installed)
# pytest tests/ -v --cov=app --cov-report=html

echo ""
echo "✅ Tests completed!"

