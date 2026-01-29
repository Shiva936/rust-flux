#!/bin/bash

# Simple validation script that checks code structure without compiling

echo "Validating rust-flux project structure..."
echo ""

ERRORS=0

# Check if all source files exist
echo "Checking source files..."
for file in src/main.rs src/config.rs src/server.rs src/proxy.rs src/auth.rs src/rate_limit.rs src/observability.rs; do
    if [ -f "$file" ]; then
        echo "  ✓ $file"
    else
        echo "  ✗ Missing: $file"
        ERRORS=$((ERRORS + 1))
    fi
done

# Check if config file exists
echo ""
echo "Checking configuration..."
if [ -f "config/config.yaml" ]; then
    echo "  ✓ config/config.yaml"
else
    echo "  ✗ Missing: config/config.yaml"
    ERRORS=$((ERRORS + 1))
fi

# Check if Cargo.toml exists
echo ""
echo "Checking project files..."
if [ -f "Cargo.toml" ]; then
    echo "  ✓ Cargo.toml"
else
    echo "  ✗ Missing: Cargo.toml"
    ERRORS=$((ERRORS + 1))
fi

# Check if Docker files exist
echo ""
echo "Checking Docker files..."
if [ -f "Dockerfile" ]; then
    echo "  ✓ Dockerfile"
else
    echo "  ✗ Missing: Dockerfile"
    ERRORS=$((ERRORS + 1))
fi

if [ -f "docker-compose.yml" ]; then
    echo "  ✓ docker-compose.yml"
else
    echo "  ✗ Missing: docker-compose.yml"
    ERRORS=$((ERRORS + 1))
fi

# Check if test files exist
echo ""
echo "Checking test files..."
if [ -f "tests/integration_test.rs" ]; then
    echo "  ✓ tests/integration_test.rs"
else
    echo "  ✗ Missing: tests/integration_test.rs"
    ERRORS=$((ERRORS + 1))
fi

# Summary
echo ""
if [ $ERRORS -eq 0 ]; then
    echo "✓ All files present. Project structure looks good!"
    echo ""
    echo "Next steps:"
    echo "  1. Install Rust: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    echo "  2. Run: ./run_tests.sh"
    echo "  3. Or use Docker: docker-compose up --build"
    exit 0
else
    echo "✗ Found $ERRORS missing file(s)"
    exit 1
fi
