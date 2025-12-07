#!/bin/bash
set -e

# Ensure build directory exists
mkdir -p build
cd build

# Clear cache if needed (optional, but good for clean builds)
# rm -f CMakeCache.txt

# Configure and Build
cmake ..
make -j$(nproc)

echo "Build complete: build/messagebox"
