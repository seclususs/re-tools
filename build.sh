#!/bin/bash
set -e

echo "=================================================="
echo "              Builder (Linux)                     "
echo "=================================================="

command -v cargo >/dev/null 2>&1 || { echo >&2 "[Error] 'cargo' not found."; exit 1; }
command -v cmake >/dev/null 2>&1 || { echo >&2 "[Error] 'cmake' not found."; exit 1; }

echo ""
echo "Select Compiler (Will perform a clean build):"
echo " [1] Default (cc/c++)"
echo " [2] Clang   (clang/clang++)"
echo " [3] GCC     (gcc/g++)"
echo ""
read -p "Enter choice [1-3]: " choice
case $choice in
    2)
        export CC=clang
        export CXX=clang++
        echo "[Setup] Toolchain: Clang"
        ;;
    3)
        export CC=gcc
        export CXX=g++
        echo "[Setup] Toolchain: GCC"
        ;;
    *)
        echo "[Setup] Toolchain: System Default"
        ;;
esac

echo ""
echo "[1/4] Cleaning artifacts..."
if [ -d "build" ]; then
    echo "   - Removing 'build' directory..."
    rm -rf build
fi
mkdir build

echo ""
echo "[2/4] Building Rust Core..."
cd core
cargo build --release
cd ..

echo ""
echo "[3/4] Configuring CMake..."
cd build
if command -v ninja >/dev/null 2>&1; then
    CMAKE_GEN="-G Ninja"
else
    CMAKE_GEN=""
fi
cmake .. $CMAKE_GEN -DCMAKE_BUILD_TYPE=Release

echo ""
echo "[4/4] Compiling C++ CLI..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    CORES=$(sysctl -n hw.ncpu)
else
    CORES=$(nproc)
fi
cmake --build . --config Release --parallel $CORES
echo ""
echo "=================================================="
echo " BUILD SUCCESSFUL"
echo "=================================================="
echo " Binary: ./build/bin/retools_cli"
echo "=================================================="