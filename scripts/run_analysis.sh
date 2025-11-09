#!/bin/bash

set -e

BINARY_PATH="samples/"
BUILD_DIR="build"

if [ ! -d "$BUILD_DIR" ]; then
    echo "Build directory not found. Running CMake..."
    mkdir "$BUILD_DIR"
    (cd "$BUILD_DIR" && cmake ..)
else
    echo "Build directory found."
fi

echo "Building project..."
(cd "$BUILD_DIR" && make re_assistant)

echo "Running RE-Assistant on $BINARY_PATH..."
"$BUILD_DIR/src/re_assistant" "$BINARY_PATH"

echo "Script finished."