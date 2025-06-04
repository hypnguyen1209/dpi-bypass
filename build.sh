#!/bin/bash

# Cross-compilation script for DPI bypass tool
set -e

# Get the directory of the script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

# Ensure dependencies are downloaded
echo "Downloading dependencies..."
go mod tidy

# Supported platforms
PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
    "windows/arm64"
)

OUTPUT="dpi-bypass"

# Build for each platform
for PLATFORM in "${PLATFORMS[@]}"; do
    GOOS=${PLATFORM%/*}
    GOARCH=${PLATFORM#*/}
    
    echo "Building for $GOOS/$GOARCH..."
    GOOS=$GOOS GOARCH=$GOARCH go build -o "build/${OUTPUT}_${GOOS}-${GOARCH}" .
    if [ "$GOOS" == "windows" ]; then
        GOOS=$GOOS GOARCH=$GOARCH go build -o "build/${OUTPUT}_${GOOS}-${GOARCH}.exe" .
    fi
    
    echo "Created build/${OUTPUT}_${GOOS}-${GOARCH}"
done

echo "All builds completed successfully!"
