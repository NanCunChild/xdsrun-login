#!/bin/bash
APP_NAME="xdsrun"

TARGETS=(
    "windows/amd64"
    "linux/amd64"
    "linux/arm/7"
    "linux/arm64"
    "linux/mipsle"
    "linux/riscv64"
    "linux/loong64"
    "darwin/amd64" # macOS Intel
    "darwin/arm64" # macOS Apple Silicon
)

mkdir -p build

for target in "${TARGETS[@]}"; do
    IFS='/' read -r GOOS GOARCH GOARM <<< "$target"

    OUTPUT_NAME="build/${APP_NAME}-${GOOS}-${GOARCH}"
    if [ ! -z "$GOARM" ]; then
        OUTPUT_NAME="${OUTPUT_NAME}v${GOARM}"
    fi
    if [ "$GOOS" = "windows" ]; then
        OUTPUT_NAME="${OUTPUT_NAME}.exe"
    fi

    echo "Building for ${GOOS}/${GOARCH}..."
    
    env GOOS=$GOOS GOARCH=$GOARCH GOARM=$GOARM CGO_ENABLED=0 go build -o $OUTPUT_NAME .

    if [ $? -eq 0 ]; then
        echo "Successfully built ${OUTPUT_NAME}"
    else
        echo "Failed to build for ${GOOS}/${GOARCH}"
    fi
done

echo "All builds completed."