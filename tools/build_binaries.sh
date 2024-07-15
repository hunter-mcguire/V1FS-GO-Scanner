#!/bin/bash

# Set the name of your main Go file
MAIN_FILE="../main.go"
OUTPUT_DIR="bin"

# Check if Go is installed
if ! command -v go &> /dev/null
then
    echo "Go is not installed. Please install Go and try again."
    exit 1
fi

# Ensure the output directory exists
mkdir -p $OUTPUT_DIR

# Build for Linux
echo "Building for Linux..."
GOOS=linux GOARCH=amd64 go build -o $OUTPUT_DIR/v1_fs_scanner_linux $MAIN_FILE
if [ $? -eq 0 ]; then
    echo "Linux build completed successfully."
else
    echo "Linux build failed."
fi

# Build for Windows
echo "Building for Windows..."
GOOS=windows GOARCH=amd64 go build -o $OUTPUT_DIR/v1_fs_scanner_windows.exe $MAIN_FILE
if [ $? -eq 0 ]; then
    echo "Windows build completed successfully."
else
    echo "Windows build failed."
fi

# Build for macOS
echo "Building for macOS..."
GOOS=darwin GOARCH=amd64 go build -o $OUTPUT_DIR/v1_fs_scanner_macos $MAIN_FILE
if [ $? -eq 0 ]; then
    echo "macOS build completed successfully."
else
    echo "macOS build failed."
fi

# Build for macOS ARM
echo "Building for macOS ARM..."
GOOS=darwin GOARCH=arm64 go build -o $OUTPUT_DIR/v1_fs_scanner_macos-arm $MAIN_FILE
if [ $? -eq 0 ]; then
    echo "macOS ARM build completed successfully."
else
    echo "macOS ARM build failed."
fi
