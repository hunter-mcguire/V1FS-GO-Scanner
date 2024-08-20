#!/bin/bash
 
# Set the name of your main Go file
MAIN_FILE="../main.go"
OUTPUT_DIR="bin"
 
# Ensure the output directory exists
mkdir -p $OUTPUT_DIR
 
# Build for Linux amd64
echo "Building for Linux amd64..."
GOOS=linux GOARCH=amd64 go build -o $OUTPUT_DIR/v1_fs_scanner_linux $MAIN_FILE
 
# Build for Linux arm
echo "Building for Linux ARM..."
GOOS=linux GOARCH=arm64 go build -o $OUTPUT_DIR/v1_fs_scanner_linux_arm $MAIN_FILE
 
# Build for Windows
echo "Building for Windows..."
GOOS=windows GOARCH=amd64 go build -o $OUTPUT_DIR/v1_fs_scanner_windows.exe $MAIN_FILE
 
# Build for macOS amd64
echo "Building for macOS amd64..."
GOOS=darwin GOARCH=amd64 go build -o $OUTPUT_DIR/v1_fs_scanner_macos $MAIN_FILE
 
# Build for macOS ARM
echo "Building for macOS ARM..."
GOOS=darwin GOARCH=arm64 go build -o $OUTPUT_DIR/v1_fs_scanner_macos_arm $MAIN_FILE
 
echo "Builds completed successfully."
 
