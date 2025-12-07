#!/bin/bash
set -e

echo "Starting installation..."

# 1. Build the application
./build.sh

# 2. Define install paths
INSTALL_BIN="$HOME/.local/bin"
INSTALL_APPS="$HOME/.local/share/applications"
INSTALL_ICON="$HOME/.local/share/icons/hicolor/128x128/apps"

# 3. Create directories
mkdir -p "$INSTALL_BIN"
mkdir -p "$INSTALL_APPS"
mkdir -p "$INSTALL_ICON"

# 4. Copy files
echo "Installing binary to $INSTALL_BIN..."
cp build/messagebox "$INSTALL_BIN/"

echo "Installing icon to $INSTALL_ICON..."
cp message.png "$INSTALL_ICON/messagebox.png"

echo "Installing desktop file to $INSTALL_APPS..."
cp messagebox.desktop "$INSTALL_APPS/"

echo "Installation complete!"
echo "You may need to log out and back in for the desktop entry to appear in menus."
