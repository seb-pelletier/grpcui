#!/bin/sh
set -e

# Reload systemd after removal
systemctl daemon-reload

# Remove service user if it exists
if id -u grpcui > /dev/null 2>&1; then
    userdel grpcui
fi
