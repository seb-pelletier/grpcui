#!/bin/sh
set -e

# Stop and disable the service before removal
if systemctl is-active --quiet grpcui; then
    systemctl stop grpcui
fi

if systemctl is-enabled --quiet grpcui; then
    systemctl disable grpcui
fi
