#!/bin/sh
set -e

# Create service user if it doesn't exist
if ! id -u grpcui > /dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin grpcui
fi
