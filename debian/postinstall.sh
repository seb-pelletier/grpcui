#!/bin/sh
set -e

# Reload systemd and enable/start the service
systemctl daemon-reload
systemctl enable grpcui
systemctl start grpcui
