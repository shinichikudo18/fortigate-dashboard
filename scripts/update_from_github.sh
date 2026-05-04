#!/bin/bash
# Update dashboard from GitHub repository
cd /opt/fortigate-dashboard
git fetch origin
git reset --hard origin/master
chmod +x scripts/*.py
echo "Updated from GitHub at $(date)" > /tmp/dashboard_update.log
