#!/bin/bash
# Auto-update script for FortiGate Dashboard
# Pulls latest changes from GitHub and restarts services

cd /opt/fortigate-dashboard || exit 1

echo "Checking for updates... $(date)"
git fetch origin

LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/master)

if [ "$LOCAL" != "$REMOTE" ]; then
    echo "New version found, updating..."
    git pull origin master
    chmod +x scripts/*.py scripts/*.sh
    
    echo "Restarting services..."
    systemctl restart fortigate-dashboard
    echo "Update complete at $(date)" >> /var/log/fortigate-update.log
else
    echo "Already up to date"
fi
