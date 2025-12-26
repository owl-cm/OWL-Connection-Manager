#!/bin/bash
# Post-removal script for OWL
# This runs when the package is removed

case "$1" in
    remove|purge)
        # Get all user home directories
        for user_home in /home/*; do
            if [ -d "$user_home" ]; then
                user=$(basename "$user_home")
                config_dir="$user_home/.config/OWL"
                
                if [ -d "$config_dir" ]; then
                    echo "Removing OWL user data for $user..."
                    rm -rf "$config_dir"
                fi
            fi
        done
        
        # Also check root's config
        if [ -d "/root/.config/OWL" ]; then
            rm -rf "/root/.config/OWL"
        fi
        ;;
esac

exit 0
